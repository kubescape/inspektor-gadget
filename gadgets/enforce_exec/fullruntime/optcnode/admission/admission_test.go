// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

const productObject = "../optcengine/optc_product_bpfel.o"

func load(t *testing.T) ([]byte, *btf.Spec) {
	t.Helper()
	obj, err := os.ReadFile(productObject)
	if err != nil {
		t.Fatalf("product object: %v (build it with optcengine/build.sh)", err)
	}
	kernel, err := btf.LoadSpec("/sys/kernel/btf/vmlinux")
	if err != nil {
		t.Fatalf("kernel BTF: %v", err)
	}
	return obj, kernel
}

// minimal rebuilds a kernel BTF holding only the object's dependencies, with
// mutate applied to the named struct.
func minimal(t *testing.T, obj []byte, kernel *btf.Spec, mutate string) *btf.Spec {
	t.Helper()
	types, hooks, err := Dependencies(obj)
	if err != nil {
		t.Fatal(err)
	}
	b, err := btf.NewBuilder(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range append(types, hooks...) {
		ts, err := kernel.AnyTypesByName(name)
		if err != nil {
			continue
		}
		for _, typ := range ts {
			if s, ok := typ.(*btf.Struct); ok && s.Name == mutate && len(s.Members) > 1 {
				c := *s // shallow: the rest of the graph stays shared
				c.Members = slices.Clone(s.Members)
				c.Members[1].Offset += 64 // a member moved: a vendor backport
				typ = &c
			}
			if _, err := b.Add(typ); err != nil {
				t.Fatal(err)
			}
		}
	}
	raw, err := b.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func objSHA(obj []byte) string {
	s := sha256.Sum256(obj)
	return hex.EncodeToString(s[:])
}

func TestDependenciesAreKernelShapedOnly(t *testing.T) {
	obj, _ := load(t)
	types, hooks, err := Dependencies(obj)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"task_struct", "fs_struct", "mount", "dentry", "linux_binprm"} {
		if !contains(types, want) {
			t.Errorf("dependency %s missing from %v", want, types)
		}
	}
	for _, want := range []string{"bpf_lsm_bprm_check_security", "bpf_lsm_task_alloc", "bpf_lsm_bprm_creds_for_exec", "bpf_lsm_bprm_committed_creds", "btf_trace_sched_process_exec", "btf_trace_sched_process_fork"} {
		if !contains(hooks, want) {
			t.Errorf("hook %s missing from %v", want, hooks)
		}
	}
	t.Logf("%d kernel types, hooks %v", len(types), hooks)
}

func TestFingerprintIsStableAndShapeSensitive(t *testing.T) {
	obj, kernel := load(t)
	full, err := Fingerprint(obj, kernel)
	if err != nil {
		t.Fatal(err)
	}
	same, err := Fingerprint(obj, minimal(t, obj, kernel, ""))
	if err != nil {
		t.Fatal(err)
	}
	if full != same {
		t.Fatalf("fingerprint depends on unrelated kernel types: %s vs %s", full, same)
	}
	changed, err := Fingerprint(obj, minimal(t, obj, kernel, "fs_struct"))
	if err != nil {
		t.Fatal(err)
	}
	if changed == full {
		t.Fatal("a moved fs_struct member did not change the fingerprint")
	}
}

func family(obj []byte, fp string) Family {
	return Family{
		Name: "test-family", ObjectSHA256: objSHA(obj), OSID: "amzn", OSVersionID: "2023",
		ReleasePattern: `^6\.12\.\d+-\d+\.\d+\.amzn2023\.x86_64$`,
		Qualification: &Qualification{
			Builds: []string{"6.12.113-138.209.amzn2023.x86_64", "6.12.115-140.210.amzn2023.x86_64"}, NewestRelease: "6.12.115-140.210.amzn2023.x86_64",
			StrictPass: 60, AuditPass: 60, Mutants: 40, MutantsDetected: 40, Fingerprints: []string{fp},
		},
	}
}

func node(kernel *btf.Spec) Node {
	return Node{Release: "6.12.120-145.215.amzn2023.x86_64", OSID: "amzn", OSVersionID: "2023", BTFSHA256: "b7f", Kernel: kernel}
}

func TestAdmit(t *testing.T) {
	obj, kernel := load(t)
	fp, err := Fingerprint(obj, kernel)
	if err != nil {
		t.Fatal(err)
	}
	changed := minimal(t, obj, kernel, "fs_struct")
	refused := func(t *testing.T, d Decision, err error, why string) {
		t.Helper()
		if !errors.Is(err, ErrRefused) || d.Level != "" || !strings.Contains(err.Error(), why) {
			t.Fatalf("decision %+v, err %v: want a refusal containing %q", d, err, why)
		}
	}
	t.Run("ExactPinAdmits", func(t *testing.T) {
		n := node(kernel)
		d, err := Admit(n, obj, Policy{Pins: []Pin{{Release: n.Release, BTFSHA256: n.BTFSHA256, ObjectSHA256: objSHA(obj)}}})
		if err != nil || d.Level != "exact" {
			t.Fatalf("%+v %v", d, err)
		}
	})
	t.Run("ExactPinOtherObjectRefused", func(t *testing.T) {
		n := node(kernel)
		d, err := Admit(n, obj, Policy{Pins: []Pin{{Release: n.Release, BTFSHA256: n.BTFSHA256, ObjectSHA256: "00"}}})
		refused(t, d, err, "family admission is off")
	})
	t.Run("FamilyOptInOffRefused", func(t *testing.T) {
		d, err := Admit(node(kernel), obj, Policy{Families: []Family{family(obj, fp)}})
		refused(t, d, err, "family admission is off")
	})
	t.Run("FamilyAdmits", func(t *testing.T) {
		d, err := Admit(node(kernel), obj, Policy{AllowFamily: true, Families: []Family{family(obj, fp)}})
		if err != nil || d.Level != "family" || d.Family != "test-family" {
			t.Fatalf("%+v %v", d, err)
		}
	})
	t.Run("FamilyMemberWithChangedShapeRefused", func(t *testing.T) {
		d, err := Admit(node(changed), obj, Policy{AllowFamily: true, Families: []Family{family(obj, fp)}})
		refused(t, d, err, "family shape changed")
	})
	t.Run("ReleasePatternMismatchRefused", func(t *testing.T) {
		n := node(kernel)
		n.Release = "6.18.56-125.164.amzn2023.x86_64"
		d, err := Admit(n, obj, Policy{AllowFamily: true, Families: []Family{family(obj, fp)}})
		refused(t, d, err, "does not match")
	})
	t.Run("UnanchoredPatternRefused", func(t *testing.T) {
		f := family(obj, fp)
		f.ReleasePattern = `6\.12\..*`
		d, err := Admit(node(kernel), obj, Policy{AllowFamily: true, Families: []Family{f}})
		refused(t, d, err, "not anchored")
	})
	t.Run("MissingQualificationRecordRefused", func(t *testing.T) {
		f := family(obj, fp)
		f.Qualification = nil
		d, err := Admit(node(kernel), obj, Policy{AllowFamily: true, Families: []Family{f}})
		refused(t, d, err, "no full qualification record")
	})
	t.Run("IncompleteQualificationRefused", func(t *testing.T) {
		for name, edit := range map[string]func(*Qualification){
			"one build":       func(q *Qualification) { q.Builds = q.Builds[:1] },
			"newest missing":  func(q *Qualification) { q.NewestRelease = "6.12.200-1.1.amzn2023.x86_64" },
			"a skip":          func(q *Qualification) { q.Skip = 1 },
			"a not-run":       func(q *Qualification) { q.NotRun = 1 },
			"mutant survived": func(q *Qualification) { q.MutantsDetected-- },
		} {
			f := family(obj, fp)
			edit(f.Qualification)
			d, err := Admit(node(kernel), obj, Policy{AllowFamily: true, Families: []Family{f}})
			if !errors.Is(err, ErrRefused) || d.Level != "" {
				t.Errorf("%s: admitted %+v", name, d)
			}
		}
	})
	t.Run("OSReleaseMismatchRefused", func(t *testing.T) {
		n := node(kernel)
		n.OSID = "rhel"
		d, err := Admit(n, obj, Policy{AllowFamily: true, Families: []Family{family(obj, fp)}})
		refused(t, d, err, "os-release")
	})
	t.Run("OtherObjectRefused", func(t *testing.T) {
		f := family(obj, fp)
		f.ObjectSHA256 = "00"
		d, err := Admit(node(kernel), obj, Policy{AllowFamily: true, Families: []Family{f}})
		refused(t, d, err, "object sha256 differs")
	})
	t.Run("NoFamilyConfiguredRefused", func(t *testing.T) {
		d, err := Admit(node(kernel), obj, Policy{AllowFamily: true})
		refused(t, d, err, "no family configured")
	})
}
