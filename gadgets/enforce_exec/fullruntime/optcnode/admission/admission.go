// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package admission decides whether the option C engine object may run on a
// node (design 005 §8). Exact pinning of a (kernel, object) pair is the
// default. Family admission is opt-in, and admits a node only if all four
// parts of a qualified family's entry match:
//
//  1. the engine object's sha256;
//  2. ID and VERSION_ID from the host's os-release;
//  3. an anchored kernel-release pattern;
//  4. a BTF shape fingerprint: a sha256 over the kernel BTF definitions of
//     exactly what the object depends on (every kernel struct, union, enum
//     and typedef it references, and the prototypes of the hooks it attaches
//     to), equal to one recorded when the family was qualified;
//
// and the family carries a full offline qualification record. Every other
// case is a refusal with a reason; nothing here admits by default.
//
// Limits of the fingerprint (review M5; they matter in family mode only,
// which is off by default):
//   - it hashes type SHAPES (sizes, member offsets and the names of member
//     types), not kernel behaviour: a backport that changes what a hook means
//     without changing a layout is invisible to it;
//   - member types are named shallowly (a named struct is checked by its own
//     entry, an anonymous one is expanded);
//   - a dependency the kernel BTF does not define is skipped silently (a
//     type local to the object; a kernel type that disappeared changes the
//     other entries that reference it, and its hook prototypes);
//   - Qualification.Complete checks a record's own claims: nothing here
//     verifies it against the evidence. A production record would carry the
//     evidence hashes (logs, objects) and a signature over them.
//
// Exact pins (the default) do not depend on any of this.
package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// ErrRefused wraps every refusal.
var ErrRefused = errors.New("option C engine not admitted on this node")

// Node is what admission knows about the running node.
type Node struct {
	Release           string // uname -r
	OSID, OSVersionID string // os-release
	BTFSHA256         string // sha256 of /sys/kernel/btf/vmlinux
	Kernel            *btf.Spec
}

// Pin is one exactly qualified (kernel, object) pair (the default).
type Pin struct {
	Release, BTFSHA256, ObjectSHA256 string
}

// Qualification is the offline record a family needs: the builds the full
// oracle ran on (at least two, including the newest of the family), with
// Strict and Audit results and the mutant detections, zero FAIL, zero SKIP.
type Qualification struct {
	Builds                   []string // kernel releases qualified
	NewestRelease            string   // the family's newest build at qualification time
	StrictPass, AuditPass    int
	Fail, Skip, NotRun       int
	MutantsDetected, Mutants int
	Evidence                 string // where the logs are
	Fingerprints             []string
}

// Family is one vendor kernel stream (005 §8: one AL2023 series, one RHEL
// minor release, one Ubuntu ABI series, one Debian stable kernel).
type Family struct {
	Name              string
	ObjectSHA256      string
	OSID, OSVersionID string
	ReleasePattern    string // anchored: ^...$
	Qualification     *Qualification
}

// Policy is the node's admission configuration.
type Policy struct {
	Pins     []Pin
	Families []Family
	// AllowFamily opts in to family admission. Off by default.
	AllowFamily bool
}

// Decision is an admission.
type Decision struct {
	Level  string // "exact" or "family"
	Family string
}

// Complete reports whether q is a full offline qualification record.
func (q *Qualification) Complete() error {
	switch {
	case q == nil:
		return errors.New("no qualification record")
	case len(q.Builds) < 2:
		return fmt.Errorf("qualified on %d builds, need at least 2", len(q.Builds))
	case q.NewestRelease == "" || !contains(q.Builds, q.NewestRelease):
		return errors.New("the family's newest build is not among the qualified builds")
	case q.Fail != 0 || q.Skip != 0 || q.NotRun != 0:
		return fmt.Errorf("qualification has %d FAIL, %d SKIP, %d NOT-RUN", q.Fail, q.Skip, q.NotRun)
	case q.StrictPass == 0 || q.AuditPass == 0:
		return errors.New("qualification lacks Strict or Audit results")
	case q.Mutants == 0 || q.MutantsDetected != q.Mutants:
		return fmt.Errorf("%d of %d mutants detected", q.MutantsDetected, q.Mutants)
	case len(q.Fingerprints) == 0:
		return errors.New("no shape fingerprint recorded")
	}
	return nil
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// Admit decides for one node and one object.
func Admit(node Node, object []byte, p Policy) (Decision, error) {
	sum := sha256.Sum256(object)
	objSHA := hex.EncodeToString(sum[:])
	for _, pin := range p.Pins {
		if pin.Release == node.Release && pin.BTFSHA256 == node.BTFSHA256 && pin.ObjectSHA256 == objSHA {
			return Decision{Level: "exact"}, nil
		}
	}
	if !p.AllowFamily {
		return Decision{}, fmt.Errorf("%w: kernel %s (BTF %.12s) is not an exactly pinned build for object %.12s, and family admission is off", ErrRefused, node.Release, node.BTFSHA256, objSHA)
	}
	var reasons []string
	for _, f := range p.Families {
		reason := func() string {
			if f.ObjectSHA256 != objSHA {
				return "object sha256 differs"
			}
			if f.OSID != node.OSID || f.OSVersionID != node.OSVersionID {
				return fmt.Sprintf("os-release %s %s, family %s %s", node.OSID, node.OSVersionID, f.OSID, f.OSVersionID)
			}
			if !strings.HasPrefix(f.ReleasePattern, "^") || !strings.HasSuffix(f.ReleasePattern, "$") {
				return "release pattern is not anchored"
			}
			re, err := regexp.Compile(f.ReleasePattern)
			if err != nil {
				return fmt.Sprintf("release pattern: %v", err)
			}
			if !re.MatchString(node.Release) {
				return fmt.Sprintf("release %s does not match %s", node.Release, f.ReleasePattern)
			}
			if err := f.Qualification.Complete(); err != nil {
				return fmt.Sprintf("no full qualification record: %v", err)
			}
			fp, err := Fingerprint(object, node.Kernel)
			if err != nil {
				return fmt.Sprintf("shape fingerprint: %v", err)
			}
			if !contains(f.Qualification.Fingerprints, fp) {
				return fmt.Sprintf("family shape changed: fingerprint %.16s is not one of the %d qualified", fp, len(f.Qualification.Fingerprints))
			}
			return ""
		}()
		if reason == "" {
			return Decision{Level: "family", Family: f.Name}, nil
		}
		reasons = append(reasons, f.Name+": "+reason)
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no family configured")
	}
	return Decision{}, fmt.Errorf("%w: %s", ErrRefused, strings.Join(reasons, "; "))
}

// Dependencies lists what object depends on in the kernel: the named kernel
// types its BTF references (CO-RE flavours "x___y" reduced to x) and the
// BTF names of the hooks its programs attach to.
func Dependencies(object []byte) (types []string, hooks []string, err error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	if spec.Types != nil {
		for t, err := range spec.Types.All() {
			if err != nil {
				return nil, nil, err
			}
			switch t.(type) {
			case *btf.Struct, *btf.Union, *btf.Enum, *btf.Typedef:
			default:
				continue
			}
			name := t.TypeName()
			if name == "" {
				continue
			}
			if i := strings.Index(name, "___"); i > 0 {
				name = name[:i]
			}
			seen[name] = true
		}
	}
	for name := range seen {
		types = append(types, name)
	}
	sort.Strings(types)
	hs := map[string]bool{}
	for _, p := range spec.Programs {
		switch p.Type {
		case ebpf.LSM:
			hs["bpf_lsm_"+p.AttachTo] = true
		case ebpf.Tracing:
			hs["btf_trace_"+p.AttachTo] = true
		}
	}
	for h := range hs {
		hooks = append(hooks, h)
	}
	sort.Strings(hooks)
	return types, hooks, nil
}

// Fingerprint is the shape fingerprint of object on kernel: a sha256 over
// the canonical kernel definitions of its dependencies. A dependency the
// object's own BTF defines (not a kernel type) is skipped; a hook missing
// from the kernel is part of the fingerprint ("missing").
func Fingerprint(object []byte, kernel *btf.Spec) (string, error) {
	if kernel == nil {
		return "", errors.New("no kernel BTF")
	}
	types, hooks, err := Dependencies(object)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, name := range types {
		ts, err := kernel.AnyTypesByName(name)
		if err != nil {
			continue // a local type of the object
		}
		var defs []string
		for _, t := range ts {
			defs = append(defs, canonical(t))
		}
		sort.Strings(defs)
		fmt.Fprintf(h, "type %s\n%s\n", name, strings.Join(defs, "\n"))
	}
	for _, name := range hooks {
		t, err := kernel.AnyTypeByName(name)
		if err != nil {
			fmt.Fprintf(h, "hook %s missing\n", name)
			continue
		}
		fmt.Fprintf(h, "hook %s %s\n", name, canonical(t))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// canonical renders one type's shape: kind, size, and each member's name,
// bit offset, bit size and the shallow name of its type. Function
// prototypes render parameters and return type.
func canonical(t btf.Type) string {
	var b strings.Builder
	switch v := t.(type) {
	case *btf.Struct:
		fmt.Fprintf(&b, "struct %s %d {", v.Name, v.Size)
		members(&b, v.Members)
		b.WriteString("}")
	case *btf.Union:
		fmt.Fprintf(&b, "union %s %d {", v.Name, v.Size)
		members(&b, v.Members)
		b.WriteString("}")
	case *btf.Enum:
		fmt.Fprintf(&b, "enum %s %d {", v.Name, v.Size)
		for _, e := range v.Values {
			fmt.Fprintf(&b, "%s=%d;", e.Name, e.Value)
		}
		b.WriteString("}")
	case *btf.Typedef:
		fmt.Fprintf(&b, "typedef %s %s", v.Name, shallow(v.Type))
	case *btf.Func:
		fmt.Fprintf(&b, "func %s %s", v.Name, shallow(v.Type))
	default:
		b.WriteString(shallow(t))
	}
	return b.String()
}

func members(b *strings.Builder, ms []btf.Member) {
	for _, m := range ms {
		fmt.Fprintf(b, "%s@%d:%d %s;", m.Name, m.Offset, m.BitfieldSize, shallow(m.Type))
	}
}

// shallow names a type without following named types (anonymous composites
// are expanded, since they have no name of their own to be checked by).
func shallow(t btf.Type) string {
	switch v := t.(type) {
	case nil:
		return "void"
	case *btf.Pointer:
		return "*" + shallow(v.Target)
	case *btf.Array:
		return fmt.Sprintf("[%d]%s", v.Nelems, shallow(v.Type))
	case *btf.Const:
		return "const " + shallow(v.Type)
	case *btf.Volatile:
		return "volatile " + shallow(v.Type)
	case *btf.Restrict:
		return "restrict " + shallow(v.Type)
	case *btf.TypeTag:
		return shallow(v.Type)
	case *btf.FuncProto:
		var ps []string
		for _, p := range v.Params {
			ps = append(ps, shallow(p.Type))
		}
		return fmt.Sprintf("(%s)%s", strings.Join(ps, ","), shallow(v.Return))
	case *btf.Struct:
		if v.Name == "" {
			return canonical(v)
		}
		return "struct " + v.Name
	case *btf.Union:
		if v.Name == "" {
			return canonical(v)
		}
		return "union " + v.Name
	case *btf.Int:
		return fmt.Sprintf("int %s %d", v.Name, v.Size)
	default:
		return fmt.Sprintf("%T %s", t, t.TypeName())
	}
}
