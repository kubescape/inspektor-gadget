// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package optcnode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/admission"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/optcengine"
)

func TestStartNodeRefusals(t *testing.T) {
	kernel, err := btf.LoadSpec("/sys/kernel/btf/vmlinux")
	if err != nil {
		t.Fatalf("kernel BTF: %v", err)
	}
	sum := sha256.Sum256(optcengine.ProductObject())
	obj := hex.EncodeToString(sum[:])
	node := admission.Node{Release: "6.12.40-63.114.amzn2023.x86_64", OSID: "amzn", OSVersionID: "2023", BTFSHA256: "b7f", Kernel: kernel}
	pinned := admission.Policy{Pins: []admission.Pin{{Release: node.Release, BTFSHA256: node.BTFSHA256, ObjectSHA256: obj}}}
	loadErr := errors.New("load: kallsyms lookup failed")
	probe := func(lsm string, n admission.Node, loaded *bool) *Probe {
		return &Probe{
			Node:     func() (admission.Node, error) { return n, nil },
			LSMs:     func() (string, error) { return lsm, nil },
			Controls: func() error { return nil },
			Load: func(optcengine.Options) (*optcengine.Engine, error) {
				*loaded = true
				return nil, loadErr
			},
		}
	}
	other := node
	other.Release = "6.12.41-64.115.amzn2023.x86_64"
	other.BTFSHA256 = "c80"
	for _, c := range []struct {
		name   string
		lsm    string
		node   admission.Node
		policy admission.Policy
		load   bool
		want   string
	}{
		{"NoBPFLSM", "lockdown,capability,yama,apparmor", node, pinned, false, "BPF LSM is not active"},
		{"UnknownKernel", "lockdown,capability,bpf", other, pinned, false, "not an exactly pinned build"},
		{"FamilyOptInOff", "lockdown,capability,bpf", other, admission.Policy{Pins: pinned.Pins, Families: []admission.Family{{Name: "al2023-6.12"}}}, false, "family admission is off"},
		{"LoadOrKsymFailure", "lockdown,capability,bpf", node, pinned, true, "kallsyms lookup failed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var loaded bool
			n, err := StartNode(context.Background(), Config{Admission: c.policy, Probe: probe(c.lsm, c.node, &loaded)})
			if n != nil || !errors.Is(err, ErrNotReady) || !errors.Is(err, fullruntime.ErrSharedNodeNotReady) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("StartNode: %v, %v: want ErrNotReady containing %q", n, err, c.want)
			}
			if loaded != c.load {
				t.Fatalf("engine load attempted=%v, want %v", loaded, c.load)
			}
		})
	}
}

func TestKernelControlsReadable(t *testing.T) {
	// Not a refusal test: the host the unit tests run on has ftrace on and,
	// typically, no livepatch; this only shows the re-read works.
	if err := kernelControls(); err != nil {
		t.Logf("kernel controls on this host: %v", err)
	}
}

func TestPublishRefusesArgv(t *testing.T) {
	yes := true
	for name, c := range map[string]struct {
		argv *fullpolicy.Argv
		want bool
	}{
		"contains": {&fullpolicy.Argv{Contains: []string{"--evil"}}, true},
		"prefix":   {&fullpolicy.Argv{Prefix: []string{"-x"}}, true},
		"stdin":    {&fullpolicy.Argv{StdinIsPipe: &yes}, false},
		"none":     {nil, false},
	} {
		p := &fullpolicy.Policy{ID: "p", Rules: []fullpolicy.Rule{{Name: "r", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{"/x"}, Argv: c.argv}}}}
		err := refuseArgv(p)
		if got := errors.Is(err, optcengine.ErrUnsupportedPolicy); got != c.want {
			t.Errorf("%s: %v, want refused=%v", name, err, c.want)
		}
	}
}

func TestQualifiedPinsNameTheEmbeddedObject(t *testing.T) {
	sum := sha256.Sum256(optcengine.ProductObject())
	if got := hex.EncodeToString(sum[:]); got != QualifiedObjectSHA256 {
		t.Fatalf("embedded product object %s is not the qualified %s: re-qualify and rotate the pins", got, QualifiedObjectSHA256)
	}
	if len(QualifiedPins) == 0 || DefaultAdmission().AllowFamily {
		t.Fatalf("default admission %+v: want exact pins only", DefaultAdmission())
	}
}

func TestUnsupportedContractMethodsNeverReportHealth(t *testing.T) {
	n := &Node{}
	for name, err := range map[string]error{
		"KernelEventCounters": func() error { _, err := n.KernelEventCounters(); return err }(),
		"CapsuleHealth":       func() error { _, err := n.CapsuleHealth(); return err }(),
		"FactHealth":          func() error { _, err := n.FactHealth(); return err }(),
		"BirthParkHealth":     func() error { _, err := n.BirthParkHealth(); return err }(),
		"FailClosedHealth":    func() error { _, err := n.FailClosedHealth(); return err }(),
		"AdoptionReport":      func() error { _, _, err := n.AdoptionReport(); return err }(),
	} {
		if !errors.Is(err, ErrNotSupported) {
			t.Errorf("%s: %v, want ErrNotSupported", name, err)
		}
	}
}
