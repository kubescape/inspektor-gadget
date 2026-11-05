// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func TestSyscallCommandsAreBorrowedNotAutomaticallyAttached(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	command, observer := new(ebpf.Program), new(ebpf.Program) // never used as real FDs
	i := &ebpfInstance{config: viper.New(), logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"control": {Name: "control", Type: ebpf.Syscall, SectionName: "syscall"}, "observer": {Name: "observer", Type: ebpf.Tracing},
	}}, collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{"control": command, "observer": observer}}}
	i.publishCommandPrograms(gc)
	if value, ok := gc.GetVar(operators.ProgramPrefix + "control"); !ok || value != command {
		t.Fatal("native command not connected")
	}
	if _, ok := gc.GetVar(operators.ProgramPrefix + "observer"); ok {
		t.Fatal("unrequested observer FD exposed")
	}
	if link, err := i.attachProgram(gc, i.collectionSpec.Programs["control"], nil); err != nil || link != nil {
		t.Fatal("syscall command attempted automatic attachment", link, err)
	}
	i.collectionSpec = nil // normal Start releases the large BTF/spec before Close
	i.unpublishCommandPrograms(gc)
	if value, _ := gc.GetVar(operators.ProgramPrefix + "control"); value != nil {
		t.Fatal("command remains visible during close")
	}
}

func TestCommandUnpublishDoesNotClearAnotherOwnersValue(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	mine, other := new(ebpf.Program), new(ebpf.Program)
	i := &ebpfInstance{collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{"control": mine}}}
	gc.SetVar(operators.ProgramPrefix+"control", other)
	i.unpublishCommandPrograms(gc)
	if value, _ := gc.GetVar(operators.ProgramPrefix + "control"); value != other {
		t.Fatal("unrelated context value cleared")
	}
}

func TestDisabledCommandCannotBeInvokedThroughContext(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(map[bool]string{false: "spec", true: "override"}[override], func(t *testing.T) {
			gc := newResolverGadgetCtx(t, nil)
			spec := &ebpf.ProgramSpec{Name: "control", Type: ebpf.Syscall, SectionName: "syscall"}
			config := viper.New()
			if override {
				config.Set("programs.control.attach_to", disabledProgram)
			} else {
				spec.AttachTo = disabledProgram
			}
			i := &ebpfInstance{config: config, logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"control": spec}}, collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{"control": new(ebpf.Program)}}}
			i.publishCommandPrograms(gc)
			if _, ok := gc.GetVar(operators.ProgramPrefix + "control"); ok {
				t.Fatal("disabled command exposed")
			}
			if link, err := i.attachProgram(gc, spec, nil); err != nil || link != nil {
				t.Fatal(link, err)
			}
		})
	}
}

func TestProgramAttachTarget(t *testing.T) {
	for _, typ := range []ebpf.ProgramType{ebpf.LSM, ebpf.Tracing, ebpf.Kprobe, ebpf.TracePoint, ebpf.RawTracepoint, ebpf.Syscall} {
		t.Run(typ.String(), func(t *testing.T) {
			spec := &ebpf.ProgramSpec{Name: "hook", Type: typ, AttachTo: "actual"}
			i := &ebpfInstance{}
			if got := i.programAttachTarget(spec); got != "actual" {
				t.Fatalf("without config: got %q", got)
			}
			i.config = viper.New()
			for _, override := range []string{"", "override", disabledProgram} {
				i.config.Set("programs.hook.attach_to", override)
				want := override
				if override == "" || (override != disabledProgram && (typ == ebpf.LSM || typ == ebpf.Tracing)) {
					want = "actual"
				}
				if got := i.programAttachTarget(spec); got != want {
					t.Errorf("override %q: got %q, want %q", override, got, want)
				}
			}
		})
	}
}
