// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package ebpfoperator

import (
	"github.com/cilium/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/spf13/viper"
	"testing"
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
