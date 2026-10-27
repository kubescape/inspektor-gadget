// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package ebpfoperator

import (
	"github.com/cilium/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (i *ebpfInstance) programAttachTarget(spec *ebpf.ProgramSpec) string {
	if i.config != nil {
		if target := i.config.GetString("programs." + spec.Name + ".attach_to"); target != "" {
			return target
		}
	}
	return spec.AttachTo
}

// Only enabled syscall commands are exposed. The owning collection retains every FD;
// callers borrow handles and must join command invocations before teardown.
func (i *ebpfInstance) publishCommandPrograms(gc operators.GadgetContext) {
	for name, spec := range i.collectionSpec.Programs {
		if spec.Type == ebpf.Syscall && i.programAttachTarget(spec) != disabledProgram {
			gc.SetVar(operators.ProgramPrefix+name, i.collection.Programs[name])
		}
	}
}
func (i *ebpfInstance) unpublishCommandPrograms(gc operators.GadgetContext) {
	for name, program := range i.collection.Programs {
		key := operators.ProgramPrefix + name
		if current, ok := gc.GetVar(key); ok && current == program {
			gc.SetVar(key, nil)
		}
	}
}
