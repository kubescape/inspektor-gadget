// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (i *ebpfInstance) publishNativeResources(gc operators.GadgetContext) {
	if _, exists := gc.GetVar(operators.NativeResourcesKey); exists {
		// Native ownership supports one collection only. Keep this invalidation
		// sticky across additional layers, including ones with duplicate names.
		// Ordinary multi-layer images do not consume this optional manifest.
		gc.SetVar(operators.NativeResourcesKey, (*operators.NativeResources)(nil))
		return
	}
	gc.SetVar(operators.NativeResourcesKey, i.nativeResources())
}

func (i *ebpfInstance) nativeResources() *operators.NativeResources {
	r := &operators.NativeResources{Maps: map[string]operators.NativeMapResource{}, Programs: map[string]operators.NativeProgramResource{}}
	for n, m := range i.collectionSpec.Maps {
		r.Maps[n] = nativeMapResource(m, 0)
	}
	for n, p := range i.collectionSpec.Programs {
		r.Programs[n] = operators.NativeProgramResource{Type: uint32(p.Type), Target: i.programAttachTarget(p), Instructions: uint64(len(p.Instructions)) * 2}
	}
	return r
}

func nativeMapResource(m *ebpf.MapSpec, depth int) operators.NativeMapResource {
	// Bound malformed/cyclic templates without silently omitting resources.
	// The unknown map type is rejected by native resource admission.
	if m == nil || depth >= 8 {
		return operators.NativeMapResource{}
	}
	r := operators.NativeMapResource{Type: uint32(m.Type), KeySize: m.KeySize, ValueSize: m.ValueSize, MaxEntries: m.MaxEntries, Flags: m.Flags}
	if m.InnerMap != nil {
		inner := nativeMapResource(m.InnerMap, depth+1)
		r.InnerMap = &inner
	}
	return r
}

func (i *ebpfInstance) validateNativeResources(gc operators.GadgetContext) error {
	value, exists := gc.GetVar(operators.NativeResourceValidatorKey)
	if !exists {
		return nil
	}
	validate, ok := value.(func(*operators.NativeResources) error)
	if !ok || validate == nil {
		return fmt.Errorf("invalid native resource validator")
	}
	return validate(i.nativeResources())
}

func (i *ebpfInstance) publishNativeAttachment(gc operators.GadgetContext, name string, p *ebpf.ProgramSpec, l link.Link) error {
	// Optional receipts must not regress ordinary tracers on link types/kernels
	// without Info support. Native consumers fail closed on the absent receipt.
	if p.Type != ebpf.LSM && p.Type != ebpf.Tracing {
		return nil
	}
	info, err := l.Info()
	if err != nil || info.Program == 0 {
		return nil
	}
	receipt := &operators.NativeAttachment{Type: uint32(p.Type), Target: i.programAttachTarget(p), Check: nativeAttachmentCheck(name, info.Program, l.Info)}
	if i.nativeAttachments == nil {
		i.nativeAttachments = map[string]*operators.NativeAttachment{}
	}
	i.nativeAttachments[name] = receipt
	gc.SetVar(operators.NativeAttachmentPrefix+name, receipt)
	return nil
}

func (i *ebpfInstance) unpublishNativeAttachments(gc operators.GadgetContext) {
	for name, receipt := range i.nativeAttachments {
		if current, _ := gc.GetVar(operators.NativeAttachmentPrefix + name); current == receipt {
			gc.SetVar(operators.NativeAttachmentPrefix+name, nil)
		}
	}
	i.nativeAttachments = nil
}

func nativeAttachmentCheck(name string, expected ebpf.ProgramID, read func() (*link.Info, error)) func() error {
	return func() error {
		current, err := read()
		if err != nil {
			return err
		}
		if current == nil || current.Program != expected {
			return fmt.Errorf("attachment %s program changed", name)
		}
		return nil
	}
}
