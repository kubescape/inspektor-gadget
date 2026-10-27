// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func TestNativeManifestDoesNotRetainMutableSpecs(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	cfg := viper.New()
	cfg.Set("programs.hook.attach_to", disabledProgram)
	i := &ebpfInstance{config: cfg, collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"state": {Type: ebpf.Hash, KeySize: 8, ValueSize: 16, MaxEntries: 4}}, Programs: map[string]*ebpf.ProgramSpec{"hook": {Name: "hook", Type: ebpf.Tracing, AttachTo: "task_newtask", Instructions: asm.Instructions{asm.Return()}}}}}
	i.publishNativeResources(gc)
	v, _ := gc.GetVar(operators.NativeResourcesKey)
	r := v.(*operators.NativeResources)
	i.collectionSpec.Maps["state"].MaxEntries = 999
	i.collectionSpec.Programs["hook"].Instructions = nil
	i.collectionSpec = nil
	if r.Maps["state"].MaxEntries != 4 || r.Programs["hook"].Instructions != 2 || r.Programs["hook"].Target != disabledProgram {
		t.Fatal("manifest not independent or override ignored")
	}
}

func TestNativeAttachmentGuard(t *testing.T) {
	var err error
	info := &link.Info{Program: 7}
	check := nativeAttachmentCheck("hook", 7, func() (*link.Info, error) { return info, err })
	if got := check(); got != nil {
		t.Fatal(got)
	}
	info.Program = 8
	if check() == nil {
		t.Fatal("replacement not detected")
	}
	info = nil
	if check() == nil {
		t.Fatal("missing info accepted")
	}
	err = errors.New("closed")
	if !errors.Is(check(), err) {
		t.Fatal("closed link not detected")
	}
}

func TestNativeReceiptUnpublishDoesNotClearOtherOwner(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	mine, other := new(operators.NativeAttachment), new(operators.NativeAttachment)
	i := &ebpfInstance{nativeAttachments: map[string]*operators.NativeAttachment{"mine": mine, "other": mine}}
	gc.SetVar(operators.NativeAttachmentPrefix+"mine", mine)
	gc.SetVar(operators.NativeAttachmentPrefix+"other", other)
	i.unpublishNativeAttachments(gc)
	if v, _ := gc.GetVar(operators.NativeAttachmentPrefix + "mine"); v != nil {
		t.Fatal("own receipt remains")
	}
	if v, _ := gc.GetVar(operators.NativeAttachmentPrefix + "other"); v != other {
		t.Fatal("other receipt cleared")
	}
}

type nativeTargetTestLink struct {
	link.Link
}

func (nativeTargetTestLink) Info() (*link.Info, error) {
	return &link.Info{Program: 7}, nil
}

func TestNativeTargetsCannotBeOverriddenForLoadedBTFPrograms(t *testing.T) {
	for _, typ := range []ebpf.ProgramType{ebpf.LSM, ebpf.Tracing} {
		t.Run(typ.String(), func(t *testing.T) {
			gc := newResolverGadgetCtx(t, nil)
			cfg := viper.New()
			cfg.Set("programs.hook.attach_to", "required_hook")
			spec := &ebpf.ProgramSpec{Name: "hook", Type: typ, AttachTo: "actual_hook"}
			i := &ebpfInstance{config: cfg, collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"hook": spec}}}
			i.publishNativeResources(gc)
			value, _ := gc.GetVar(operators.NativeResourcesKey)
			if got := value.(*operators.NativeResources).Programs["hook"].Target; got != spec.AttachTo {
				t.Fatalf("manifest reports overridden target %q", got)
			}
			if err := i.publishNativeAttachment(gc, "hook", spec, nativeTargetTestLink{}); err != nil {
				t.Fatal(err)
			}
			value, _ = gc.GetVar(operators.NativeAttachmentPrefix + "hook")
			receipt := value.(*operators.NativeAttachment)
			if receipt.Target != spec.AttachTo {
				t.Fatalf("receipt reports overridden target %q", receipt.Target)
			}
			if err := receipt.Check(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeManifestRejectsMultipleCollections(t *testing.T) {
	for _, duplicateNames := range []bool{false, true} {
		t.Run(fmt.Sprint("duplicate-names=", duplicateNames), func(t *testing.T) {
			gc := newResolverGadgetCtx(t, nil)
			for layer := range 3 {
				name := fmt.Sprintf("map%d", layer)
				if duplicateNames {
					name = "map"
				}
				i := &ebpfInstance{collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{name: {Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1}}}}
				i.publishNativeResources(gc)
				value, exists := gc.GetVar(operators.NativeResourcesKey)
				if !exists {
					t.Fatal("missing native manifest marker")
				}
				manifest, _ := value.(*operators.NativeResources)
				if (manifest != nil) != (layer == 0) {
					t.Fatalf("layer %d: multilayer invalidation lost", layer)
				}
				if err := i.validateNativeResources(gc); err != nil {
					t.Fatalf("ordinary image without native validator rejected: %v", err)
				}
			}
		})
	}
}

func TestNativeFinalResourceValidationPrecedesAllocation(t *testing.T) {
	const maxEntries = uint32(1 << 25) // 256 MiB with the 8-byte map entry.
	for _, source := range []string{"variable", "parameter", "context"} {
		t.Run(source, func(t *testing.T) {
			gc := newResolverGadgetCtx(t, nil)
			size := &ebpf.VariableSpec{Name: "state_max_entries"}
			if err := size.Set(maxEntries); err != nil {
				t.Fatal(err)
			}
			i := &ebpfInstance{
				logger:      gc.Logger(),
				params:      map[string]*param{ParamTraceKernel: {Param: &api.Param{Key: ParamTraceKernel, TypeHint: api.TypeBool, DefaultValue: "false"}}},
				paramValues: api.ParamValues{},
				collectionSpec: &ebpf.CollectionSpec{
					Maps:      map[string]*ebpf.MapSpec{"state": {Name: "state", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1}},
					Variables: map[string]*ebpf.VariableSpec{size.Name: size},
				},
			}
			if source != "variable" {
				if err := size.Set(uint32(1)); err != nil {
					t.Fatal(err)
				}
			}
			switch source {
			case "parameter":
				i.params[size.Name] = &param{Param: &api.Param{Key: size.Name, TypeHint: api.TypeUint32}, fromEbpf: true}
				i.paramValues[size.Name] = fmt.Sprint(maxEntries)
			case "context":
				i.vars = map[string]*ebpfVar{size.Name: {name: size.Name, refType: reflect.TypeOf(maxEntries)}}
				gc.SetVar(size.Name, maxEntries)
			}
			i.publishNativeResources(gc)
			value, _ := gc.GetVar(operators.NativeResourcesKey)
			if value.(*operators.NativeResources).Maps["state"].MaxEntries != 1 {
				t.Fatal("preflight must see original static size")
			}
			budgetExceeded := errors.New("native map budget exceeded")
			called := false
			gc.SetVar(operators.NativeResourceValidatorKey, func(r *operators.NativeResources) error {
				called = true
				m := r.Maps["state"]
				if m.MaxEntries != maxEntries || uint64(m.MaxEntries)*uint64(m.KeySize+m.ValueSize) <= 128<<20 {
					t.Fatalf("final map size missing: %+v", m)
				}
				return budgetExceeded
			})
			if err := i.Start(gc); !errors.Is(err, budgetExceeded) || !called {
				t.Fatalf("final preallocation validation not reached: called=%v err=%v", called, err)
			}
			if i.collection != nil {
				t.Fatal("collection allocated before rejection")
			}
		})
	}
}
