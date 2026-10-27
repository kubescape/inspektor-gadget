// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/spf13/viper"

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
