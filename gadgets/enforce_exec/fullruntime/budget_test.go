// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func testBudget(t *testing.T, n uint64) *Budget {
	t.Helper()
	b, err := NewBudget(BudgetLimits{n, n * OwnerMapPayloadLimit, n * OwnerInstructionLimit, n * OwnerHistoryLimit})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestBudgetScopeCapacityAndSharedHandles(t *testing.T) {
	b := testBudget(t, 1)
	r, err := b.reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.reserve(1); err == nil {
		t.Fatal("duplicate scope accepted")
	}
	if _, err = b.reserve(2); err == nil {
		t.Fatal("capacity exceeded")
	}
	copy := *r
	r.release()
	next, err := b.reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	copy.release()
	if b.Usage().Owners != 1 {
		t.Fatal("stale copy released later owner")
	}
	next.release()
	if b.Usage() != (BudgetLimits{}) {
		t.Fatal("budget leaked")
	}
}
func TestBudgetConcurrentCopies(t *testing.T) {
	b := testBudget(t, 8)
	var wg sync.WaitGroup
	for scope := uint64(1); scope <= 8; scope++ {
		r, err := b.reserve(scope)
		if err != nil {
			t.Fatal(err)
		}
		copy := *r
		for range 8 {
			wg.Go(func() { copy.release() })
		}
	}
	wg.Wait()
	if b.Usage() != (BudgetLimits{}) {
		t.Fatal("concurrent release lost accounting")
	}
}
func testResourceManifest() *operators.NativeResources {
	r := &operators.NativeResources{Maps: map[string]operators.NativeMapResource{"eo_work": {Type: uint32(ebpf.TaskStorage), KeySize: 4, ValueSize: 1096}}, Programs: map[string]operators.NativeProgramResource{}}
	for n, h := range ownerHooks {
		r.Programs[n] = operators.NativeProgramResource{Type: uint32(h.kind), Target: h.target, Instructions: 1}
	}
	r.Programs["eo_command"] = operators.NativeProgramResource{Type: uint32(ebpf.Syscall), Instructions: 1}
	return r
}
func TestResourcePreflightBounds(t *testing.T) {
	if err := validateOwnerResources(testResourceManifest(), 8); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*operators.NativeResources){
		"oversized hash": func(r *operators.NativeResources) {
			r.Maps["extra"] = operators.NativeMapResource{Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: 0xffffffff, MaxEntries: 0xffffffff}
		},
		"unknown storage": func(r *operators.NativeResources) {
			r.Maps["extra"] = operators.NativeMapResource{Type: uint32(ebpf.TaskStorage), ValueSize: 8}
		},
		"oversized ring": func(r *operators.NativeResources) {
			r.Maps["extra"] = operators.NativeMapResource{Type: uint32(ebpf.RingBuf), MaxEntries: 0xffffffff}
		},
		"disabled hook": func(r *operators.NativeResources) {
			p := r.Programs["eo_task_exit"]
			p.Target = "gadget_program_disabled"
			r.Programs["eo_task_exit"] = p
		},
		"missing hook": func(r *operators.NativeResources) { delete(r.Programs, "eo_task_alloc") },
		"noncommand": func(r *operators.NativeResources) {
			r.Programs["eo_command"] = operators.NativeProgramResource{Type: uint32(ebpf.LSM), Instructions: 1}
		},
		"instructions": func(r *operators.NativeResources) {
			r.Programs["extra"] = operators.NativeProgramResource{Instructions: OwnerInstructionLimit + 1}
		},
		"unbounded map": func(r *operators.NativeResources) {
			r.Maps["extra"] = operators.NativeMapResource{Type: uint32(ebpf.Hash), ValueSize: 1}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := testResourceManifest()
			mutate(r)
			if err := validateOwnerResources(r, 8); err == nil {
				t.Fatal("unsupported resources accepted")
			}
		})
	}
	if err := validateOwnerResources(testResourceManifest(), 4097); err == nil {
		t.Fatal("CPU bound ignored")
	}
}
