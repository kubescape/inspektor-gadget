// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func sharedResourcesFixture() (SharedProfile, *operators.NativeResources) {
	p := sharedTestProfile()
	return p, &operators.NativeResources{
		Maps: map[string]operators.NativeMapResource{
			"se_configuration": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 56, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
			"se_admin":         {Type: uint32(ebpf.TaskStorage), KeySize: 4, ValueSize: 8, MaxEntries: 0, Flags: unix.BPF_F_NO_PREALLOC},
			"se_commands":      {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 696, MaxEntries: 1, Flags: unix.BPF_F_WRONLY},
			"se_receipts":      {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 48, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
			"se_objects":       {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 80, MaxEntries: 8, Flags: unix.BPF_F_RDONLY},
			"se_bindings":      {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 824, MaxEntries: 2, Flags: unix.BPF_F_RDONLY},
			"se_arena":         {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 288, MaxEntries: 23552, Flags: unix.BPF_F_RDONLY},
		},
		Programs: map[string]operators.NativeProgramResource{"se_command": {Type: uint32(ebpf.Syscall), Instructions: 17}},
	}
}

func checkSharedResources(t *testing.T, p SharedProfile, r *operators.NativeResources, wantValid bool) sharedResourceUsage {
	t.Helper()
	before, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	usage, validationErr := validateSharedProtocolResources(p, r)
	after, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("validation mutated caller's resource manifest")
	}
	if wantValid && validationErr != nil {
		t.Fatal(validationErr)
	}
	if !wantValid && (validationErr == nil || usage != (sharedResourceUsage{})) {
		t.Fatalf("invalid manifest returned admitted usage: %+v %v", usage, validationErr)
	}
	return usage
}

func TestSharedResourcesExactProtocolAccounting(t *testing.T) {
	p, r := sharedResourcesFixture()
	got := checkSharedResources(t, p, r, true)
	want := sharedResourceUsage{
		MapPayloadBytes:     56 + 696 + 48 + 8*80 + 2*824 + 23552*288,
		AdminPayloadBytes:   8,
		ProgramInstructions: 17, ProgramBytes: 17 * 8,
		NativeAllowanceBytes: 2*(8<<20) + (1 << 20) + 4096 + 4096,
	}
	want.LogicalBytes = want.MapPayloadBytes + want.AdminPayloadBytes + want.ProgramBytes + want.NativeAllowanceBytes
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	for _, size := range []uint32{1, sharedProtocolRodataMaxBytes} {
		r.Maps[".rodata"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: size, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG}
		got = checkSharedResources(t, p, r, true)
		if got.MapPayloadBytes != want.MapPayloadBytes+uint64(size) || got.LogicalBytes != want.LogicalBytes+uint64(size) || got.AdminPayloadBytes != 8 {
			t.Fatalf("rodata uncharged or dynamic admin omitted: %+v", got)
		}
	}
}

func TestSharedResourcesRejectEveryMapGeometryChange(t *testing.T) {
	_, fixture := sharedResourcesFixture()
	changes := map[string]func(*operators.NativeMapResource){
		"type":               func(m *operators.NativeMapResource) { m.Type = uint32(ebpf.Hash) },
		"key":                func(m *operators.NativeMapResource) { m.KeySize++ },
		"value":              func(m *operators.NativeMapResource) { m.ValueSize++ },
		"count":              func(m *operators.NativeMapResource) { m.MaxEntries++ },
		"missing-protection": func(m *operators.NativeMapResource) { m.Flags = 0 },
		"extra-flag":         func(m *operators.NativeMapResource) { m.Flags |= unix.BPF_F_MMAPABLE },
		"inner-template": func(m *operators.NativeMapResource) {
			m.InnerMap = &operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: 1}
		},
	}
	for name := range fixture.Maps {
		t.Run(name+"/missing", func(t *testing.T) {
			p, r := sharedResourcesFixture()
			delete(r.Maps, name)
			checkSharedResources(t, p, r, false)
		})
		for change, mutate := range changes {
			t.Run(name+"/"+change, func(t *testing.T) {
				p, r := sharedResourcesFixture()
				m := r.Maps[name]
				mutate(&m)
				r.Maps[name] = m
				checkSharedResources(t, p, r, false)
			})
		}
	}
}

func TestSharedResourcesRejectUnaccountedMapsAndPrograms(t *testing.T) {
	for _, name := range []string{"eo_programs", "eo_gates", "fs_inode_origins", "future_canonical_history", ".rodata.future", ".bss"} {
		t.Run(name, func(t *testing.T) {
			p, r := sharedResourcesFixture()
			r.Maps[name] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: 1}
			checkSharedResources(t, p, r, false)
		})
	}
	tests := map[string]func(*operators.NativeResources){
		"missing-command": func(r *operators.NativeResources) { delete(r.Programs, "se_command") },
		"wrong-command-type": func(r *operators.NativeResources) {
			c := r.Programs["se_command"]
			c.Type = uint32(ebpf.Tracing)
			r.Programs["se_command"] = c
		},
		"wrong-command-target": func(r *operators.NativeResources) {
			c := r.Programs["se_command"]
			c.Target = "sys_enter"
			r.Programs["se_command"] = c
		},
		"zero-instructions": func(r *operators.NativeResources) {
			c := r.Programs["se_command"]
			c.Instructions = 0
			r.Programs["se_command"] = c
		},
		"instruction-byte-overflow": func(r *operators.NativeResources) {
			c := r.Programs["se_command"]
			c.Instructions = math.MaxUint64
			r.Programs["se_command"] = c
		},
		"legacy-hook": func(r *operators.NativeResources) {
			r.Programs["eo_sched_exec"] = operators.NativeProgramResource{Type: uint32(ebpf.Tracing), Target: "sched_process_exec", Instructions: 10}
		},
		"future-hook": func(r *operators.NativeResources) {
			r.Programs["future_hook"] = operators.NativeProgramResource{Type: uint32(ebpf.LSM), Target: "bprm_check_security", Instructions: 10}
		},
		"nil-maps": func(r *operators.NativeResources) { r.Maps = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) { p, r := sharedResourcesFixture(); mutate(r); checkSharedResources(t, p, r, false) })
	}
	p, _ := sharedResourcesFixture()
	checkSharedResources(t, p, nil, false)
}

func TestSharedResourcesRodataIsBoundedNotAPrefixAllowlist(t *testing.T) {
	changes := map[string]func(*operators.NativeMapResource){
		"oversized": func(m *operators.NativeMapResource) { m.ValueSize = sharedProtocolRodataMaxBytes + 1 },
		"zero":      func(m *operators.NativeMapResource) { m.ValueSize = 0 },
		"writable":  func(m *operators.NativeMapResource) { m.Flags = 0 },
		"type":      func(m *operators.NativeMapResource) { m.Type = uint32(ebpf.PerCPUArray) },
		"key":       func(m *operators.NativeMapResource) { m.KeySize = 8 },
		"count":     func(m *operators.NativeMapResource) { m.MaxEntries = 2 },
		"inner":     func(m *operators.NativeMapResource) { m.InnerMap = &operators.NativeMapResource{} },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			p, r := sharedResourcesFixture()
			m := operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG}
			mutate(&m)
			r.Maps[".rodata"] = m
			checkSharedResources(t, p, r, false)
		})
	}
}

func TestSharedResourcesRejectProfileAndAccountingOverflow(t *testing.T) {
	changes := map[string]func(*SharedProfile){
		"version":                  func(p *SharedProfile) { p.Version++ },
		"cpus-zero":                func(p *SharedProfile) { p.PossibleCPUs = 0 },
		"cpus-65":                  func(p *SharedProfile) { p.PossibleCPUs = 65 },
		"missing-native-allowance": func(p *SharedProfile) { p.RolloutBytes = 0 },
		"reservation":              func(p *SharedProfile) { p.PerBinding.InodeFacts++ },
		"bindings":                 func(p *SharedProfile) { p.Bindings = math.MaxUint64 },
		"arena-product":            func(p *SharedProfile) { p.PolicySlots[3] = math.MaxUint64 },
		"compile-product":          func(p *SharedProfile) { p.CompileBytes = math.MaxUint64 },
		"native-sum":               func(p *SharedProfile) { p.CandidateBytes = math.MaxUint64 },
		"total-sum": func(p *SharedProfile) {
			p.CompileBytes = 1
			p.CompileConcurrency = 1
			p.TelemetryBytes = 1
			p.RolloutBytes = 1
			p.CandidateBytes = math.MaxUint64 - 3
		},
		"profile-map-mismatch": func(p *SharedProfile) { p.PolicySlots[0]++ },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) { p, r := sharedResourcesFixture(); mutate(&p); checkSharedResources(t, p, r, false) })
	}
}
