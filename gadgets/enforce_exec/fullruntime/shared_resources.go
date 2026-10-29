// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"math"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedResourceUsage accounts logical payload and declared native allowances,
// not allocator/JIT overhead, physical RSS, kernel admission or protection Ready.
// AdminPayloadBytes covers ONE owned task-storage value, not a preallocated map;
// the startup adapter must enforce that lifetime/cardinality separately.
type sharedResourceUsage struct {
	MapPayloadBytes, AdminPayloadBytes, NativeAllowanceBytes uint64
	ProgramInstructions, ProgramBytes, LogicalBytes          uint64
}

const sharedProtocolRodataMaxBytes uint32 = 4096

func checkedSharedResourceSum(values ...uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return 0, fmt.Errorf("shared resource sum overflow")
		}
		total += value
	}
	return total, nil
}

// validateSharedProtocolResources validates the current protocol-only manifest
// before allocation. It NEVER resizes or rewrites image resources. An image with
// legacy eo_* banks/hooks or future unaccounted canonical maps is rejected: the
// final shared runtime must explicitly extend this inventory and accounting.
// This is not a complete enforcement-image or attachment validator.
func validateSharedProtocolResources(profile SharedProfile, resources *operators.NativeResources) (sharedResourceUsage, error) {
	admission, err := profile.Validate()
	if err != nil {
		return sharedResourceUsage{}, err
	}
	if resources == nil {
		return sharedResourceUsage{}, fmt.Errorf("shared native resource manifest required")
	}
	expected := map[string]operators.NativeMapResource{
		"se_configuration": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 56, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
		"se_admin":         {Type: uint32(ebpf.TaskStorage), KeySize: 4, ValueSize: 8, Flags: unix.BPF_F_NO_PREALLOC},
		"se_commands":      {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 696, MaxEntries: 1, Flags: unix.BPF_F_WRONLY},
		"se_receipts":      {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 48, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
		"se_objects":       {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 80, MaxEntries: uint32(admission.PolicyObjects), Flags: unix.BPF_F_RDONLY},
		"se_bindings":      {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 824, MaxEntries: uint32(profile.Bindings), Flags: unix.BPF_F_RDONLY},
		"se_arena":         {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 288, MaxEntries: uint32(admission.ArenaCells), Flags: unix.BPF_F_RDONLY},
	}
	for name, want := range expected {
		if got, ok := resources.Maps[name]; !ok || got != want {
			return sharedResourceUsage{}, fmt.Errorf("shared map %s missing or incompatible", name)
		}
	}
	var usage sharedResourceUsage
	for name, resource := range resources.Maps {
		if _, ok := expected[name]; !ok {
			if name != ".rodata" || resource.Type != uint32(ebpf.Array) || resource.KeySize != 4 || resource.ValueSize == 0 || resource.ValueSize > sharedProtocolRodataMaxBytes || resource.MaxEntries != 1 || resource.Flags != unix.BPF_F_RDONLY_PROG || resource.InnerMap != nil {
				return sharedResourceUsage{}, fmt.Errorf("unaccounted or incompatible shared map %s", name)
			}
		}
		if name == "se_admin" {
			usage.AdminPayloadBytes = uint64(resource.ValueSize)
			continue
		}
		payload, err := checkedSharedProduct(uint64(resource.ValueSize), uint64(resource.MaxEntries))
		if err != nil {
			return sharedResourceUsage{}, err
		}
		usage.MapPayloadBytes, err = checkedSharedResourceSum(usage.MapPayloadBytes, payload)
		if err != nil {
			return sharedResourceUsage{}, err
		}
	}
	command, ok := resources.Programs["se_command"]
	if !ok || len(resources.Programs) != 1 || command.Type != uint32(ebpf.Syscall) || command.Target != "" || command.Instructions == 0 {
		return sharedResourceUsage{}, fmt.Errorf("shared protocol requires only the se_command syscall program")
	}
	usage.ProgramInstructions = command.Instructions
	usage.ProgramBytes, err = checkedSharedProduct(command.Instructions, 8)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	compileBytes, err := checkedSharedProduct(profile.CompileBytes, profile.CompileConcurrency)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	usage.NativeAllowanceBytes, err = checkedSharedResourceSum(compileBytes, profile.CandidateBytes, profile.TelemetryBytes, profile.RolloutBytes)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	usage.LogicalBytes, err = checkedSharedResourceSum(usage.MapPayloadBytes, usage.AdminPayloadBytes, usage.ProgramBytes, usage.NativeAllowanceBytes)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	return usage, nil
}
