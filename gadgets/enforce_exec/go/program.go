// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"path"
	"strings"

	policy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var (
	document             policy.Document
	generation           uint64
	entries              [policy.KernelMaxRules + 1]policy.KernelEntry
	bindings, candidate  api.Map
	cgroup               uint64
	status, updates      api.DataSource
	statusF              map[string]api.Field
	updateRaw, updateCAS api.Field
	stopping             bool
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var err error
	status, err = api.NewDataSource("status", api.DataSourceTypeSingle)
	if err != nil {
		return failed(err)
	}
	statusF = make(map[string]api.Field)
	for _, name := range []string{"state", "revision", "message"} {
		statusF[name], err = status.AddField(name, api.Kind_String)
		if err != nil {
			return failed(err)
		}
	}
	for _, name := range []string{"generation", "cgroup_id"} {
		statusF[name], err = status.AddField(name, api.Kind_Uint64)
		if err != nil {
			return failed(err)
		}
	}
	// An embedding host emits to this input. The CLI parameter is initial input.
	updates, err = api.NewDataSource("exec_policy_updates", api.DataSourceTypeSingle)
	if err != nil {
		return failed(err)
	}
	updateRaw, err = updates.AddField("policy", api.Kind_String)
	if err != nil {
		return failed(err)
	}
	updateCAS, err = updates.AddField("expected_generation", api.Kind_Uint64)
	if err != nil {
		return failed(err)
	}
	return 0
}

func failed(err error) int32 { api.Errorf("enforce_exec: %v", err); return 1 }

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	raw, err := api.GetParamValue(policy.ParameterName, uint64(policy.DefaultLimits().MaxBytes+1))
	if err != nil {
		return failed(fmt.Errorf("reading exec-policy: %w", err))
	}
	document, err = policy.Parse(strings.NewReader(raw), policy.DefaultLimits())
	if err != nil {
		return failed(fmt.Errorf("invalid policy: %w", err))
	}
	entries, err = policy.CompileKernel(document, 1)
	if err != nil {
		return failed(fmt.Errorf("invalid kernel policy: %w", err))
	}
	generation = 1
	api.Infof("enforce_exec: validated policy %s; waiting for target resolution", document.Hash())
	return 0
}

func newGeneration(values [policy.KernelMaxRules + 1]policy.KernelEntry) (api.Map, error) {
	m, err := api.NewMap(api.MapSpec{Name: "exec_generation", Type: api.Array, KeySize: 4, ValueSize: 288, MaxEntries: policy.KernelMaxRules + 1})
	if err != nil {
		return 0, err
	}
	for index, value := range values {
		if err := m.Put(uint32(index), value); err != nil {
			return 0, errors.Join(err, m.Close())
		}
	}
	if err := m.Freeze(); err != nil {
		return 0, errors.Join(err, m.Close())
	}
	return m, nil
}

func emitStatus(state, message string) {
	packet, err := status.NewPacketSingle()
	if err == nil {
		data := api.Data(packet)
		err = errors.Join(statusF["state"].SetString(data, state), statusF["revision"].SetString(data, document.Hash()), statusF["message"].SetString(data, message), statusF["generation"].SetUint64(data, generation), statusF["cgroup_id"].SetUint64(data, cgroup))
		if err == nil {
			err = status.EmitAndRelease(api.Packet(packet))
		} else {
			err = errors.Join(err, status.Release(api.Packet(packet)))
		}
	}
	if err != nil {
		api.Errorf("enforce_exec: reporting status: %v", err)
	}
	api.Infof("enforce_exec: %s generation=%d cgroup=%d: %s", state, generation, cgroup, message)
}

func activeState() string {
	if cgroup == 0 {
		return "waiting-for-target"
	}
	switch document.Policy.Mode {
	case "audit":
		return "auditing"
	case "off":
		return "off"
	default:
		return "enforcing"
	}
}

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	var err error
	bindings, err = api.GetMap("bindings")
	if err != nil {
		return failed(err)
	}
	candidate, err = newGeneration(entries)
	if err != nil {
		return failed(err)
	}
	containers, err := api.GetDataSource(api.DataSourceContainers)
	if err != nil {
		return failed(err)
	}
	fields := make(map[string]api.Field)
	for _, name := range []string{"event_type", "runtime", "container_id", "cgroup_id", "cgroup_v2_path"} {
		fields[name], err = containers.GetField(name)
		if err != nil {
			return failed(err)
		}
	}
	if err := containers.Subscribe(func(_ api.DataSource, data api.Data) {
		if stopping {
			return
		}
		runtime, e1 := fields["runtime"].String(data, 64)
		id, e2 := fields["container_id"].String(data, 4096)
		kind, e3 := fields["event_type"].String(data, api.DataSourceContainersEventTypeMaxSize)
		cg, e4 := fields["cgroup_id"].Uint64(data)
		cgpath, e5 := fields["cgroup_v2_path"].String(data, 4096)
		if err := errors.Join(e1, e2, e3, e4, e5); err != nil {
			emitStatus("error", fmt.Sprintf("invalid container event: %v", err))
			return
		}
		if runtime != document.Binding.Container.Runtime || id != document.Binding.Container.ID {
			return
		}
		switch kind {
		case "CREATED":
			if cg == 0 || cgpath == "/" || !path.IsAbs(cgpath) || path.Clean(cgpath) != cgpath || (cgroup != 0 && cgroup != cg) {
				emitStatus("error", "missing cgroup v2 identity or conflicting live target")
				return
			}
			if err := bindings.Put(cg, candidate); err != nil {
				emitStatus("error", fmt.Sprintf("binding failed: %v", err))
				return
			}
			cgroup = cg
			emitStatus(activeState(), "target bound; enforcement lifetime follows this gadget instance")
		case "DELETED":
			if cgroup == 0 || cg != cgroup {
				return
			}
			if err := bindings.Delete(cgroup); err != nil {
				emitStatus("error", fmt.Sprintf("removing binding failed: %v", err))
				return
			}
			cgroup = 0
			emitStatus("target-removed", "binding removed")
		}
	}, 0); err != nil {
		return failed(err)
	}
	if err := updates.Subscribe(func(_ api.DataSource, data api.Data) {
		if stopping {
			return
		}
		raw, e1 := updateRaw.String(data, uint32(policy.DefaultLimits().MaxBytes+1))
		expected, e2 := updateCAS.Uint64(data)
		if err := errors.Join(e1, e2); err != nil {
			emitStatus("update-rejected", err.Error())
			return
		}
		if err := replace(raw, expected); err != nil {
			emitStatus("update-rejected", err.Error())
		}
	}, 0); err != nil {
		return failed(err)
	}
	emitStatus("waiting-for-target", "program attached with no active binding; no first-execution guarantee")
	return 0
}

func replace(raw string, expected uint64) error {
	if expected != generation || generation == ^uint64(0) {
		return fmt.Errorf("generation conflict: expected %d, active %d", expected, generation)
	}
	doc, err := policy.Parse(strings.NewReader(raw), policy.DefaultLimits())
	if err != nil {
		return err
	}
	values, err := policy.CompileKernel(doc, generation+1)
	if err != nil {
		return err
	}
	if *doc.Binding.Container != *document.Binding.Container {
		return fmt.Errorf("target changes require a new gadget instance")
	}
	m, err := newGeneration(values)
	if err != nil {
		return err
	}
	if cgroup != 0 {
		if err := bindings.Put(cgroup, m); err != nil {
			return errors.Join(err, m.Close())
		}
	}
	old := candidate
	candidate, document, entries = m, doc, values
	generation++
	if err := old.Close(); err != nil {
		api.Warnf("enforce_exec: releasing old generation: %v", err)
	}
	emitStatus(activeState(), "policy generation replaced")
	return nil
}

//go:wasmexport gadgetStop
func gadgetStop() int32 {
	stopping = true
	if cgroup != 0 {
		if err := bindings.Delete(cgroup); err != nil {
			return failed(err)
		}
		cgroup = 0
	}
	if candidate != 0 {
		if err := candidate.Close(); err != nil {
			return failed(err)
		}
		candidate = 0
	}
	if bindings != 0 {
		if err := api.ReleaseHandle(bindings); err != nil {
			return failed(err)
		}
		bindings = 0
	}
	emitStatus("stopped", "binding removed; BPF links are released by IG")
	return 0
}
func main() {}
