// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"

	policy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var (
	document                        policy.Document
	generation                      uint64
	entries                         [policy.KernelMaxRules + 1]policy.KernelEntry
	bindings, candidate             api.Map
	processBindings, processTargets api.Map
	processHealth                   api.Map
	processBound                    bool
	requestID                       uint64
	updateRequest                   api.Field
	cgroup                          uint64
	status, updates                 api.DataSource
	statusF                         map[string]api.Field
	updateRaw, updateCAS            api.Field
	stopping                        bool
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
	for _, name := range []string{"generation", "cgroup_id", "request_id", "host_pid", "tracking_failures", "tracking_degraded"} {
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
	updateRequest, err = updates.AddField("request_id", api.Kind_Uint64)
	if err != nil {
		return failed(err)
	}
	lifecycle, err := api.NewDataSource("process_lifecycle", api.DataSourceTypeSingle)
	if err != nil {
		return failed(err)
	}
	if _, err = lifecycle.AddField("event_type", api.Kind_String); err != nil {
		return failed(err)
	}
	if _, err = lifecycle.AddField("host_pid", api.Kind_Uint32); err != nil {
		return failed(err)
	}
	if _, err = lifecycle.AddField("start_time_ticks", api.Kind_Uint64); err != nil {
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

type trackingHealth struct {
	Failures uint64
	Degraded uint64
}

func readTrackingHealth() (trackingHealth, error) {
	var health trackingHealth
	if processHealth == 0 {
		return health, fmt.Errorf("process tracking health unavailable")
	}
	err := processHealth.Lookup(uint32(0), &health)
	return health, err
}

func emitStatus(state, message string) {
	var health trackingHealth
	if document.Binding.Process != nil && state != "stopped" {
		var err error
		health, err = readTrackingHealth()
		if err != nil {
			health.Degraded = 1
			message += "; process tracking health unknown: " + err.Error()
			// The generation may already be committed. Keep its acknowledgement
			// successful while reporting unknown health explicitly in the message.
		} else if health.Degraded != 0 {
			message += "; process tracking degraded; launch a new process and instance to enable enforcement"
		}
	}
	packet, err := status.NewPacketSingle()
	if err == nil {
		data := api.Data(packet)
		var pid uint64
		if document.Binding.Process != nil {
			pid = uint64(document.Binding.Process.HostPID)
		}
		err = errors.Join(statusF["tracking_failures"].SetUint64(data, health.Failures), statusF["tracking_degraded"].SetUint64(data, health.Degraded), statusF["request_id"].SetUint64(data, requestID), statusF["host_pid"].SetUint64(data, pid), statusF["state"].SetString(data, state), statusF["revision"].SetString(data, document.Hash()), statusF["message"].SetString(data, message), statusF["generation"].SetUint64(data, generation), statusF["cgroup_id"].SetUint64(data, cgroup))
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
	if cgroup == 0 && !processBound {
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
	if document.Binding.Process != nil {
		if err := bindProcess(); err != nil {
			return failed(err)
		}
	} else if err := subscribeContainers(); err != nil {
		return failed(err)
	}
	if err := updates.Subscribe(func(_ api.DataSource, data api.Data) {
		if stopping {
			return
		}
		id, idErr := updateRequest.Uint64(data)
		if idErr != nil {
			emitStatus("update-rejected", idErr.Error())
			return
		}
		requestID = id
		defer func() { requestID = 0 }()
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
	emitStatus(activeState(), "program attached; resolved target protected; executions before binding are outside coverage")
	return 0
}

func subscribeContainers() error {
	var err error
	containers, err := api.GetDataSource(api.DataSourceContainers)
	if err != nil {
		return err
	}
	fields := make(map[string]api.Field)
	for _, name := range []string{"event_type", "runtime", "container_id", "cgroup_id", "cgroup_v2_path"} {
		fields[name], err = containers.GetField(name)
		if err != nil {
			return err
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
		return err
	}
	return nil
}

func bindProcess() error {
	var err error
	processHealth, err = api.GetMap("process_health")
	if err != nil {
		return err
	}
	if _, err := readTrackingHealth(); err != nil {
		return fmt.Errorf("reading process tracking health: %w", err)
	}
	processBindings, err = api.GetMap("process_bindings")
	if err != nil {
		return err
	}
	processTargets, err = api.GetMap("process_targets")
	if err != nil {
		return err
	}
	lifecycle, err := api.GetDataSource("process_lifecycle")
	if err != nil {
		return err
	}
	event, err := lifecycle.GetField("event_type")
	if err != nil {
		return err
	}
	pid, err := lifecycle.GetField("host_pid")
	if err != nil {
		return err
	}
	birth, err := lifecycle.GetField("start_time_ticks")
	if err != nil {
		return err
	}
	if err := lifecycle.Subscribe(func(_ api.DataSource, data api.Data) {
		if stopping {
			return
		}
		kind, e1 := event.String(data, 16)
		hostpid, e2 := pid.Uint32(data)
		ticks, e3 := birth.Uint64(data)
		p := document.Binding.Process
		if errors.Join(e1, e2, e3) != nil || kind != "EXITED" || hostpid != uint32(p.HostPID) || ticks != p.StartTimeTicks {
			return
		}
		if err := processBindings.Delete(uint32(0)); err != nil {
			emitStatus("error", err.Error())
			return
		}
		processBound = false
		emitStatus("target-removed", "selected process exited; task storage was reclaimed")
	}, 0); err != nil {
		return err
	}
	if err := processBindings.Put(uint32(0), candidate); err != nil {
		return err
	}
	p := document.Binding.Process
	if err := api.BindProcess(processTargets, p.Node, p.BootID, uint32(p.HostPID), p.StartTimeTicks); err != nil {
		return errors.Join(err, processBindings.Delete(uint32(0)))
	}
	processBound = true
	return nil
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
	if !reflect.DeepEqual(doc.Binding, document.Binding) {
		return fmt.Errorf("target changes require a new gadget instance")
	}
	if doc.Binding.Process != nil {
		if !processBound {
			return fmt.Errorf("selected process exited; target changes require a new gadget instance")
		}
		// An audit/off hook can still be running when this update is handled.
		// Even a clean health snapshot cannot prove it will preserve the marker.
		if doc.Policy.Mode == "enforce" && document.Policy.Mode != "enforce" {
			return fmt.Errorf("enabling process enforcement from audit/off requires a new process launch and gadget instance")
		}
		health, err := readTrackingHealth()
		if err != nil {
			return fmt.Errorf("reading process tracking health: %w", err)
		}
		if doc.Policy.Mode == "enforce" && health.Degraded != 0 {
			return fmt.Errorf("process tracking degraded; enforcement requires a new process launch and gadget instance")
		}
	}
	m, err := newGeneration(values)
	if err != nil {
		return err
	}
	if processBound {
		if err := processBindings.Put(uint32(0), m); err != nil {
			return errors.Join(err, m.Close())
		}
	} else if cgroup != 0 {
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
	if processBound {
		if err := processBindings.Delete(uint32(0)); err != nil {
			return failed(err)
		}
		processBound = false
	}
	for _, m := range []api.Map{processBindings, processTargets, processHealth} {
		if m != 0 {
			if err := api.ReleaseHandle(m); err != nil {
				return failed(err)
			}
		}
	}
	processBindings, processTargets, processHealth = 0, 0, 0
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
