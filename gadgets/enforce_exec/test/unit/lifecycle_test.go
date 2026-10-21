// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package unit_test

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	policy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
)

// runLifecycle executes the actual guest with in-memory host services. Kernel
// verifier/attachment coverage belongs to the privileged integration suite.
func runLifecycle(t *testing.T, wasm, raw []byte) {
	t.Helper()
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		t.Fatal(err)
	}
	compiled, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := policy.Parse(strings.NewReader(string(raw)), policy.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	type generationMap struct {
		values         map[uint32][]byte
		frozen, closed bool
	}
	maps := map[uint64]*generationMap{}
	sources := map[string]uint64{"containers": 5}
	fields := map[uint64]string{}
	callbacks := map[uint64]uint64{}
	input := map[string]string{}
	var inputGeneration, inputCgroup, bound, boundCgroup uint64
	var next uint64 = 100
	var failFreeze, failBind, failHealth bool
	var failures, degraded, reportedFailures, reportedDegraded uint64
	var binds int
	failHealthAfterReads := -1
	var state, message string
	var reportedGeneration uint64
	alloc := func() uint64 { next++; return next }
	read := func(m api.Module, ptr uint64) []byte {
		b, ok := m.Memory().Read(uint32(ptr), uint32(ptr>>32))
		if !ok {
			panic("invalid guest buffer")
		}
		return b
	}
	host := rt.NewHostModuleBuilder("ig")
	seen := map[string]bool{}
	for _, fn := range compiled.ImportedFunctions() {
		module, name, _ := fn.Import()
		if module != "ig" || seen[name] {
			continue
		}
		seen[name] = true
		host.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, s []uint64) {
			for i, typ := range fn.ParamTypes() {
				if typ == api.ValueTypeI32 {
					s[i] = uint64(uint32(s[i]))
				}
			}
			var result uint64
			switch name {
			case "getParamValue":
				if !m.Memory().Write(uint32(s[1]), append(append([]byte{}, raw...), 0)) {
					panic("invalid parameter destination")
				}
			case "gadgetShouldLog":
				result = 0
			case "gadgetLog":
			case "newDataSource":
				result = alloc()
				sources[string(read(m, s[0]))] = result
			case "getDataSource":
				result = sources[string(read(m, s[0]))]
			case "dataSourceAddField", "dataSourceGetField":
				result = alloc()
				fields[result] = string(read(m, s[1]))
			case "dataSourceSubscribe":
				callbacks[s[0]] = s[3]
			case "dataSourceNewPacketSingle":
				result = 99
			case "dataSourceEmitAndRelease", "dataSourceRelease", "releaseHandle":
			case "fieldSet":
				switch fields[s[0]] {
				case "state":
					state = string(read(m, s[3]))
				case "message":
					message = string(read(m, s[3]))
				case "generation":
					reportedGeneration = s[3]
				case "tracking_failures":
					reportedFailures = s[3]
				case "tracking_degraded":
					reportedDegraded = s[3]
				}
			case "fieldGetBuffer":
				value := []byte(input[fields[s[0]]])
				if uint64(len(value)) > s[3]>>32 {
					panic("short field buffer")
				}
				if !m.Memory().Write(uint32(s[3]), value) {
					panic("invalid field destination")
				}
				result = uint64(len(value))
			case "fieldGetScalar":
				if !m.Memory().WriteUint32Le(uint32(s[3]), 0) {
					panic("invalid error destination")
				}
				switch fields[s[0]] {
				case "cgroup_id":
					result = inputCgroup
				case "expected_generation":
					result = inputGeneration
				case "request_id":
					result = 0
				case "host_pid":
					result = uint64(doc.Binding.Process.HostPID)
				case "start_time_ticks":
					result = doc.Binding.Process.StartTimeTicks
				default:
					panic("unexpected scalar")
				}
			case "getMap":
				switch string(read(m, s[0])) {
				case "bindings":
					result = 7
				case "process_bindings":
					result = 8
				case "process_targets":
					result = 9
				case "process_health":
					result = 10
				}
			case "bindProcess":
				if s[0] != 9 || bound == 0 {
					panic("process marked before publishing policy")
				}
				binds++
			case "mapLookup":
				if s[0] != 10 {
					panic("unexpected lookup")
				}
				if failHealth || failHealthAfterReads == 0 {
					result = 1
				} else {
					if failHealthAfterReads > 0 {
						failHealthAfterReads--
					}
					value := make([]byte, 16)
					binary.LittleEndian.PutUint64(value, failures)
					binary.LittleEndian.PutUint64(value[8:], degraded)
					if !m.Memory().Write(uint32(s[2]), value) {
						panic("invalid health buffer")
					}
				}
			case "newMap":
				if s[1] != 2 || s[2] != 4 || s[3] != 288 || s[4] != 9 {
					panic("unexpected map ABI")
				}
				result = alloc()
				maps[result] = &generationMap{values: map[uint32][]byte{}}
			case "mapUpdate":
				if s[0] == 7 || s[0] == 8 {
					candidate := uint64(binary.LittleEndian.Uint32(read(m, s[2])))
					if maps[candidate] == nil || !maps[candidate].frozen || maps[candidate].closed {
						panic("binding unpublished generation")
					}
					if failBind {
						result = 1
					} else {
						bound = candidate
						if s[0] == 7 {
							boundCgroup = binary.LittleEndian.Uint64(read(m, s[1]))
						}
					}
				} else {
					gm := maps[s[0]]
					if gm == nil || gm.frozen || gm.closed {
						panic("writing immutable generation")
					}
					gm.values[binary.LittleEndian.Uint32(read(m, s[1]))] = append([]byte{}, read(m, s[2])...)
				}
			case "mapFreeze":
				gm := maps[s[0]]
				if gm == nil || len(gm.values) != 9 {
					panic("freezing incomplete generation")
				}
				if failFreeze {
					result = 1
				} else {
					gm.frozen = true
				}
			case "mapRelease":
				gm := maps[s[0]]
				if gm == nil || gm.closed {
					panic("closing invalid generation")
				}
				gm.closed = true
			case "mapDelete":
				if (s[0] != 7 && s[0] != 8) || (s[0] == 7 && binary.LittleEndian.Uint64(read(m, s[1])) != boundCgroup) {
					panic("deleting wrong binding")
				}
				bound = 0
				boundCgroup = 0
			default:
				panic("unexpected host call " + name)
			}
			if len(fn.ResultTypes()) > 0 {
				s[0] = result
			}
		}), fn.ParamTypes(), fn.ResultTypes()).Export(name)
	}
	if _, err := host.Instantiate(ctx); err != nil {
		t.Fatal(err)
	}
	guest, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithStartFunctions("_initialize"))
	if err != nil {
		t.Fatal(err)
	}
	call := func(name string, args ...uint64) {
		t.Helper()
		result, err := guest.ExportedFunction(name).Call(ctx, args...)
		if err != nil || (len(result) > 0 && result[0] != 0) {
			t.Fatalf("%s: result=%v err=%v", name, result, err)
		}
	}
	emit := func(source string) {
		t.Helper()
		ds := sources[source]
		cb, ok := callbacks[ds]
		if !ok {
			t.Fatalf("no subscription to %s", source)
		}
		call("dataSourceCallback", cb, ds, 1)
	}
	container := func(kind, runtime, id string, cg uint64) {
		input = map[string]string{"event_type": kind, "runtime": runtime, "container_id": id, "cgroup_v2_path": "/test-target"}
		inputCgroup = cg
		emit("containers")
	}
	update := func(value string, expected uint64) {
		input = map[string]string{"policy": value}
		inputGeneration = expected
		emit("exec_policy_updates")
	}
	assertActive := func(want uint64) {
		t.Helper()
		if bound == 0 || binary.LittleEndian.Uint64(maps[bound].values[0]) != want || reportedGeneration != want {
			t.Fatalf("expected generation %d; bound=%d reported=%d", want, bound, reportedGeneration)
		}
	}
	call("gadgetInit")
	call("gadgetPreStart")
	call("gadgetStart")
	if doc.Binding.Process != nil {
		if binds != 1 || bound == 0 {
			t.Fatal("process not bound")
		}
		assertActive(1)
		modePolicy := func(mode string) string {
			return strings.Replace(string(raw), "mode: "+doc.Policy.Mode, "mode: "+mode, 1)
		}
		wantState := map[string]string{"enforce": "enforcing", "audit": "auditing", "off": "off"}[doc.Policy.Mode]
		if state != wantState {
			t.Fatalf("initial state %s", state)
		}
		gen := uint64(1)
		reject := func(raw string) {
			t.Helper()
			old, allocated := bound, len(maps)
			update(raw, gen)
			if state != "update-rejected" || bound != old || len(maps) != allocated {
				t.Fatalf("rejected update mutated policy: state=%s bound=%d maps=%d", state, bound, len(maps))
			}
			assertActive(gen)
		}
		if doc.Policy.Mode == "enforce" {
			update(modePolicy("enforce"), gen)
			gen++
			assertActive(gen)
			update(modePolicy("audit"), gen)
			gen++
			assertActive(gen)
		}
		// Reject escalation even with a clean health snapshot: an older hook
		// can still lose the marker after this snapshot is read.
		reject(modePolicy("enforce"))
		failures, degraded = 3, 1
		reject(modePolicy("enforce"))
		if reportedFailures != 3 || reportedDegraded != 1 {
			t.Fatal("tracking health missing from rejection")
		}
		for _, mode := range []string{"off", "audit", "off"} {
			update(modePolicy(mode), gen)
			gen++
			assertActive(gen)
			want := map[string]string{"audit": "auditing", "off": "off"}[mode]
			if state != want || reportedFailures != 3 || reportedDegraded != 1 {
				t.Fatal("nonblocking update lost degraded status")
			}
		}
		// The preflight read succeeds and the generation commits, but the
		// status read fails. Its acknowledgement must still describe success.
		failHealthAfterReads = 1
		update(modePolicy("audit"), gen)
		gen++
		assertActive(gen)
		if state != "auditing" || reportedDegraded != 1 || !strings.Contains(message, "health unknown") {
			t.Fatal("committed update lost acknowledgement on health read failure")
		}
		failHealthAfterReads = -1
		failHealth = true
		reject(modePolicy("audit"))
		if reportedDegraded != 1 {
			t.Fatal("unreadable health reported healthy")
		}
		failHealth = false
		input = map[string]string{"event_type": "EXITED"}
		emit("process_lifecycle")
		if state != "target-removed" || bound != 0 {
			t.Fatal("exit retained process binding")
		}
		allocated := len(maps)
		update(modePolicy("enforce"), gen)
		if state != "update-rejected" || len(maps) != allocated || reportedGeneration != gen {
			t.Fatal("exited process accepted enforcement")
		}
		call("gadgetStop")
		for id, gm := range maps {
			if !gm.closed {
				t.Fatalf("stop leaked generation %d", id)
			}
		}
		if binds != 1 {
			t.Fatal("live update silently rebound process")
		}
		return
	}
	if state != "waiting-for-target" || bound != 0 {
		t.Fatalf("unexpected initial state %s", state)
	}
	target := doc.Binding.Container
	container("CREATED", "other-runtime", target.ID, 77)
	container("CREATED", target.Runtime, "other-container", 77)
	if bound != 0 {
		t.Fatal("unrelated container bound")
	}
	for _, invalidPath := range []string{"", "/", "relative/path", "/unclean/../path"} {
		input = map[string]string{"event_type": "CREATED", "runtime": target.Runtime, "container_id": target.ID, "cgroup_v2_path": invalidPath}
		inputCgroup = 77
		emit("containers")
		if bound != 0 {
			t.Fatalf("invalid cgroup v2 path %q bound target", invalidPath)
		}
	}
	container("CREATED", target.Runtime, target.ID, 77)
	if state != "enforcing" || boundCgroup != 77 {
		t.Fatalf("target not enforcing: %s", state)
	}
	assertActive(1)
	old := bound
	update(string(raw), 0)
	if state != "update-rejected" || bound != old {
		t.Fatal("stale CAS replaced generation")
	}
	update("version: 100", 1)
	if state != "update-rejected" || bound != old {
		t.Fatal("invalid policy replaced generation")
	}
	failFreeze = true
	update(string(raw), 1)
	failFreeze = false
	if state != "update-rejected" || bound != old {
		t.Fatal("freeze failure replaced generation")
	}
	failBind = true
	update(string(raw), 1)
	failBind = false
	if state != "update-rejected" || bound != old {
		t.Fatal("binding failure replaced generation")
	}
	assertActive(1)
	update(strings.Replace(string(raw), "mode: enforce", "mode: audit", 1), 1)
	assertActive(2)
	if state != "auditing" || !maps[old].closed {
		t.Fatal("replacement did not retire previous generation")
	}
	for id, gm := range maps {
		if id != bound && !gm.closed {
			t.Fatalf("generation map %d leaked", id)
		}
	}
	container("DELETED", target.Runtime, target.ID, 88)
	assertActive(2)
	container("DELETED", target.Runtime, target.ID, 77)
	if bound != 0 || state != "target-removed" {
		t.Fatal("target deletion retained binding")
	}
	container("CREATED", target.Runtime, target.ID, 99)
	assertActive(2)
	call("gadgetStop")
	if bound != 0 || state != "stopped" {
		t.Fatal("stop retained binding")
	}
	for id, gm := range maps {
		if !gm.closed {
			t.Fatalf("stop leaked generation %d", id)
		}
	}
	container("CREATED", target.Runtime, target.ID, 99)
	if bound != 0 {
		t.Fatal("event after stop reinstated binding")
	}
}
