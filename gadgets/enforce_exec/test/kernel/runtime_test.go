// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// TestExecRuntime runs the production object and actual guest through IG's OCI
// lifecycle. Synthetic container notifications isolate runtime integration from
// container-runtime installation and discovery timing.
func TestExecRuntime(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" {
		t.Skip("requires disposable BPF LSM host and IG_EXEC_KERNEL_TEST=1")
	}
	require.Equal(t, 0, os.Geteuid(), "root required")
	require.NoError(t, rlimit.RemoveMemlock())
	readArtifact := func(name string) []byte {
		t.Helper()
		path := os.Getenv(name)
		require.NotEmpty(t, path, name)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		return data
	}
	object, wasm, metadata := readArtifact("IG_EXEC_BPF_OBJECT"), readArtifact("IG_EXEC_WASM"), readArtifact("IG_EXEC_METADATA")
	cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-exec-runtime-%d", os.Getpid())
	require.NoError(t, os.Mkdir(cgpath, 0o755))
	t.Cleanup(func() { require.NoError(t, os.Remove(cgpath)) })
	cg, err := os.Open(cgpath)
	require.NoError(t, err)
	t.Cleanup(func() { cg.Close() })
	var st syscall.Stat_t
	require.NoError(t, syscall.Fstat(int(cg.Fd()), &st))
	tmp := t.TempDir()
	good, bad := filepath.Join(tmp, "allowed", "tool"), filepath.Join(tmp, "blocked", "tool")
	exe, err := os.ReadFile("/usr/bin/true")
	require.NoError(t, err)
	for _, path := range []string{good, bad} {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, exe, 0o755))
	}
	policy := func(path string) string {
		return fmt.Sprintf("version: 1\nbinding:\n  container:\n    runtime: containerd\n    id: runtime-test\npolicy:\n  mode: enforce\n  exec:\n    default: deny\n    rules:\n      - name: approved\n        target:\n          path: [%q]\n        action: allow\n", path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	store := memory.New()
	push := func(media string, data []byte) ocispec.Descriptor {
		d := content.NewDescriptorFromBytes(media, data)
		require.NoError(t, store.Push(ctx, d, bytes.NewReader(data)))
		return d
	}
	cfg := push("application/vnd.gadget.config.v1+yaml", metadata)
	layers := []ocispec.Descriptor{push("application/vnd.gadget.ebpf.program.v1+binary", object), push("application/vnd.gadget.wasm.program.v1+binary", wasm)}
	manifest := ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: cfg, Layers: layers}
	raw, err := json.Marshal(manifest)
	require.NoError(t, err)
	desc := push(ocispec.MediaTypeImageManifest, raw)
	desc.Platform = &ocispec.Platform{Architecture: goruntime.GOARCH, OS: "linux"}
	raw, err = json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}})
	require.NoError(t, err)
	desc = push(ocispec.MediaTypeImageIndex, raw)
	const image = "ghcr.io/inspektor-gadget/gadget/enforce_exec:runtime-test"
	require.NoError(t, store.Tag(ctx, desc, image))
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	require.NoError(t, params.Set("verify-image", "false"))
	require.NoError(t, params.Set("allow-enforcement", "true"))
	require.NoError(t, handler.Init(params))
	type observedStatus struct {
		state      string
		generation uint64
	}
	statuses := make(chan observedStatus, 32)
	var containers, updates datasource.DataSource
	emitContainer := func(kind string) error {
		packet, err := containers.NewPacketSingle()
		if err != nil {
			return err
		}
		for key, value := range map[string]string{"event_type": kind, "runtime": "containerd", "container_id": "runtime-test", "cgroup_v2_path": "/" + filepath.Base(cgpath)} {
			if err := containers.GetField(key).PutString(packet, value); err != nil {
				return err
			}
		}
		if err := containers.GetField("cgroup_id").PutUint64(packet, st.Ino); err != nil {
			return err
		}
		return containers.EmitAndRelease(packet)
	}
	target := simple.New("test-target", simple.WithPriority(-1), simple.OnInit(func(gc operators.GadgetContext) error {
		var err error
		containers, err = gc.RegisterDataSource(datasource.TypeSingle, "containers")
		if err != nil {
			return err
		}
		for _, key := range []string{"event_type", "runtime", "container_id", "cgroup_v2_path"} {
			if _, err := containers.AddField(key, api.Kind_String); err != nil {
				return err
			}
		}
		if _, err := containers.AddField("cgroup_id", api.Kind_Uint64); err != nil {
			return err
		}
		status := gc.GetDataSources()["status"]
		if status == nil {
			return fmt.Errorf("guest did not register status datasource")
		}
		updates = gc.GetDataSources()["exec_policy_updates"]
		return status.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
			state, err := status.GetField("state").String(data)
			if err != nil {
				return err
			}
			generation, err := status.GetField("generation").Uint64(data)
			if err != nil {
				return err
			}
			statuses <- observedStatus{state, generation}
			return nil
		}, 0)
	}), simple.OnStart(func(operators.GadgetContext) error { return emitContainer("CREATED") }))
	gc := gadgetcontext.New(ctx, image, gadgetcontext.WithDataOperators(handler, target), gadgetcontext.WithOrasReadonlyTarget(store))
	runtime := local.New()
	require.NoError(t, runtime.Init(nil))
	done := make(chan error, 1)
	go func() {
		done <- runtime.RunGadget(gc, nil, map[string]string{"operator.oci.wasm.exec-policy": policy(filepath.Dir(good) + "/**")})
	}()
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Errorf("runtime shutdown: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("runtime failed to stop")
			}
		}
	})
	await := func(state string, generation uint64) {
		t.Helper()
		for {
			select {
			case got := <-statuses:
				if got.state == state {
					require.Equal(t, generation, got.generation)
					return
				}
				if got.state == "error" {
					t.Fatalf("guest reported error while waiting for %s", state)
				}
			case err := <-done:
				finished = true
				t.Fatalf("runtime ended while waiting for %s: %v", state, err)
			case <-ctx.Done():
				t.Fatalf("waiting for %s: %v", state, ctx.Err())
			}
		}
	}
	execute := func(path string, managed, deny bool) {
		t.Helper()
		cmd := exec.Command(path)
		if managed {
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
		}
		err := cmd.Run()
		if deny {
			require.ErrorIs(t, err, syscall.EPERM)
		} else {
			require.NoError(t, err)
		}
	}
	update := func(raw string, expected uint64) {
		t.Helper()
		packet, err := updates.NewPacketSingle()
		require.NoError(t, err)
		require.NoError(t, updates.GetField("policy").PutString(packet, raw))
		require.NoError(t, updates.GetField("expected_generation").PutUint64(packet, expected))
		require.NoError(t, updates.EmitAndRelease(packet))
	}
	await("enforcing", 1)
	// The enforcing status is emitted during Start. Wait until the full operator
	// lifecycle is ready before exercising the public context update entry point.
	require.Eventually(t, func() bool {
		supported, err := gc.ParameterUpdatesSupported()
		return err == nil && supported
	}, 5*time.Second, time.Millisecond)
	hostUpdate := func(raw string) error {
		return gc.UpdateParameters(ctx, api.ParamValues{"operator.oci.wasm.exec-policy": raw})
	}
	execute(good, true, false)
	execute(bad, true, true)
	execute(bad, false, false)
	require.ErrorContains(t, hostUpdate("invalid: policy"), "rejected")
	await("update-rejected", 1)
	execute(bad, true, true)
	// Binding changes must be rejected through the same public API without
	// restarting the gadget or losing the last accepted policy.
	require.ErrorContains(t, hostUpdate(strings.Replace(policy(bad), "runtime-test", "other-container", 1)), "rejected")
	await("update-rejected", 1)
	execute(bad, true, true)
	require.ErrorContains(t, gc.UpdateParameters(ctx, api.ParamValues{
		"operator.oci.wasm.exec-policy": policy(bad), "runtime.other": "changed",
	}), "outside")
	execute(bad, true, true)
	// Direct datasource submissions retain coverage for stale-generation input;
	// normal daemon reconciliation obtains the expected generation from the host.
	update(policy(bad), 0)
	await("update-rejected", 1)
	execute(bad, true, true)
	require.NoError(t, hostUpdate(policy(bad)))
	await("enforcing", 2)
	execute(bad, true, false)
	execute(good, true, true)
	// Explicit context updates republish even when the desired value is unchanged.
	require.NoError(t, hostUpdate(policy(bad)))
	await("enforcing", 3)
	update(policy(good), 1)
	await("update-rejected", 3)
	execute(good, true, true)
	// A corrected update must still work after the rejected input.
	require.NoError(t, hostUpdate(policy(good)))
	await("enforcing", 4)
	execute(good, true, false)
	execute(bad, true, true)
	require.NoError(t, emitContainer("DELETED"))
	await("target-removed", 4)
	execute(bad, true, false)
	// Rebind before cancellation so shutdown itself must release active enforcement.
	require.NoError(t, emitContainer("CREATED"))
	await("enforcing", 4)
	execute(bad, true, true)
	cancel()
	select {
	case err := <-done:
		finished = true
		if err != nil && !errors.Is(err, context.Canceled) {
			require.NoError(t, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runtime shutdown timed out")
	}
	execute(bad, true, false)
	require.ErrorIs(t, hostUpdate(policy(bad)), context.Canceled)
	t.Log("real OCI/BPF/WASM lifecycle: scope, acknowledged host updates, binding/stale rejection, last-good policy, removal, and shutdown passed")
}
