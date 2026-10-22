// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/processlaunch"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// TestExecLaunchRuntime binds the actual guest through the launch capability,
// then releases its private barrier only after the entire gadget has started.
// Deny must prevent the application's very first exec, including its side effect.
func TestExecLaunchRuntime(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" {
		t.Skip("requires disposable BPF LSM host and IG_EXEC_KERNEL_TEST=1")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	read := func(name string) []byte {
		t.Helper()
		p := os.Getenv(name)
		require.NotEmpty(t, p)
		b, e := os.ReadFile(p)
		require.NoError(t, e)
		return b
	}
	store := memory.New()
	push := func(media string, data []byte) ocispec.Descriptor {
		t.Helper()
		d := content.NewDescriptorFromBytes(media, data)
		require.NoError(t, store.Push(ctx, d, bytes.NewReader(data)))
		return d
	}
	cfg := push("application/vnd.gadget.config.v1+yaml", read("IG_EXEC_METADATA"))
	layers := []ocispec.Descriptor{push("application/vnd.gadget.ebpf.program.v1+binary", read("IG_EXEC_BPF_OBJECT")), push("application/vnd.gadget.wasm.program.v1+binary", read("IG_EXEC_WASM"))}
	raw, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: cfg, Layers: layers})
	require.NoError(t, err)
	desc := push(ocispec.MediaTypeImageManifest, raw)
	desc.Platform = &ocispec.Platform{Architecture: goruntime.GOARCH, OS: "linux"}
	raw, err = json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}})
	require.NoError(t, err)
	desc = push(ocispec.MediaTypeImageIndex, raw)
	const image = "ghcr.io/inspektor-gadget/gadget/enforce_exec:launch-test"
	require.NoError(t, store.Tag(ctx, desc, image))
	runtime := local.New()
	require.NoError(t, runtime.Init(nil))
	defer runtime.Close()
	for _, scenario := range []string{"allow", "deny", "unregistered"} {
		t.Run(scenario, func(t *testing.T) {
			action := scenario
			if scenario == "unregistered" {
				action = "allow"
			}
			instanceCtx, stop := context.WithCancel(ctx)
			defer stop()
			marker := filepath.Join(t.TempDir(), "application-started")
			var stderr bytes.Buffer
			child, err := processlaunch.Start(instanceCtx, []string{"/bin/sh", "-c", `printf '%s' "$$" > "$1"`, "application", marker}, processlaunch.Options{Stderr: &stderr})
			require.NoError(t, err)
			defer child.Close()
			id := child.Identity()
			policy, err := execpolicy.ParseLaunch(strings.NewReader(fmt.Sprintf("version: 1\npolicy:\n  mode: enforce\n  exec:\n    default: %s\n", action)), execpolicy.DefaultLimits(), execpolicy.Process{Node: id.Node, BootID: id.BootID, HostPID: int(id.PID), StartTimeTicks: id.StartTimeTicks})
			require.NoError(t, err)
			encoded, err := yaml.Marshal(policy)
			require.NoError(t, err)
			handler := ocihandler.New()
			params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
			require.NoError(t, params.Set("verify-image", "false"))
			require.NoError(t, params.Set("allow-enforcement", "true"))
			require.NoError(t, handler.Init(params))
			released := make(chan struct{})
			launchCtx := instanceCtx
			if scenario != "unregistered" {
				launchCtx = child.Context(instanceCtx)
			}
			gc := gadgetcontext.New(launchCtx, image, gadgetcontext.WithDataOperators(handler), gadgetcontext.WithOrasReadonlyTarget(store), gadgetcontext.WithOnStarted(func() error {
				err := child.Release()
				if err == nil {
					close(released)
				}
				return err
			}))
			done := make(chan error, 1)
			go func() {
				done <- runtime.RunGadget(gc, nil, map[string]string{"operator.oci.wasm.exec-policy": string(encoded)})
			}()
			defer func() {
				stop()
				select {
				case err := <-done:
					if scenario == "unregistered" {
						require.Error(t, err)
					} else {
						require.NoError(t, err)
					}
				case <-time.After(10 * time.Second):
					t.Error("gadget shutdown timed out")
				}
			}()
			select {
			case <-released:
				require.NotEqual(t, "unregistered", scenario, "released process without launch capability")
			case err := <-done:
				done <- err
				if scenario == "unregistered" {
					require.Error(t, err)
					require.Error(t, child.Release(), "unregistered process must remain unbound")
					_, statErr := os.Stat(marker)
					require.True(t, os.IsNotExist(statErr))
					return
				}
				t.Fatalf("runtime failed before release: %v", err)
			case <-instanceCtx.Done():
				t.Fatal(instanceCtx.Err())
			}
			err = child.Wait()
			if action == "allow" {
				require.NoError(t, err, stderr.String())
				b, e := os.ReadFile(marker)
				require.NoError(t, e)
				require.Equal(t, fmt.Sprint(id.PID), string(b), "application must replace registered child")
			} else {
				require.Error(t, err)
				_, e := os.Stat(marker)
				require.True(t, os.IsNotExist(e), "denied initial exec ran application: %v", e)
			}
		})
	}
}
