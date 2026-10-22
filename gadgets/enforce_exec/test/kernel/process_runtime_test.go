// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
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
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/processlaunch"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// TestExecProcessFailureRuntime exercises launcher binding and guest updates,
// with allocation failure injected only in the BPF test object. No test switch
// is present in the production gadget.
func TestExecProcessFailureRuntime(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" {
		t.Skip("requires disposable BPF LSM host and IG_EXEC_KERNEL_TEST=1")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	readArtifact := func(name string) []byte {
		t.Helper()
		p := os.Getenv(name)
		require.NotEmpty(t, p, name)
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		return b
	}
	object := readArtifact("IG_EXEC_PROCESS_FAILURE_OBJECT")
	wasm, metadata := readArtifact("IG_EXEC_WASM"), readArtifact("IG_EXEC_METADATA")
	tmp := t.TempDir()
	helper, source := filepath.Join(tmp, "helper"), filepath.Join(tmp, "helper.c")
	require.NoError(t, os.WriteFile(source, []byte(processHelperSource), 0o600))
	out, err := exec.Command("clang", "-Wall", "-Werror", "-pthread", "-O2", source, "-o", helper).CombinedOutput()
	require.NoError(t, err, string(out))
	for _, initialMode := range []string{"audit", "off"} {
		t.Run(initialMode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			var policy func(string) string
			var read func(string)
			var send func(string, string)
			var ready string
			store := memory.New()
			push := func(media string, data []byte) ocispec.Descriptor {
				d := content.NewDescriptorFromBytes(media, data)
				require.NoError(t, store.Push(ctx, d, bytes.NewReader(data)))
				return d
			}
			cfg := push("application/vnd.gadget.config.v1+yaml", metadata)
			layers := []ocispec.Descriptor{push("application/vnd.gadget.ebpf.program.v1+binary", object), push("application/vnd.gadget.wasm.program.v1+binary", wasm)}
			raw, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: cfg, Layers: layers})
			require.NoError(t, err)
			desc := push(ocispec.MediaTypeImageManifest, raw)
			desc.Platform = &ocispec.Platform{Architecture: goruntime.GOARCH, OS: "linux"}
			raw, err = json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}})
			require.NoError(t, err)
			desc = push(ocispec.MediaTypeImageIndex, raw)
			const image = "ghcr.io/inspektor-gadget/gadget/enforce_exec:process-failure-test"
			require.NoError(t, store.Tag(ctx, desc, image))
			type observed struct {
				state                          string
				generation, failures, degraded uint64
			}
			start := func(mode string) (*gadgetcontext.GadgetContext, func(string, uint64) observed, func()) {
				instanceCtx, stop := context.WithCancel(ctx)
				t.Cleanup(stop)
				stdin, input, err := os.Pipe()
				require.NoError(t, err)
				t.Cleanup(func() { stdin.Close(); input.Close() })
				output, stdout, err := os.Pipe()
				require.NoError(t, err)
				t.Cleanup(func() { output.Close(); stdout.Close() })
				child, err := processlaunch.Start(instanceCtx, []string{helper, "/usr/bin/true"}, processlaunch.Options{Stdin: stdin, Stdout: stdout, Stderr: os.Stderr})
				require.NoError(t, err)
				t.Cleanup(func() { child.Close() })
				stdin.Close()
				stdout.Close()
				id := child.Identity()
				ready = fmt.Sprintf("READY %d", id.PID)
				scanner := bufio.NewScanner(output)
				read = func(want string) {
					t.Helper()
					require.True(t, scanner.Scan(), "expected %s; scan error: %v", want, scanner.Err())
					require.Equal(t, want, scanner.Text())
				}
				send = func(command, want string) {
					t.Helper()
					_, err := input.Write([]byte(command))
					require.NoError(t, err)
					read(want)
				}
				policy = func(mode string) string {
					return fmt.Sprintf("version: 1\nbinding:\n  process:\n    node: %q\n    bootID: %q\n    hostPID: %d\n    startTimeTicks: %d\npolicy:\n  mode: %s\n  exec:\n    default: deny\n    rules:\n      - name: helper\n        target:\n          path: [%q]\n        action: allow\n", id.Node, id.BootID, id.PID, id.StartTimeTicks, mode, helper)
				}

				handler := ocihandler.New()
				params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
				require.NoError(t, params.Set("verify-image", "false"))
				require.NoError(t, params.Set("allow-enforcement", "true"))
				require.NoError(t, handler.Init(params))
				statuses := make(chan observed, 32)
				observer := simple.New("observe-process-health", simple.WithPriority(-1), simple.OnInit(func(gc operators.GadgetContext) error {
					status := gc.GetDataSources()["status"]
					if status == nil {
						return fmt.Errorf("missing status datasource")
					}
					return status.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
						state, err := status.GetField("state").String(data)
						if err != nil {
							return err
						}
						gen, err := status.GetField("generation").Uint64(data)
						if err != nil {
							return err
						}
						failures, err := status.GetField("tracking_failures").Uint64(data)
						if err != nil {
							return err
						}
						degraded, err := status.GetField("tracking_degraded").Uint64(data)
						if err != nil {
							return err
						}
						statuses <- observed{state, gen, failures, degraded}
						return nil
					}, 0)
				}))
				gc := gadgetcontext.New(child.Context(instanceCtx), image, gadgetcontext.WithDataOperators(handler, observer), gadgetcontext.WithOrasReadonlyTarget(store), gadgetcontext.WithOnStarted(child.Release))
				runtime := local.New()
				require.NoError(t, runtime.Init(nil))
				t.Cleanup(func() { runtime.Close() })
				done := make(chan error, 1)
				go func() {
					done <- runtime.RunGadget(gc, nil, map[string]string{"operator.oci.wasm.exec-policy": policy(mode)})
				}()
				finished := false
				shutdown := func() {
					t.Helper()
					stop()
					child.Close()
					if finished {
						return
					}
					select {
					case err := <-done:
						finished = true
						if err != nil && !errors.Is(err, context.Canceled) {
							t.Errorf("runtime shutdown: %v", err)
						}
					case <-time.After(10 * time.Second):
						t.Error("runtime shutdown timeout")
					}
				}
				t.Cleanup(shutdown)
				await := func(state string, generation uint64) observed {
					t.Helper()
					for {
						select {
						case got := <-statuses:
							if got.state == state {
								require.Equal(t, generation, got.generation)
								return got
							}
							require.NotEqual(t, "error", got.state, "guest reported error")
						case err := <-done:
							finished = true
							t.Fatalf("runtime ended waiting for %s: %v", state, err)
						case <-instanceCtx.Done():
							t.Fatalf("waiting for %s: %v", state, instanceCtx.Err())
						}
					}
				}
				return gc, await, shutdown
			}
			gc, await, stop := start(initialMode)
			state := map[string]string{"audit": "auditing", "off": "off"}[initialMode]
			got := await(state, 1)
			read(ready)
			require.Zero(t, got.failures)
			require.Zero(t, got.degraded)
			require.Eventually(t, func() bool { ok, err := gc.ParameterUpdatesSupported(); return err == nil && ok }, 5*time.Second, time.Millisecond)
			send("t", ready) // Forced marker allocation failure must not deny audit/off exec.
			update := func(mode string) error {
				return gc.UpdateParameters(ctx, api.ParamValues{"operator.oci.wasm.exec-policy": policy(mode)})
			}
			require.NoError(t, update(initialMode))
			got = await(state, 2)
			require.Equal(t, uint64(1), got.failures)
			require.Equal(t, uint64(1), got.degraded)
			require.ErrorContains(t, update("enforce"), "rejected")
			got = await("update-rejected", 2)
			require.Equal(t, uint64(1), got.degraded)
			stop()
			// Enforcing again requires a fresh launch; an already running process
			// cannot be rebound after tracking continuity was lost.
			gc, await, stop = start("enforce")
			got = await("enforcing", 1)
			read(ready)
			require.Zero(t, got.failures)
			require.Zero(t, got.degraded)
			send("d", "DENIED")
			send("e", ready)
			send("d", "DENIED")
			stop()
		})
	}
}
