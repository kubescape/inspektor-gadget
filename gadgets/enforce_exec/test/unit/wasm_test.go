// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package unit_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"gopkg.in/yaml.v3"
)

// TestWasmPreStart compiles the actual gadget and invokes its exported lifecycle
// hook using the IG parameter/log ABI. It substitutes host services only; policy
// parsing and kernel compilation execute inside the real WASM guest.
func TestWasmPreStart(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(t.TempDir(), "program.wasm")
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", artifact, ".")
	cmd.Dir = filepath.Join(root, "go")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build actual gadget: %v\n%s", err, out)
	}
	wasm, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(filepath.Join(root, "examples", "enforce.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := os.ReadFile(filepath.Join(root, "gadget.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var md struct {
		Params map[string]map[string]struct {
			Key       string `yaml:"key"`
			Mandatory bool   `yaml:"isMandatory"`
		} `yaml:"params"`
	}
	if err := yaml.Unmarshal(metadata, &md); err != nil {
		t.Fatal(err)
	}
	param := md.Params["wasm"]["exec-policy"]
	if param.Key != "exec-policy" || !param.Mandatory {
		t.Fatal("metadata must declare the guest parameter")
	}
	t.Run("lifecycle", func(t *testing.T) { runLifecycle(t, wasm, policy) })
	processPolicy, err := os.ReadFile(filepath.Join(root, "examples", "process.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"enforce", "audit", "off"} {
		t.Run("process-lifecycle-"+mode, func(t *testing.T) {
			runLifecycle(t, wasm, []byte(strings.Replace(string(processPolicy), "mode: enforce", "mode: "+mode, 1)))
		})
	}
	t.Run("IG-local-runtime", func(t *testing.T) { runThroughIG(t, wasm, metadata, policy) })

	for _, tc := range []struct {
		name, raw, want string
		missing         bool
		wantResult      uint64
	}{
		{"valid", string(policy), "validated policy", false, 0},
		{"audit", strings.Replace(string(policy), "mode: enforce", "mode: audit", 1), "validated policy", false, 0},
		{"off", strings.Replace(string(policy), "mode: enforce", "mode: off", 1), "validated policy", false, 0},
		{"unknown predicate", strings.Replace(string(policy), "target:", "target:\n          fromImage: true", 1), "invalid policy", false, 1},
		{"invalid", "version: 100", "invalid policy", false, 1},
		{"oversize", strings.Repeat("x", 65538), "reading exec-policy", false, 1},
		{"missing", "", "reading exec-policy", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			var logs []string
			read := func(m api.Module, v uint64) string {
				data, ok := m.Memory().Read(uint32(v), uint32(v>>32))
				if !ok {
					panic("invalid guest string")
				}
				return string(data)
			}
			host := rt.NewHostModuleBuilder("ig")
			seen := map[string]bool{}
			for _, fn := range compiled.ImportedFunctions() {
				module, name, _ := fn.Import()
				if module != "ig" || seen[name] {
					continue
				}
				seen[name] = true
				host.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
					switch name {
					case "getParamValue":
						key, dst := read(m, stack[0]), stack[1]
						if key != "exec-policy" || tc.missing || len(tc.raw)+1 > int(dst>>32) {
							stack[0] = 1
							return
						}
						if !m.Memory().Write(uint32(dst), append([]byte(tc.raw), 0)) {
							panic("invalid destination")
						}
						stack[0] = 0
					case "gadgetShouldLog":
						stack[0] = 1
					case "gadgetLog":
						logs = append(logs, read(m, stack[1]))
					default:
						panic(fmt.Sprintf("unexpected host call %s", name))
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
			hook := guest.ExportedFunction("gadgetPreStart")
			if hook == nil {
				t.Fatal("missing gadgetPreStart export")
			}
			result, err := hook.Call(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(result) != 1 || result[0] != tc.wantResult {
				t.Fatalf("pre-start result = %v, want %d", result, tc.wantResult)
			}
			if !strings.Contains(strings.Join(logs, "\n"), tc.want) {
				t.Fatalf("expected %q, logs %v", tc.want, logs)
			}
		})
	}
}
