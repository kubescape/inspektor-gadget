// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpaqueExecCapsuleContract drives the default-off source-only
// physical-exec capsule (full/shared_exec_capsule.h) through the actual
// shared_route.h helpers. It is the original-class replacement for the
// current-route fallback that TestOpaqueSourceModeHeaderlessMigrationContract
// keeps as a deliberate counterexample. Kernel serialization and hook
// coverage are proved separately on the exact AL2023 kernels.
func TestOpaqueExecCapsuleContract(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	scenarios := []string{
		"same-scope", "headerless-migrated", "fresh-control",
		"losing-waiter", "nonleader-dethread",
		"wrong-duplicate-terminal", "stale-reuse", "check-only",
		"late-attach", "unselected-first", "fault-first",
		"sequence-exhausted", "out-of-range", "busy-capsule-degrades",
		"check-frozen-never-success", "tampered-owner-or-route",
		"pin-failed", "stale-then-exhausted", "terminal-and-entry-skipped",
		"legacy-fallback-is-unsafe",
	}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "exec-capsule")
			args := []string{"-std=gnu11", optimization, "-Wall", "-Wextra",
				"-Werror", "-iquote", "../full", "-iquote",
				"../fullpolicy/bpf",
				"testdata/opaque_exec_capsule_contract.c", "-o", binary}
			if out, err := exec.CommandContext(t.Context(), cc, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile capsule fixture: %v\n%s", err, out)
			}
			for _, mode := range []string{"audit", "strict"} {
				for _, scenario := range scenarios {
					t.Run(mode+"/"+scenario, func(t *testing.T) {
						out, err := exec.CommandContext(t.Context(), binary,
							scenario, mode).CombinedOutput()
						if err != nil {
							t.Fatalf("capsule contract: %v\n%s", err, out)
						}
						want := scenario + "/" + mode + ": PASS"
						if !strings.Contains(string(out), want) {
							t.Fatalf("scenario did not run: %q", out)
						}
					})
				}
			}
		})
	}
}

// TestOpaqueExecCapsuleRequiresSourcePin keeps the capsule unusable without
// the explicit source-pin route candidate.
func TestOpaqueExecCapsuleRequiresSourcePin(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "nopin.c")
	if err := os.WriteFile(src, []byte("#include <linux/bpf.h>\n#include \"shared_exec_capsule.h\"\nint main(void){return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), cc, "-std=gnu11", "-fsyntax-only",
		"-iquote", "../full", "-iquote", "../fullpolicy/bpf", src).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "requires the source-mode route pin candidate") {
		t.Fatalf("capsule compiled without the source-pin candidate: %v\n%s", err, out)
	}
}
