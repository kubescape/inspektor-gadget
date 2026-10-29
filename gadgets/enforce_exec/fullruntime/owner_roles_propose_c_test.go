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

// Compile the actual proposal and completion functions with deterministic storage/helper stubs.
// This tests fault scope, not BPF verifier or real task-storage synchronization.
func TestOwnerRoleProposalAndCompletionFaultScope(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	header, err := os.ReadFile("../full/owner_roles.h")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(header), "static __always_inline int eo_exec_propose(")
	end := strings.Index(string(header), "/* Completion always")
	if start < 0 || end <= start {
		t.Fatal("proposal function boundary missing")
	}
	driver, err := os.ReadFile("testdata/owner_roles_propose.c")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(driver), "/* ACTUAL_PROPOSAL */", string(header[start:end]), 1)
	fillStart := strings.Index(string(header), "static __always_inline int eo_fill_roles(")
	if fillStart < 0 || fillStart >= start {
		t.Fatal("role fact function missing")
	}
	source = strings.Replace(source, "/* ACTUAL_ROLE_FACTS */", string(header[fillStart:start]), 1)
	finishEnd := strings.Index(string(header), "static __always_inline __u64 eo_task_cgroup")
	if finishEnd <= end {
		t.Fatal("completion function boundary missing")
	}
	source = strings.Replace(source, "/* ACTUAL_COMPLETION */", string(header[end:finishEnd]), 1)
	dir := t.TempDir()
	file := filepath.Join(dir, "proposal.c")
	binary := filepath.Join(dir, "proposal")
	if err = os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	for _, development := range []bool{false, true} {
		args := []string{"-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "-iquote", filepath.Join(root, "../fullpolicy/bpf")}
		if development {
			args = append(args, "-DENFORCE_EXEC_ABI3_DEVELOPMENT=1")
		}
		args = append(args, file, "-o", binary)
		if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
			t.Fatalf("compile development=%v: %v\n%s", development, err, out)
		}
		if out, err := exec.Command(binary).CombinedOutput(); err != nil {
			t.Fatalf("proposal scope development=%v: %v\n%s", development, err, out)
		}
	}
}
