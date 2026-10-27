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

// Compile the actual proposal function with deterministic storage/helper stubs.
// This tests fault scope, not BPF verifier or real task-storage synchronization.
func TestOwnerRoleProposalFaultScope(t *testing.T) {
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
	dir := t.TempDir()
	file := filepath.Join(dir, "proposal.c")
	binary := filepath.Join(dir, "proposal")
	if err = os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", file, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("proposal scope: %v\n%s", err, out)
	}
}
