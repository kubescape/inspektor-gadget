// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import "testing"

func TestCompileKernelProcessBinding(t *testing.T) {
	container := document(t)
	process := container
	process.Binding = Binding{Process: &Process{Node: "node-a", BootID: "boot-a", HostPID: 42, StartTimeTicks: 100}}
	// Target resolution is a host responsibility. Compiling identical rules for
	// a process must preserve the exact policy generation and path semantics.
	want, err := CompileKernel(container, 7)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CompileKernel(process, 7)
	if err != nil {
		t.Fatalf("valid process binding rejected: %v", err)
	}
	if got != want {
		t.Fatal("process binding changed compiled policy rules")
	}
	process.Binding.Process.StartTimeTicks = 0
	invalid, err := CompileKernel(process, 7)
	if err == nil {
		t.Fatal("incomplete process identity accepted")
	}
	if invalid != ([KernelMaxRules + 1]KernelEntry{}) {
		t.Fatal("invalid identity returned partial generation")
	}
}
