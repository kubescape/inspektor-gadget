// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

func TestLaunchArguments(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		valid bool
	}{
		{"valid", []string{"image", "--policy", "policy.yaml", "--", "/bin/true"}, true},
		{"application flags", []string{"image", "--policy", "policy.yaml", "--", "app", "--help"}, true},
		{"missing separator", []string{"image", "--policy", "policy.yaml", "app"}, false},
		{"missing command", []string{"image", "--policy", "policy.yaml", "--"}, false},
		{"missing image", []string{"--policy", "policy.yaml", "--", "app"}, false},
		{"two images", []string{"image", "other", "--policy", "policy.yaml", "--", "app"}, false},
		{"missing policy", []string{"image", "--", "app"}, false},
		{"zero timeout", []string{"image", "--policy", "policy.yaml", "--startup-timeout=0", "--", "app"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newLaunchCommand(local.New())
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			err := cmd.Args(cmd, cmd.Flags().Args())
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}

func TestLaunchRejectsInvalidPolicyBeforeRuntime(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(file, []byte("version: 1\nbinding: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newLaunchCommand(local.New())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"image", "--policy", file, "--", "/bin/true"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "field binding not found") {
		t.Fatalf("expected strict parser rejection before root/runtime initialization, got %v", err)
	}
}

func TestLaunchParamValues(t *testing.T) {
	p := params.ParamDescs{{Key: "verify-image", DefaultValue: "true"}}.ToParams()
	values := launchParamValues("policy", p)
	if values["operator.oci.wasm.exec-policy"] != "policy" {
		t.Fatalf("missing WASM policy parameter: %v", values)
	}
	if values["operator.oci.verify-image"] != "true" {
		t.Fatalf("lost OCI instance parameter: %v", values)
	}
	if _, ok := values["exec-policy"]; ok {
		t.Fatal("unnamespaced gadget policy parameter")
	}
}

func TestLaunchDoesNotRequireContainerDiscovery(t *testing.T) {
	// main registers OCI before constructing local commands.
	operators.RegisterDataOperator(ocihandler.OciHandler)
	cmd := newLaunchCommand(local.New())
	if cmd.Flags().Lookup("runtimes") != nil || cmd.PersistentFlags().Lookup("runtimes") != nil {
		t.Fatal("process launch unexpectedly includes container discovery")
	}
	for _, key := range []string{"allow-enforcement", "verify-image", "allowed-gadgets"} {
		if cmd.PersistentFlags().Lookup(key) == nil {
			t.Fatalf("missing host admission setting %s", key)
		}
	}
}
