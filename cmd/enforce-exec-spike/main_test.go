// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommand(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")
	policy := `version: 1
binding:
  container: {runtime: containerd, id: demo}
policy:
  mode: enforce
  exec:
    default: deny
    rules:
      - name: approved
        action: allow
        target: {path: ["/usr/bin/**"]}
`
	if err := os.WriteFile(file, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	if err := run([]string{"--policy-file", file, "/usr/bin/tool", "/tmp/tool"}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"wouldBlock":true`, `"verdict":"allow"`, `"enforced":false`, `"type":"removed-state"`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s in %s", want, out.String())
		}
	}
	if !strings.Contains(diagnostics.String(), "SIMULATION ONLY") {
		t.Fatal("missing simulation notice")
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 100"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"--policy-file", file, "--replace-policy-file", bad}, &out, &diagnostics); err == nil {
		t.Fatal("bad replacement accepted")
	}
	if !strings.Contains(out.String(), `"type":"retained-state","value":{"backend":"memory-simulation","enforcement":false,"active":true,"generation":1`) {
		t.Fatalf("last good policy not reported: %s", out.String())
	}
}
