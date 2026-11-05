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

func TestSharedControlRejectsMalformedCompiledProfile(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("testdata/shared_control.c")
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range map[string][2]string{"negative-compensated": {"5", "-1"}, "oversized-compensated": {"4294967296ULL", "-1073741824LL"}} {
		t.Run(name, func(t *testing.T) {
			code := strings.Replace(string(source), "#define SE_PROFILE_SLOTS_256 2", "#define SE_PROFILE_SLOTS_256 "+values[0], 1)
			code = strings.Replace(code, "#define SE_PROFILE_SLOTS_1024 0", "#define SE_PROFILE_SLOTS_1024 "+values[1], 1)
			dir := t.TempDir()
			file := filepath.Join(dir, "profile.c")
			if err := os.WriteFile(file, []byte(code), 0o600); err != nil {
				t.Fatal(err)
			}
			// This test requires a hard language-level assertion, not a warning that
			// disappears when a downstream build does not enable -Werror.
			out, err := exec.Command(cc, "-std=gnu11", "-O2", "-iquote", root, "-c", file, "-o", filepath.Join(dir, "profile.o")).CombinedOutput()
			if err == nil {
				t.Fatal("malformed image geometry compiled")
			}
			if !strings.Contains(string(out), "slot count domain") {
				t.Fatalf("wrong refusal: %s", out)
			}
		})
	}
}
