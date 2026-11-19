// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package restartfence

import (
	"os"
	"testing"
)

func TestRefuseUnverifiedCgroupID(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	for _, f := range []*os.File{nil, dir} {
		if _, err := PodCgroupID(f); err == nil {
			t.Fatalf("accepted unverified host pod cgroup %v", f)
		}
	}
	if !unifiedCgroupEntry("0::/system.slice/service\n") || !unifiedCgroupEntry("0::/\n") {
		t.Fatal("refused unified host membership")
	}
	for _, bad := range []string{"", "5:cpu:/", "0::/\n5:cpu:/legacy\n", "0::bogus"} {
		if unifiedCgroupEntry(bad) {
			t.Fatalf("accepted unsupported hierarchy %q", bad)
		}
	}
}
