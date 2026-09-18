// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kfilefields

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// findTwoDistinctFilesOnOverlayfs scans /proc/mounts for an overlay mount
// and returns the paths of two distinct regular files under it. It returns
// ok == false if no overlay mount with at least two regular files could be
// found.
func findTwoDistinctFilesOnOverlayfs(t *testing.T) (a, b string, ok bool) {
	t.Helper()

	f, err := os.Open("/proc/mounts")
	if err != nil {
		t.Skipf("reading /proc/mounts: %v", err)
	}
	defer f.Close()

	var overlayMountpoints []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[2] == "overlay" {
			overlayMountpoints = append(overlayMountpoints, fields[1])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Skipf("scanning /proc/mounts: %v", err)
	}

	for _, mnt := range overlayMountpoints {
		var found []string
		_ = filepath.WalkDir(mnt, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // best-effort scan, skip unreadable entries
			}
			if len(found) >= 2 {
				return filepath.SkipAll
			}
			if d.Type().IsRegular() {
				found = append(found, path)
			}
			return nil
		})
		if len(found) >= 2 {
			return found[0], found[1], true
		}
	}

	return "", "", false
}

// TestReadRealInodeFromFdDistinctOnOverlayfs is a regression test for the
// bug described in
// https://github.com/kubescape/inspektor-gadget/issues/4: on kernels >=
// 6.13, file->private_data for an overlayfs file no longer points directly
// at the underlying struct file, so reading f_inode straight off it
// produced the same bogus "real inode" pointer for every overlay-backed
// file. Two distinct files on an overlay mount must resolve to two
// distinct, non-zero real-inode values.
func TestReadRealInodeFromFdDistinctOnOverlayfs(t *testing.T) {
	utils.RequireRoot(t)

	pathA, pathB, ok := findTwoDistinctFilesOnOverlayfs(t)
	if !ok {
		t.Skip("no overlayfs mount with two distinct regular files found; skipping")
	}

	fdA1, err := os.Open(pathA)
	if err != nil {
		t.Fatalf("opening %q: %v", pathA, err)
	}
	defer fdA1.Close()

	// A second, independent fd for the same underlying file as pathA. The
	// production use case (uprobetracer's per-pid dedup set) relies on this
	// resolving to the *same* real inode as fdA1 -- that is the actual
	// invariant the bug broke, more directly than mere cross-file
	// distinctness: on kernels >= 6.13 the old code returned a value read
	// from out-of-bounds memory near the ovl_file wrapper, so a repeat call
	// close in time on the same file, or a different file, could equally
	// well not match.
	fdA2, err := os.Open(pathA)
	if err != nil {
		t.Fatalf("opening %q a second time: %v", pathA, err)
	}
	defer fdA2.Close()

	fdB, err := os.Open(pathB)
	if err != nil {
		t.Fatalf("opening %q: %v", pathB, err)
	}
	defer fdB.Close()

	realInodeA1, err := ReadRealInodeFromFd(int(fdA1.Fd()))
	if err != nil {
		t.Fatalf("ReadRealInodeFromFd(%q): %v", pathA, err)
	}
	realInodeA2, err := ReadRealInodeFromFd(int(fdA2.Fd()))
	if err != nil {
		t.Fatalf("ReadRealInodeFromFd(%q) (2nd fd): %v", pathA, err)
	}
	realInodeB, err := ReadRealInodeFromFd(int(fdB.Fd()))
	if err != nil {
		t.Fatalf("ReadRealInodeFromFd(%q): %v", pathB, err)
	}

	if realInodeA1 == 0 {
		t.Fatalf("real inode for %q resolved to 0", pathA)
	}
	if realInodeB == 0 {
		t.Fatalf("real inode for %q resolved to 0", pathB)
	}
	if realInodeA1 != realInodeA2 {
		t.Fatalf("two fds for the same overlayfs file %q resolved to different real inodes "+
			"(0x%x vs 0x%x); this breaks uprobetracer's dedup identity", pathA, realInodeA1, realInodeA2)
	}
	if realInodeA1 == realInodeB {
		t.Fatalf("distinct overlayfs files %q and %q resolved to the same real inode 0x%x; "+
			"this is the dedup-poisoning bug from issue #4", pathA, pathB, realInodeA1)
	}
}
