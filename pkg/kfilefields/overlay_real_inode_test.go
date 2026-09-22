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

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// findTwoDistinctFilesOnOverlayfs scans /proc/mounts for an overlay mount
// and returns open descriptors for two distinct regular files on it. It returns
// ok == false if no overlay mount with at least two regular files could be
// found.
func findTwoDistinctFilesOnOverlayfs(t *testing.T) (a, b *os.File, ok bool) {
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
		if a, b, ok := findTwoDistinctFilesOnFilesystem(mnt, unix.OVERLAYFS_SUPER_MAGIC); ok {
			return a, b, true
		}
	}

	return nil, nil, false
}

func findTwoDistinctFilesOnFilesystem(root string, fsType int64) (a, b *os.File, ok bool) {
	var firstInfo os.FileInfo
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil //nolint:nilerr // best-effort scan, skip unreadable entries
		}
		f, err := os.Open(path)
		if err != nil {
			return nil //nolint:nilerr // skip files we cannot open
		}
		keep := false
		defer func() {
			if !keep {
				f.Close()
			}
		}()
		// Check the opened file: WalkDir can cross into nested mounts, and
		// overlay files need not have the same st_dev as their mountpoint.
		var statfs unix.Statfs_t
		if err := unix.Fstatfs(int(f.Fd()), &statfs); err != nil || int64(statfs.Type) != fsType {
			return nil //nolint:nilerr // skip files outside the requested filesystem type
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return nil //nolint:nilerr // the file may have changed during traversal
		}
		if a == nil {
			a, firstInfo, keep = f, info, true
			return nil
		}
		if os.SameFile(firstInfo, info) {
			return nil
		}
		b, keep = f, true
		return filepath.SkipAll
	})
	if b != nil {
		return a, b, true
	}
	if a != nil {
		a.Close()
	}
	return nil, nil, false
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

	fdA1, fdB, ok := findTwoDistinctFilesOnOverlayfs(t)
	if !ok {
		t.Skip("no overlayfs mount with two distinct regular files found; skipping")
	}

	defer fdA1.Close()
	defer fdB.Close()
	pathA, pathB := fdA1.Name(), fdB.Name()

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

func TestFindTwoDistinctFilesOnFilesystem(t *testing.T) {
	root := t.TempDir()
	pathA := filepath.Join(root, "a")
	pathB := filepath.Join(root, "b-hardlink")
	pathC := filepath.Join(root, "c")
	if err := os.WriteFile(pathA, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(pathA, pathB); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathC, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	var statfs unix.Statfs_t
	if err := unix.Statfs(root, &statfs); err != nil {
		t.Fatal(err)
	}

	t.Run("skips hardlinks", func(t *testing.T) {
		a, b, ok := findTwoDistinctFilesOnFilesystem(root, int64(statfs.Type))
		if !ok {
			t.Fatal("expected two distinct files")
		}
		defer a.Close()
		defer b.Close()
		if a.Name() != pathA || b.Name() != pathC {
			t.Fatalf("selected %q and %q; want %q and %q", a.Name(), b.Name(), pathA, pathC)
		}
	})

	t.Run("rejects other filesystem types", func(t *testing.T) {
		a, b, ok := findTwoDistinctFilesOnFilesystem(root, -1)
		if a != nil {
			defer a.Close()
		}
		if b != nil {
			defer b.Close()
		}
		if ok || a != nil || b != nil {
			t.Fatal("selected files from the wrong filesystem type")
		}
	})

	t.Run("hardlinks alone are not a pair", func(t *testing.T) {
		if err := os.Remove(pathC); err != nil {
			t.Fatal(err)
		}
		a, b, ok := findTwoDistinctFilesOnFilesystem(root, int64(statfs.Type))
		if a != nil {
			defer a.Close()
		}
		if b != nil {
			defer b.Close()
		}
		if ok || a != nil || b != nil {
			t.Fatal("selected hardlinks as distinct files")
		}
	})
}
