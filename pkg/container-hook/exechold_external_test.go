// Copyright 2024 The Inspektor Gadget authors
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

//go:build linux
// +build linux

package containerhook

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// stageExternalCandidate creates a directory holding a regular file named
// basename and returns that file's absolute path.
//
// The directory is made directly under "/" rather than with t.TempDir() because
// MarkExecHoldCandidate resolves the candidate under /proc/<pid>/root, and the
// only pid a test can hand it is its own — whose root IS "/". The st_dev control
// then compares the candidate's device against "/", so the staged file has to
// live on the root filesystem; t.TempDir() usually lands on a tmpfs and would
// be refused for that reason alone.
func stageExternalCandidate(t *testing.T, basename string) string {
	t.Helper()

	dir, err := os.MkdirTemp("/", "ig-exechold-external-")
	if err != nil {
		t.Skipf("cannot stage a candidate on the root filesystem: %s", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	path := filepath.Join(dir, basename)
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	return path
}

// TestMarkExecHoldCandidateMarksRootfsBinary is the positive end-to-end case
// for the external entry point: a caller that watched a container write an
// allowlisted binary asks for it to be marked, and a FAN_OPEN_EXEC_PERM mark
// lands on that exact inode — without the binary ever having been exec'd, which
// is the whole point of the entry point existing.
func TestMarkExecHoldCandidateMarksRootfsBinary(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})
	const mntnsID = uint64(4242)

	binPath := stageExternalCandidate(t, "allowed")
	var binStat unix.Stat_t
	require.NoError(t, unix.Stat(binPath, &binStat))

	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd), "group must start with no marks")

	result := n.MarkExecHoldCandidate(mntnsID, uint32(os.Getpid()), binPath)
	require.Equal(t, ExecHoldMarkInstalled, result)
	require.Contains(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd), binStat.Ino,
		"a FAN_OPEN_EXEC_PERM mark must be installed on the requested binary")

	// The per-(container, basename) bookkeeping is shared with the first-exec
	// path, so a second external request for the same basename is absorbed
	// rather than paying for the resolution again.
	require.Equal(t, ExecHoldMarkNotInstalled,
		n.MarkExecHoldCandidate(mntnsID, uint32(os.Getpid()), binPath))
}

// TestMarkExecHoldCandidateNotAllowlisted asserts the cheap no-op: a path whose
// basename is not on the notifier's allowlist is rejected before anything is
// opened or marked. A caller feeding this entry point from a file-open stream
// takes that path for nearly every call, so it must cost a slice scan and
// leave no trace.
func TestMarkExecHoldCandidateNotAllowlisted(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})

	binPath := stageExternalCandidate(t, "notallowed")

	require.Equal(t, ExecHoldMarkNotAllowlisted,
		n.MarkExecHoldCandidate(4242, uint32(os.Getpid()), binPath))
	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd),
		"a basename outside the allowlist must not reach the marking path at all")
}

// TestMarkExecHoldCandidateNotApplicable covers the outcomes an external caller
// racing container lifecycle must be able to tell apart from a real failure:
// exec-hold was never enabled, and the container is no longer there.
func TestMarkExecHoldCandidateNotApplicable(t *testing.T) {
	t.Run("exec-hold disabled", func(t *testing.T) {
		// No root needed: nothing is opened on this path.
		n := &ContainerNotifier{}
		require.Equal(t, ExecHoldMarkNotApplicable,
			n.MarkExecHoldCandidate(4242, uint32(os.Getpid()), "/usr/bin/allowed"))
	})

	t.Run("container gone", func(t *testing.T) {
		n := newExecHoldTestNotifier(t, []string{"allowed"})
		binPath := stageExternalCandidate(t, "allowed")

		// A pid that has already been reaped: /proc/<pid>/root is gone, which is
		// exactly what a container that exited between the caller observing the
		// write and calling here looks like.
		cmd := exec.Command("/bin/true")
		require.NoError(t, cmd.Run())
		gonePID := uint32(cmd.Process.Pid)

		require.Equal(t, ExecHoldMarkNotApplicable,
			n.MarkExecHoldCandidate(4242, gonePID, binPath))
		require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd))
	})

	t.Run("relative path", func(t *testing.T) {
		n := newExecHoldTestNotifier(t, []string{"allowed"})
		require.Equal(t, ExecHoldMarkNotApplicable,
			n.MarkExecHoldCandidate(4242, uint32(os.Getpid()), "allowed"))
	})
}

// TestMarkExecHoldCandidateConcurrentCallers asserts the entry point is safe to
// drive from a subsystem with its own goroutines, concurrently, which is the
// only way an external caller can use it.
//
// Under -race this is the assertion that the resolve-and-mark serialises on the
// same lock the notifier's own first-exec path takes; the count assertion is
// that serialising actually deduplicates the (container, basename) rather than
// merely not crashing.
func TestMarkExecHoldCandidateConcurrentCallers(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})
	binPath := stageExternalCandidate(t, "allowed")

	const callers = 16
	var wg sync.WaitGroup
	var installed atomic.Int64
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n.MarkExecHoldCandidate(4242, uint32(os.Getpid()), binPath) == ExecHoldMarkInstalled {
				installed.Add(1)
			}
		}()
	}
	wg.Wait()

	require.LessOrEqual(t, installed.Load(), int64(1),
		"concurrent requests for one (container, basename) must collapse to at most one mark")
}
