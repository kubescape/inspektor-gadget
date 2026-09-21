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
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/s3rj1k/go-fanotify/fanotify"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// statDev returns the st_dev of path, following symlinks.
func statDev(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	require.NoError(t, unix.Stat(path, &st))
	return uint64(st.Dev)
}

// openRoot opens path as a resolution root the way markExecHoldCandidates opens
// /proc/<pid>/root.
func openRoot(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, unix.O_PATH, 0)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

// TestExecHoldOpenCandidateRejectsForeignDevice is the security regression test
// for the st_dev control: a candidate that resolves, entirely legally as far as
// openat2's RESOLVE_IN_ROOT is concerned, onto a DIFFERENT filesystem than the
// rootfs must be refused, because that is what a bind mount of a host path over
// an allowlisted binary looks like. Marking it would hold every exec of that
// host binary on the node.
//
// It uses "/" as the rootfs and a procfs file as the candidate: a real
// cross-device resolution inside the resolution root, exercising exactly the
// st_dev comparison (not just the path resolution) without needing privileges
// to create a bind mount. TestMarkExecHoldCandidatesInRootRejectsBindMount
// below is the privileged end-to-end form of the same control.
func TestExecHoldOpenCandidateRejectsForeignDevice(t *testing.T) {
	const crossDevicePath = "/proc/version"

	rootDev := statDev(t, "/")
	if statDev(t, crossDevicePath) == rootDev {
		t.Skipf("%s is on the same device as /; cannot exercise the st_dev mismatch", crossDevicePath)
	}
	root := openRoot(t, "/")

	file, err := execHoldOpenCandidate(int(root.Fd()), execHoldRootIdentity{dev: rootDev}, crossDevicePath)
	if file != nil {
		file.Close()
	}
	require.Nil(t, file, "a candidate on a foreign device must not be returned for marking")
	require.ErrorContains(t, err, "refusing to mark")
}

// TestExecHoldOpenCandidateAcceptsRootfsBinary is the positive counterpart: a
// regular file that really lives on the rootfs device resolves and is returned.
func TestExecHoldOpenCandidateAcceptsRootfsBinary(t *testing.T) {
	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr/bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rootPath, "usr/bin/allowed"), []byte("#!/bin/sh\n"), 0o755))

	root := openRoot(t, rootPath)

	file, err := execHoldOpenCandidate(int(root.Fd()), execHoldRootIdentity{dev: statDev(t, rootPath)}, "/usr/bin/allowed")
	require.NoError(t, err)
	require.NotNil(t, file)
	defer file.Close()

	var st unix.Stat_t
	require.NoError(t, unix.Fstat(int(file.Fd()), &st))
	require.Equal(t, statDev(t, filepath.Join(rootPath, "usr/bin/allowed")), uint64(st.Dev))
}

// TestExecHoldOpenCandidateRejectsSymlinkEscape asserts the resolution half:
// a symlink inside the rootfs pointing at a host path is confined by
// RESOLVE_IN_ROOT, so it cannot reach the host file at all.
func TestExecHoldOpenCandidateRejectsSymlinkEscape(t *testing.T) {
	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr/bin"), 0o755))
	// Absolute symlink to a host binary: re-rooted at rootPath, so it dangles.
	require.NoError(t, os.Symlink("/bin/true", filepath.Join(rootPath, "usr/bin/allowed")))

	root := openRoot(t, rootPath)

	file, err := execHoldOpenCandidate(int(root.Fd()), execHoldRootIdentity{dev: statDev(t, rootPath)}, "/usr/bin/allowed")
	if file != nil {
		file.Close()
	}
	require.Nil(t, file)
	require.Error(t, err, "a symlink escaping the rootfs must not resolve to the host binary")
}

// stageBindMountEscape builds a container rootfs whose /usr/bin/allowed is a
// REAL bind mount of a host binary living on another filesystem -- the escape
// openat2's RESOLVE_IN_ROOT cannot see, since the path resolves entirely inside
// the rootfs. It returns the rootfs path, and skips the test if the escape
// cannot be staged here (no mount capability, or /tmp and / on one device).
func stageBindMountEscape(t *testing.T) string {
	t.Helper()

	const hostBinary = "/bin/true"
	rootPath := t.TempDir()
	if statDev(t, hostBinary) == statDev(t, rootPath) {
		t.Skipf("%s and %s are on the same device; cannot stage a cross-device bind mount", hostBinary, rootPath)
	}

	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr/bin"), 0o755))
	target := filepath.Join(rootPath, "usr/bin/allowed")
	require.NoError(t, os.WriteFile(target, nil, 0o755))

	if err := unix.Mount(hostBinary, target, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("cannot bind-mount %s over %s: %s", hostBinary, target, err)
	}
	t.Cleanup(func() { unix.Unmount(target, unix.MNT_DETACH) })

	// Precondition: the escape really is staged, i.e. the in-rootfs path now IS
	// the host binary. Without this the test could pass for the wrong reason.
	var targetStat, hostStat unix.Stat_t
	require.NoError(t, unix.Stat(target, &targetStat))
	require.NoError(t, unix.Stat(hostBinary, &hostStat))
	require.Equal(t, hostStat.Ino, targetStat.Ino, "bind mount did not take effect")
	require.NotEqual(t, statDev(t, rootPath), uint64(targetStat.Dev))

	return rootPath
}

// TestExecHoldOpenCandidateRejectsBindMountedHostBinary is the st_dev control
// under the real attack: the allowlisted basename resolves cleanly inside the
// rootfs, but a bind mount has made it a host binary. Only the st_dev
// comparison can catch this -- path resolution alone sees nothing wrong.
func TestExecHoldOpenCandidateRejectsBindMountedHostBinary(t *testing.T) {
	rootPath := stageBindMountEscape(t)
	root := openRoot(t, rootPath)

	file, err := execHoldOpenCandidate(int(root.Fd()), execHoldRootIdentity{dev: statDev(t, rootPath)}, "/usr/bin/allowed")
	if file != nil {
		file.Close()
	}
	require.Nil(t, file, "a bind-mounted host binary must not be returned for marking")
	require.ErrorContains(t, err, "refusing to mark")
}

// fanotifyMarkedInodes parses /proc/self/fdinfo/<fd> and returns the inode
// numbers this fanotify group holds a FAN_OPEN_EXEC_PERM mark on. This is the
// only way to read fanotify marks back from userspace.
func fanotifyMarkedInodes(t *testing.T, fd int) []uint64 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", strconv.Itoa(fd)))
	require.NoError(t, err)

	// The leading space in " mask:" is load-bearing: an fdinfo line carries both
	// "mask:" and "ignored_mask:", and a greedy `.*mask:` matches the LATTER,
	// reading every mark's mask as the ignored mask (0) and so reporting no
	// marks at all.
	re := regexp.MustCompile(`^fanotify ino:([0-9a-f]+) .* mask:([0-9a-f]+)`)
	var inodes []uint64
	for _, line := range strings.Split(string(raw), "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		mask, err := strconv.ParseUint(m[2], 16, 64)
		require.NoError(t, err)
		if mask&unix.FAN_OPEN_EXEC_PERM == 0 {
			continue
		}
		ino, err := strconv.ParseUint(m[1], 16, 64)
		require.NoError(t, err)
		inodes = append(inodes, ino)
	}
	return inodes
}

// newExecHoldTestNotifier builds a notifier carrying only what the exec-hold
// marking path needs, mirroring how the guardrail tests in tracer_test.go
// construct a ContainerNotifier directly.
func newExecHoldTestNotifier(t *testing.T, basenames []string) *ContainerNotifier {
	t.Helper()
	utils.RequireRoot(t)

	notify, err := initExecHoldFanotify()
	require.NoError(t, err, "creating the exec-hold fanotify group")
	t.Cleanup(func() { notify.File.Close() })

	return &ContainerNotifier{
		execHoldNotify:   notify,
		execHoldBinaries: basenames,
	}
}

// TestMarkExecHoldCandidatesInRootMarksRootfsBinary asserts the positive
// end-to-end case: a container rootfs that contains a real allowlisted binary
// at a normal location gets a FAN_OPEN_EXEC_PERM mark on that exact inode,
// verified by reading the group's marks back from fdinfo.
func TestMarkExecHoldCandidatesInRootMarksRootfsBinary(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})

	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr/bin"), 0o755))
	binPath := filepath.Join(rootPath, "usr/bin/allowed")
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	var binStat unix.Stat_t
	require.NoError(t, unix.Stat(binPath, &binStat))

	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd), "group must start with no marks")

	marked := n.markExecHoldCandidatesInRoot(openRoot(t, rootPath), 0)
	require.Equal(t, []string{"/usr/bin/allowed"}, marked)

	require.Contains(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd), binStat.Ino,
		"a FAN_OPEN_EXEC_PERM mark must be installed on the container's binary")
}

// TestMarkExecHoldCandidatesInRootRejectsBindMount is the privileged,
// end-to-end form of the st_dev control: the allowlisted basename resolves
// cleanly inside the rootfs, but a bind mount has made it a HOST binary on
// another filesystem. No mark may be installed, on that file or any other.
func TestMarkExecHoldCandidatesInRootRejectsBindMount(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})
	rootPath := stageBindMountEscape(t)

	marked := n.markExecHoldCandidatesInRoot(openRoot(t, rootPath), 0)
	require.Empty(t, marked, "a bind-mounted host binary must never be marked")
	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd),
		"no fanotify mark may be installed when the st_dev check rejects the candidate")
}

// TestMarkExecHoldCandidatesNoAllowlist asserts the opt-in default: with an
// empty allowlist the marking path does nothing at all, so the container-hook
// pays nothing per container until an operator configures it.
func TestMarkExecHoldCandidatesNoAllowlist(t *testing.T) {
	n := &ContainerNotifier{}
	n.markExecHoldCandidates(uint32(os.Getpid()), 0)
	require.Nil(t, n.markExecHoldCandidatesInRoot(openRoot(t, t.TempDir()), 0))
}

// TestMarkExecHoldCandidatesMntnsMismatchSkipsEnumeration pins the pid-reuse
// guard added to markExecHoldCandidates: when the mount namespace read back
// for containerPID does not match the expected one recorded at
// container-add time, nothing is marked -- containerPID no longer identifies
// the container this enumeration was scoped to (it exited and was recycled
// for an unrelated process, or never matched to begin with).
func TestMarkExecHoldCandidatesMntnsMismatchSkipsEnumeration(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"sh"})

	// Wrong on purpose: this test process's real mount namespace is never 1
	// (namespace inode numbers start well above the low, reserved range).
	n.markExecHoldCandidates(uint32(os.Getpid()), 1)

	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd),
		"a mount-namespace mismatch must skip enumeration entirely, not mark anything")
}

// TestMarkExecHoldCandidatesMntnsMatchStillEnumerates is the control for the
// guard above: the SAME call with the process's real, current mount
// namespace must still enumerate normally, so the guard rejects a genuine
// mismatch without silently breaking the intended path.
func TestMarkExecHoldCandidatesMntnsMatchStillEnumerates(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"sh"})

	realMntNs, err := containerutils.GetMntNs(os.Getpid())
	require.NoError(t, err)

	n.markExecHoldCandidates(uint32(os.Getpid()), realMntNs)

	require.NotEmpty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd),
		"a matching mount namespace must still enumerate and mark sh, exactly as with no check at all")
}

// TestSetExecHoldBinaries asserts the allowlist is snapshotted into the
// notifier at construction rather than read live from the package variable.
func TestSetExecHoldBinaries(t *testing.T) {
	name := fmt.Sprintf("ig-test-%d", rand.Uint32())
	previous := execHoldBinaries
	t.Cleanup(func() { SetExecHoldBinaries(previous) })

	SetExecHoldBinaries([]string{name})
	require.Equal(t, []string{name}, execHoldBinaries)
}

// TestExecHoldExecedPathResolvesRunningBinary asserts the only thing an exec
// event can be turned into a path with: the record carries a mntns id and a
// tgid, so the exec'd binary has to come from /proc/<pid>/exe.
func TestExecHoldExecedPathResolvesRunningBinary(t *testing.T) {
	path, err := execHoldExecedPath(uint32(os.Getpid()))
	require.NoError(t, err)

	self, err := os.Executable()
	require.NoError(t, err)
	require.Equal(t, self, path)
}

// TestExecHoldExecedPathRejectsDeadPid asserts a pid that has already gone does
// not yield a path to mark.
func TestExecHoldExecedPathRejectsDeadPid(t *testing.T) {
	// Pid 0 is never a process directory in /proc.
	_, err := execHoldExecedPath(0)
	require.Error(t, err)
}

// TestExecHoldAllowlisted covers the basename filter that keeps the per-exec
// cost of this path to a readlink and a slice scan for every exec that is not
// of interest.
func TestExecHoldAllowlisted(t *testing.T) {
	n := &ContainerNotifier{execHoldBinaries: []string{"allowed", "other"}}
	require.True(t, n.execHoldAllowlisted("allowed"))
	require.True(t, n.execHoldAllowlisted("other"))
	require.False(t, n.execHoldAllowlisted("notallowed"))
	require.False(t, (&ContainerNotifier{}).execHoldAllowlisted("allowed"))
}

// TestExecHoldOnExecNoAllowlist asserts the opt-in default holds for the
// first-exec path too: with no allowlist (and so no fanotify group) an exec
// event does no work at all and cannot panic on the nil group.
func TestExecHoldOnExecNoAllowlist(t *testing.T) {
	n := &ContainerNotifier{}
	n.execHoldOnExec(1234, uint32(os.Getpid()))
	require.False(t, n.execHoldMarkExecedBinary(1234, openRoot(t, t.TempDir()), "/usr/bin/allowed"))
	require.Nil(t, n.execHoldMarked)
}

// TestExecHoldForgetDropsContainerState asserts the per-container bookkeeping is
// released on termination, so the set cannot grow with the node's container
// churn.
func TestExecHoldForgetDropsContainerState(t *testing.T) {
	n := &ContainerNotifier{
		execHoldMarked: map[uint64]map[string]execHoldKey{
			42: {"allowed": {dev: 1, ino: 100}},
			43: {"allowed": {dev: 1, ino: 200}},
		},
	}

	n.execHoldForget(42)
	require.NotContains(t, n.execHoldMarked, uint64(42))
	require.Contains(t, n.execHoldMarked, uint64(43))

	// Forgetting an unknown container is a no-op, not an error: the exec-hold
	// state is only populated for containers that actually exec'd something
	// allowlisted.
	n.execHoldForget(9999)
}

// TestExecHoldForgetKeepsSharedMarkForOtherContainer is execHoldForget's own
// half of the shared-mark-across-containers fix (see
// TestExecHoldSettleKeepsMarkWhileAnotherContainerOwnsIt for the settle
// half): two containers can retain a mark for the IDENTICAL host inode (an
// unmodified base-image layer). Terminating one must drop only its own
// entry and retained fd -- the kernel mark and dispatcher hold-state must
// stay in place for the other, still-alive owner, and only actually get
// removed once that last owner is forgotten too.
func TestExecHoldForgetKeepsSharedMarkForOtherContainer(t *testing.T) {
	path, key := testBinary(t)

	// A pipe stands in for the fanotify group: FAN_MARK_REMOVE on it always
	// fails, which is fine here -- execHoldMark logs and moves on, same as
	// TestMarkExecHoldPathRollsBackHoldStateOnMarkFailure's use of the same
	// trick. What this test asserts is the LOCAL bookkeeping, not whether the
	// kernel call itself succeeded.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { r.Close(); w.Close() })

	fileA, err := os.Open(path)
	require.NoError(t, err)
	fileB, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { fileA.Close(); fileB.Close() })

	n := &ContainerNotifier{
		execHoldNotify: &fanotify.NotifyFD{Fd: int(r.Fd()), File: r},
		execHoldContainerMarks: map[uint64][]execHoldMarkedFile{
			100: {{key: key, file: fileA}},
			200: {{key: key, file: fileB}},
		},
	}
	n.execHoldRememberHold(key)

	n.execHoldForget(100)
	require.NotContains(t, n.execHoldContainerMarks, uint64(100), "the terminated container's own entry must be dropped")
	require.Contains(t, n.execHoldContainerMarks, uint64(200), "the OTHER, still-alive container's entry must be untouched")
	require.True(t, n.execHoldHasHold(key), "hold-state must stay in place while another container still owns the object")

	n.execHoldForget(200)
	require.NotContains(t, n.execHoldContainerMarks, uint64(200))
	require.False(t, n.execHoldHasHold(key), "once the LAST owner is forgotten, the shared object's state must finally be dropped")
}

// TestExecHoldAbsentBinaryIsNotMarkedAtCreate is the premise of this whole code
// path, asserted explicitly rather than assumed: a binary that is not in the
// container rootfs when the container is created gets no mark from the
// create-time enumeration, so without a first-exec mark every exec of it would
// go unseen forever.
func TestExecHoldAbsentBinaryIsNotMarkedAtCreate(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})

	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr/bin"), 0o755))

	require.Empty(t, n.markExecHoldCandidatesInRoot(openRoot(t, rootPath), 0),
		"nothing may be marked for a rootfs that does not contain the binary")
	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd))

	// And the first-exec path likewise refuses a path that is not there: it
	// marks what was actually exec'd, it does not create anything.
	require.False(t, n.execHoldMarkExecedBinary(1, openRoot(t, rootPath), "/usr/bin/allowed"))
	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd))
}

// TestExecHoldMarkExecedBinaryMarksBinaryAddedAfterCreate is the core of this
// story: the binary appears in the rootfs only AFTER the container was created
// (so the create-time enumeration never saw it), and the exec event is what
// gets it marked.
func TestExecHoldMarkExecedBinaryMarksBinaryAddedAfterCreate(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})

	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "opt/app"), 0o755))
	root := openRoot(t, rootPath)

	// Container-create time: nothing to mark.
	require.Empty(t, n.markExecHoldCandidatesInRoot(root, 0))
	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd))

	// The workload drops the binary in, at a path that is not even one of the
	// enumeration's search paths, and execs it.
	binPath := filepath.Join(rootPath, "opt/app/allowed")
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	var binStat unix.Stat_t
	require.NoError(t, unix.Stat(binPath, &binStat))

	require.True(t, n.execHoldMarkExecedBinary(1, root, "/opt/app/allowed"))
	require.Contains(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd), binStat.Ino,
		"the exec'd binary must carry a FAN_OPEN_EXEC_PERM mark for subsequent execs")
}

// TestExecHoldMarkExecedBinaryIgnoresUnallowlistedBinary asserts the allowlist
// really gates this call site: an exec of something else in the same container
// installs nothing.
func TestExecHoldMarkExecedBinaryIgnoresUnallowlistedBinary(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})

	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr/bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rootPath, "usr/bin/other"), []byte("x"), 0o755))

	require.False(t, n.execHoldMarkExecedBinary(1, openRoot(t, rootPath), "/usr/bin/other"))
	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd))
}

// TestExecHoldMarkExecedBinaryIsIdempotent asserts that a busy binary exec'd
// over and over does not re-resolve and re-mark on every exec, and that the
// group ends up holding exactly one mark on that inode.
func TestExecHoldMarkExecedBinaryIsIdempotent(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})

	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr/bin"), 0o755))
	binPath := filepath.Join(rootPath, "usr/bin/allowed")
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	var binStat unix.Stat_t
	require.NoError(t, unix.Stat(binPath, &binStat))

	root := openRoot(t, rootPath)
	require.True(t, n.execHoldMarkExecedBinary(7, root, "/usr/bin/allowed"))
	require.False(t, n.execHoldMarkExecedBinary(7, root, "/usr/bin/allowed"),
		"a second exec of the same binary in the same container must not mark again")

	var count int
	for _, ino := range fanotifyMarkedInodes(t, n.execHoldNotify.Fd) {
		if ino == binStat.Ino {
			count++
		}
	}
	require.Equal(t, 1, count, "the group must hold exactly one mark on the binary")

	// A DIFFERENT container running the same basename is a different inode in a
	// different rootfs, so it is not deduplicated against the first one.
	require.True(t, n.execHoldMarkExecedBinary(8, root, "/usr/bin/allowed"))
}

// TestExecHoldMarkExecedBinaryRemarksReplacedFile is the regression test for
// the path-only dedup bug: FAN_MARK_ADD marks the INODE, not the path, so
// after a first mark, replacing the file AT THE SAME PATH (e.g. an atomic
// rewrite -- unlink + rename, as most package managers and self-updaters do)
// leaves the OLD mark on now-orphaned content while the NEW inode at that
// path was never marked at all. Dedup keyed only on (mntnsID, path) would
// treat the second exec as a pure repeat and skip it forever; keying on the
// actual (dev, ino) too must catch the replacement and mark the new object.
func TestExecHoldMarkExecedBinaryRemarksReplacedFile(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})

	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr/bin"), 0o755))
	binPath := filepath.Join(rootPath, "usr/bin/allowed")
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	var firstStat unix.Stat_t
	require.NoError(t, unix.Stat(binPath, &firstStat))

	root := openRoot(t, rootPath)
	require.True(t, n.execHoldMarkExecedBinary(7, root, "/usr/bin/allowed"))
	require.Contains(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd), firstStat.Ino)

	// Atomic replace: a new file staged alongside, then renamed over the
	// original -- a DIFFERENT inode ends up at the exact same path.
	replacement := binPath + ".new"
	require.NoError(t, os.WriteFile(replacement, []byte("#!/bin/sh\nexit 1\n"), 0o755))
	require.NoError(t, os.Rename(replacement, binPath))
	var secondStat unix.Stat_t
	require.NoError(t, unix.Stat(binPath, &secondStat))
	require.NotEqual(t, firstStat.Ino, secondStat.Ino, "the test setup must actually produce a different inode")

	require.True(t, n.execHoldMarkExecedBinary(7, root, "/usr/bin/allowed"),
		"a same-path exec of a REPLACED binary must be marked again, not treated as a repeat")
	require.Contains(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd), secondStat.Ino,
		"the new object's inode must now carry a mark")

	// A third exec of the (now unchanged again) replacement is correctly
	// deduplicated, same as the ordinary repeat case.
	require.False(t, n.execHoldMarkExecedBinary(7, root, "/usr/bin/allowed"))
}

// TestExecHoldMarkExecedBinaryRejectsBindMountedHostBinary confirms this new
// call site is behind the same st_dev control as the create-time enumeration:
// a container that bind-mounts a host binary over an allowlisted name and execs
// it cannot get the HOST binary marked, which would hold every exec of it on
// the node. It reuses US-03's staging of the escape verbatim.
func TestExecHoldMarkExecedBinaryRejectsBindMountedHostBinary(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})
	rootPath := stageBindMountEscape(t)

	require.False(t, n.execHoldMarkExecedBinary(1, openRoot(t, rootPath), "/usr/bin/allowed"),
		"a bind-mounted host binary must never be marked via the exec-event path")
	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd))
}

// TestExecHoldMarkExecedBinaryRejectsSymlinkEscape is the resolution half of
// the same control at this call site: an exec'd path that is a symlink out of
// the rootfs cannot reach the host file, because the path is re-resolved with
// RESOLVE_IN_ROOT rather than trusted as read from /proc/<pid>/exe.
func TestExecHoldMarkExecedBinaryRejectsSymlinkEscape(t *testing.T) {
	n := newExecHoldTestNotifier(t, []string{"allowed"})

	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr/bin"), 0o755))
	require.NoError(t, os.Symlink("/bin/true", filepath.Join(rootPath, "usr/bin/allowed")))

	require.False(t, n.execHoldMarkExecedBinary(1, openRoot(t, rootPath), "/usr/bin/allowed"))
	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd))
}

// sameDeviceDir returns a writable directory on the same filesystem as "/", or
// skips: a binary on any other device is refused by the st_dev control, which
// is correct behaviour but makes it impossible to stage a legitimate mark.
func sameDeviceDir(t *testing.T) string {
	t.Helper()

	rootDev := statDev(t, "/")
	if dir := t.TempDir(); statDev(t, dir) == rootDev {
		return dir
	}
	dir, err := os.MkdirTemp("/var/tmp", "ig-exechold-")
	if err != nil || statDev(t, dir) != rootDev {
		if err == nil {
			os.RemoveAll(dir)
		}
		t.Skip("no writable directory found on the same filesystem as /; cannot stage a markable binary")
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// TestExecHoldOnExecMarksRealExecedProcess drives the whole first-exec path the
// way watchExecEvents does -- with nothing but a mntns id and a pid -- against a
// real running process, so the /proc/<pid>/exe and /proc/<pid>/root resolution
// is exercised rather than stubbed.
func TestExecHoldOnExecMarksRealExecedProcess(t *testing.T) {
	const basename = "ig-exechold-allowed"

	n := newExecHoldTestNotifier(t, []string{basename})
	dir := sameDeviceDir(t)

	// A copy, never a host binary: marking a real host binary would hold every
	// exec of it on this machine for as long as the group is open.
	src, err := exec.LookPath("sleep")
	require.NoError(t, err)
	payload, err := os.ReadFile(src)
	require.NoError(t, err)
	binPath := filepath.Join(dir, basename)
	require.NoError(t, os.WriteFile(binPath, payload, 0o755))

	var binStat unix.Stat_t
	require.NoError(t, unix.Stat(binPath, &binStat))

	cmd := exec.Command(binPath, "60")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd))

	// The REAL mount namespace of cmd.Process.Pid, not a fabricated value:
	// execHoldOnExec now revalidates the mntns it is handed against the one
	// the pid actually has (see TestExecHoldOnExecMntnsMismatchDoesNotMark for
	// the negative case), matching the guarantee watchExecEvents' real exec
	// event record actually provides -- a mismatch here would no longer mark
	// anything.
	mntnsID, err := containerutils.GetMntNs(cmd.Process.Pid)
	require.NoError(t, err)
	n.execHoldOnExec(mntnsID, uint32(cmd.Process.Pid))

	require.Contains(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd), binStat.Ino,
		"observing the exec must install a mark for subsequent execs of that binary")
	require.Contains(t, n.execHoldMarked[mntnsID], filepath.Join(dir, basename))

	// Idempotent through the full path too, not just its core.
	n.execHoldOnExec(mntnsID, uint32(cmd.Process.Pid))
	var count int
	for _, ino := range fanotifyMarkedInodes(t, n.execHoldNotify.Fd) {
		if ino == binStat.Ino {
			count++
		}
	}
	require.Equal(t, 1, count)
}

// TestExecHoldOnExecMntnsMismatchDoesNotMark is the security regression test
// for the PID-recycle hardening added to execHoldOnExec: if the mount
// namespace execPid actually has no longer matches the mntnsID the caller
// (the original exec event) carried, nothing may be marked -- opening
// /proc/<execPid>/root and marking under it would otherwise resolve an
// UNRELATED process's (potentially the HOST's) filesystem, not the container
// the event was really about.
//
// Uses the same real, allowlisted subprocess as
// TestExecHoldOnExecMarksRealExecedProcess (so this exercises the mntns check
// specifically, not just the earlier allowlist filter), but hands
// execHoldOnExec a mntnsID that does not match its real one.
func TestExecHoldOnExecMntnsMismatchDoesNotMark(t *testing.T) {
	const basename = "ig-exechold-allowed"

	n := newExecHoldTestNotifier(t, []string{basename})
	dir := sameDeviceDir(t)

	src, err := exec.LookPath("sleep")
	require.NoError(t, err)
	payload, err := os.ReadFile(src)
	require.NoError(t, err)
	binPath := filepath.Join(dir, basename)
	require.NoError(t, os.WriteFile(binPath, payload, 0o755))

	cmd := exec.Command(binPath, "60")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	realMntNs, err := containerutils.GetMntNs(cmd.Process.Pid)
	require.NoError(t, err)

	// Any value that is not the process's real mntns simulates the pid
	// having been recycled for an unrelated process since the exec event
	// that named mntnsID was observed.
	n.execHoldOnExec(realMntNs+1, uint32(cmd.Process.Pid))

	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd),
		"a mount-namespace mismatch must refuse to mark, not resolve an unrelated process's root")
	require.Empty(t, n.execHoldMarked)
}
