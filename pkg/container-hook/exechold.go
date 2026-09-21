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

package containerhook

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// execHoldSearchPaths are the directories inside a container rootfs where an
// allowlisted basename is looked up, in the usual PATH order. A basename found
// in several of them is marked in each: they are distinct inodes and any of
// them could be the one exec'd.
var execHoldSearchPaths = []string{
	"/usr/local/sbin",
	"/usr/local/bin",
	"/usr/sbin",
	"/usr/bin",
	"/sbin",
	"/bin",
}

// execHoldBinaries is the operator-configurable allowlist of basenames whose
// exec is held inside newly created containers. It is empty by default, so the
// container-hook adds no per-container cost until an operator opts in. Set it
// with SetExecHoldBinaries before NewContainerNotifier; a config-plumbing story
// wires it to PrivateConfig separately.
var execHoldBinaries []string

// SetExecHoldBinaries sets the exec-hold allowlist. It must be called before
// NewContainerNotifier, which copies it into the notifier; changing it
// afterwards does not affect an existing notifier.
//
// Clones basenames rather than aliasing it: NewContainerNotifier clones this
// package-level slice again for the same reason (see its own doc comment), so
// this clone's only job is to stop a caller's later mutation of basenames'
// backing array from being visible here even before a notifier is
// constructed.
func SetExecHoldBinaries(basenames []string) {
	execHoldBinaries = append([]string(nil), basenames...)
}

// initExecHoldFanotify creates the fanotify group used to hold execs of
// allowlisted binaries inside containers. It is deliberately a SEPARATE group
// from the one initFanotify creates for the runtime binary and the pid file
// directories: those two feed the container-detection pipeline (and the
// fsnotify_remove_first_event kprobe pairing keyed on the tracer group), while
// this one carries per-container marks with a different lifetime and a
// different event consumer.
func initExecHoldFanotify() (*fanotify.NotifyFD, error) {
	// Flags for the fanotify fd
	var fanotifyFlags uint
	// FAN_CLOEXEC is required to avoid leaking the fd to child processes
	fanotifyFlags |= uint(unix.FAN_CLOEXEC)
	// FAN_CLASS_CONTENT is required for perm events such as FAN_OPEN_EXEC_PERM
	fanotifyFlags |= uint(unix.FAN_CLASS_CONTENT)
	// FAN_UNLIMITED_MARKS is required so we can mark as many container binaries
	// as necessary without being restricted by:
	//     sysctl fs.fanotify.max_user_marks
	fanotifyFlags |= uint(unix.FAN_UNLIMITED_MARKS)
	// FAN_NONBLOCK is required so GetEvent can be interrupted by Close()
	fanotifyFlags |= uint(unix.FAN_NONBLOCK)
	// Deliberately NOT FAN_REPORT_TID, unlike initFanotify: that flag makes the
	// kernel report the triggering THREAD id, and holding an exec needs the
	// process pid to resolve which container the exec belongs to.
	// Deliberately NOT FAN_UNLIMITED_QUEUE, unlike initFanotify: these are
	// permission events that each pin a blocked process, so the queue must stay
	// bounded and shed (the kernel then allows the exec) rather than grow without
	// limit if the consumer falls behind.

	// Flags for the fd installed when reading a fanotify event (i.e. the fd of
	// the binary being exec'd).
	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	return fanotify.Initialize(fanotifyFlags, openFlags)
}

// execHoldRootIdentity is the device and (kernel permitting) unique mount
// identity of a container rootfs, resolved once per enumeration/mark call and
// checked against every candidate execHoldOpenCandidate opens under it.
type execHoldRootIdentity struct {
	dev uint64
	// mntID and mntIDValid: see execHoldStatObject. mntIDValid is false on a
	// pre-5.8 kernel, where mount identity cannot be checked at all and
	// rootDev is the only signal execHoldOpenCandidate has.
	mntID      uint64
	mntIDValid bool
}

// execHoldStatObject reports fd's device and, on a kernel that supports it
// (Linux >= 5.8 for STATX_MNT_ID, preferring the reuse-proof
// STATX_MNT_ID_UNIQUE from Linux >= 6.8), its unique mount identity. fd may be
// an O_PATH descriptor: AT_EMPTY_PATH means no second path resolution is
// involved, so this cannot itself become a TOCTOU window.
func execHoldStatObject(fd int) (execHoldRootIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return execHoldRootIdentity{}, fmt.Errorf("fstat: %w", err)
	}
	id := execHoldRootIdentity{dev: uint64(stat.Dev)}

	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID_UNIQUE, &stx); err == nil && stx.Mask&uint32(unix.STATX_MNT_ID_UNIQUE) != 0 {
		id.mntID, id.mntIDValid = stx.Mnt_id, true
	} else if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stx); err == nil && stx.Mask&uint32(unix.STATX_MNT_ID) != 0 {
		id.mntID, id.mntIDValid = stx.Mnt_id, true
	}
	// Neither statx call reporting the mask bit means a pre-5.8 kernel: leave
	// mntIDValid false rather than treating that as an error, since st_dev
	// alone is still a real (if narrower) check.
	return id, nil
}

// execHoldOpenCandidate resolves unsafePath strictly inside the container
// rootfs referred to by rootFd and returns an open O_RDONLY fd for it, or an
// error if the candidate must not be marked.
//
// rootFd is used as the resolution root for openat2 with
// RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS, the same hardening
// secureopen.OpenInContainer applies; it is taken as an already-open fd rather
// than a /proc/<pid>/root path so the root is pinned once and the candidate is
// returned as an fd the caller can act on without resolving the path again.
func execHoldOpenCandidate(rootFd int, root execHoldRootIdentity, unsafePath string) (*os.File, error) {
	// O_PATH avoids blocking on opening the candidate if it turns out to be a
	// pipe or a device, and is enough for fstat. It is NOT enough for
	// fanotify_mark: the kernel's NULL-pathname mark-by-fd form resolves the
	// dirfd argument via fdget(), which explicitly excludes FMODE_PATH files
	// and returns EBADF for an O_PATH descriptor -- verified directly against
	// this host's kernel (fanotify_mark on an O_PATH fd: "bad file descriptor";
	// the identical call on an O_RDONLY fd for the same inode: succeeds). So
	// validation happens via O_PATH, but the fd actually handed to Mark() below
	// is a separate, plain O_RDONLY re-open of the SAME already-validated
	// object -- never a second resolution of the path, which would reopen the
	// exact TOCTOU window this function's own RESOLVE_IN_ROOT/st_dev checks
	// exist to close.
	how := unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Mode:    0,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	pathFd, err := unix.Openat2(rootFd, unsafePath, &how)
	if err != nil {
		return nil, fmt.Errorf("openat2 %q in container rootfs: %w", unsafePath, err)
	}
	pathFile := os.NewFile(uintptr(pathFd), unsafePath)
	defer pathFile.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(pathFd, &stat); err != nil {
		return nil, fmt.Errorf("fstat %q in container rootfs: %w", unsafePath, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%q in container rootfs is not a regular file: expected %d, got %d",
			unsafePath, unix.S_IFREG, stat.Mode&unix.S_IFMT)
	}

	// RESOLVE_IN_ROOT confines symlinks to the rootfs, but it cannot see through
	// a bind mount: a container can mount a host path over /usr/bin/<name> and
	// have a perfectly in-root resolution land on a HOST binary. Requiring the
	// candidate's st_dev to match the rootfs' st_dev rejects a bind mount from a
	// DIFFERENT filesystem, since that carries a different device. This is a
	// security control, not a heuristic: marking a host binary would hold every
	// exec of it on the node, container or not.
	//
	// The cost is that a binary living on a filesystem legitimately mounted
	// inside the container (e.g. /usr as a separate volume) is skipped rather
	// than marked. Refusing to mark is the safe direction of that trade.
	if uint64(stat.Dev) != root.dev {
		return nil, fmt.Errorf("%q in container rootfs is on device %d, not the rootfs device %d: refusing to mark",
			unsafePath, uint64(stat.Dev), root.dev)
	}

	// st_dev alone is not enough: a bind mount of a HOST path that happens to
	// live on the SAME filesystem as the rootfs (a same-device bind mount, e.g.
	// bind-mounting another directory from the node's root filesystem into the
	// container) carries the same st_dev and passes the check above untouched,
	// even though the candidate is not actually part of the container's own
	// rootfs mount. Comparing the candidate's mount identity against the
	// rootfs's closes that gap; see execHoldStatObject for why this is
	// kernel-version-gated (pre-5.8: mntIDValid is false and this check is
	// skipped, same posture as before this hardening existed).
	if root.mntIDValid {
		candID, err := execHoldStatObject(pathFd)
		if err == nil && candID.mntIDValid && candID.mntID != root.mntID {
			return nil, fmt.Errorf("%q in container rootfs is on mount %d, not the rootfs mount %d: refusing to mark (bind mount)",
				unsafePath, candID.mntID, root.mntID)
		}
	}

	// Re-open the exact object behind pathFd -- not unsafePath again -- via
	// /proc/self/fd, so there is no second path resolution and therefore no
	// window for the container to swap the target between validation and this
	// re-open. Safe to use a real, readable open now: S_ISREG, st_dev and (where
	// the kernel supports it) mount identity are already confirmed, so this can
	// no longer land on a device, pipe, or cross-device/cross-mount target the
	// O_PATH open was specifically avoiding. The fd this function returns is
	// therefore O_RDONLY, not O_PATH -- fanotify_mark's NULL-pathname mark-by-fd
	// form requires it (see the O_PATH comment above), so callers must not
	// assume the returned fd is O_PATH-restricted.
	fd, err := unix.Openat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", pathFd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("re-opening validated candidate %q for marking: %w", unsafePath, err)
	}
	return os.NewFile(uintptr(fd), unsafePath), nil
}

// execHoldMarkedFile pairs a still-OPEN marking fd with the key it marked.
// markExecHoldPath retains it (per mntnsID, in
// ContainerNotifier.execHoldContainerMarks) instead of closing it, because
// removing a specific object's fanotify mark later (execHoldForget, on
// container termination) needs a live fd on that SAME object, and by
// termination time /proc/<pid>/root is gone: there is no path left to
// re-resolve it from.
type execHoldMarkedFile struct {
	key  execHoldKey
	file *os.File
}

// markExecHoldPath resolves candidatePath under the container rootfs referred
// to by rootFd, with execHoldOpenCandidate's full hardening, and installs the
// FAN_OPEN_EXEC_PERM mark on the object it resolved to.
//
// It is the single place where an exec-hold mark is installed, so every call
// site — the create-time enumeration and the first-exec path alike — is
// necessarily behind the same openat2 RESOLVE_IN_ROOT/st_dev/mount-identity
// controls.
//
// mntnsID scopes the mark to a container for later removal (execHoldForget):
// 0 means the caller could not resolve one, in which case the mark is
// installed exactly as before this scoping existed (fire-and-forget, closed
// immediately, never explicitly removed) rather than refused -- refusing
// would give up real protection over a bookkeeping gap.
func (n *ContainerNotifier) markExecHoldPath(rootFd int, root execHoldRootIdentity, mntnsID uint64, candidatePath string) error {
	file, err := execHoldOpenCandidate(rootFd, root, candidatePath)
	if err != nil {
		return err
	}

	// The dispatcher's hold-state is keyed on the object's (dev, ino), which is
	// read from the very fd about to be marked, so the state and the mark can
	// never describe different objects.
	key, err := execHoldKeyOfFd(int(file.Fd()))
	if err != nil {
		file.Close()
		return fmt.Errorf("identifying %q for marking: %w", candidatePath, err)
	}

	// Mark the ALREADY-OPEN, already-validated fd: passing it as dirFd
	// together with an EMPTY path forwards a NULL pathname to fanotify_mark,
	// so the kernel marks this exact object instead of resolving the path a
	// second time, which is a window the container could use to swap the
	// target between validation and mark.
	err = n.execHoldInstallMark(key, func() error {
		return n.execHoldNotify.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, int(file.Fd()), "")
	})
	if err != nil {
		file.Close()
		return fmt.Errorf("marking %q: %w", candidatePath, err)
	}

	if mntnsID == 0 {
		file.Close()
		return nil
	}
	n.execHoldContainerMarksMu.Lock()
	if n.execHoldContainerMarks == nil {
		n.execHoldContainerMarks = make(map[uint64][]execHoldMarkedFile)
	}
	n.execHoldContainerMarks[mntnsID] = append(n.execHoldContainerMarks[mntnsID], execHoldMarkedFile{key: key, file: file})
	n.execHoldContainerMarksMu.Unlock()

	return nil
}

// execHoldInstallMark records the dispatcher's hold-state for key and then
// installs the mark, rolling the state back if marking fails.
//
// The ordering is the point, and is why this is a function of its own rather
// than three lines inline: hold-state must exist BEFORE the kernel can deliver
// an event for the object, because an event with no hold-state is allowed
// immediately by the dispatcher's guard. State recorded after fanotify_mark
// returned would leave a window in which a genuine hold looks unrecognised.
//
// holdsMu is held across BOTH the state update and the mark() syscall itself
// -- not delegated to execHoldRememberHold, which releases the lock
// immediately and exists for tests that want to seed hold-state without a
// real mark call. Spanning the syscall is what makes this mutually exclusive
// with execHoldReleaseHeldMark (used by execHoldSettle and execHoldForget)
// for the SAME key: without it, a settle racing between this call's
// increment and its mark() syscall could delete key's hold-state believing
// the kernel mark it just removed was the only one, just before mark()
// installs a NEW kernel mark nothing tracks any more -- future events for key
// would then fail the F10 guard and be waved through unheld, with the mark
// itself silently orphaned (present in the kernel, absent from this
// dispatcher's bookkeeping) until this notifier closes.
//
// mark is injected so that ordering is observable in a test.
func (n *ContainerNotifier) execHoldInstallMark(key execHoldKey, mark func() error) error {
	n.execHold.holdsMu.Lock()
	defer n.execHold.holdsMu.Unlock()

	if n.execHold.holds == nil {
		n.execHold.holds = make(map[execHoldKey]int)
	}
	n.execHold.holds[key]++

	if err := mark(); err != nil {
		n.execHold.holds[key]--
		if n.execHold.holds[key] <= 0 {
			delete(n.execHold.holds, key)
		}
		return err
	}
	return nil
}

// markExecHoldCandidatesInRoot marks every allowlisted binary it can safely
// resolve under the already-open container rootfs rootDir, and returns the
// paths it marked. mntnsID scopes the marks for later removal; see
// markExecHoldPath.
//
// It deliberately performs NO real-inode lookup and consults no attachment
// state: every safely-resolved candidate is marked unconditionally. Deciding
// whether a given exec is actually of interest belongs to the event consumer,
// which sees the exec'd fd itself.
func (n *ContainerNotifier) markExecHoldCandidatesInRoot(rootDir *os.File, mntnsID uint64) []string {
	if n.execHoldNotify == nil || len(n.execHoldBinaries) == 0 {
		return nil
	}

	root, err := execHoldStatObject(int(rootDir.Fd()))
	if err != nil {
		log.Errorf("container-hook: exec-hold: fstat of container rootfs: %s", err)
		return nil
	}

	var marked []string
	for _, basename := range n.execHoldBinaries {
		for _, dir := range execHoldSearchPaths {
			candidatePath := filepath.Join(dir, basename)

			if err := n.markExecHoldPath(int(rootDir.Fd()), root, mntnsID, candidatePath); err != nil {
				// Expected for every search path the binary is not in, so this
				// stays at debug level: the rejection cases are logged by the
				// error text they carry.
				log.Debugf("container-hook: exec-hold: not marking %s: %s", candidatePath, err)
				continue
			}

			marked = append(marked, candidatePath)
		}
	}

	return marked
}

// markExecHoldCandidates installs the exec-hold marks for a container that is
// being created. It runs inside the bounded AddContainer gate (see
// callbackAddContainerBounded), so it is covered by the same hard bound and
// fail-open as the callback itself and can never hold runc's create→start
// transition open.
//
// expectedMntnsID re-validates containerPID's identity before trusting
// /proc/<containerPID>/root: this runs from an unjoined, fire-and-forget
// goroutine (see callbackAddContainerBounded's own doc comment) with no bound
// on how long it might sit before actually running, so containerPID can in
// principle have already exited and been recycled by the kernel for an
// unrelated host process by the time this executes -- opening its root by PID
// alone would then mark that unrelated process's binaries, not the intended
// container's. This is the same TOCTOU class execHoldOpenCandidate's
// open-then-validate hardening already closes for individual mark targets;
// this closes it one level up, for the container identity the whole
// enumeration is scoped to.
func (n *ContainerNotifier) markExecHoldCandidates(containerPID uint32, expectedMntnsID uint64) {
	if n.execHoldNotify == nil || len(n.execHoldBinaries) == 0 {
		return
	}

	// /proc/<pid>/root is how the rest of this codebase reaches a container's
	// filesystem from the host (see secureopen.openInContainer). O_PATH pins the
	// rootfs without opening it for I/O.
	root := filepath.Join(host.HostProcFs, strconv.Itoa(int(containerPID)), "root")
	rootDir, err := os.OpenFile(root, unix.O_PATH, 0)
	if err != nil {
		log.Debugf("container-hook: exec-hold: opening %q: %s", root, err)
		return
	}
	defer rootDir.Close()

	// Re-checked AFTER opening root, narrowing the window rather than closing
	// it outright: this is still a second, independent /proc/<pid> read, not
	// derived from the already-open rootDir fd itself (nothing here ties the
	// two reads to the same underlying process atomically), so a recycle
	// landing in the gap between them is possible in principle, just far
	// less likely than the original unchecked window this replaces. A
	// mismatch means containerPID no longer names the container this
	// enumeration was scoped to (exited and reused, or never matched), so
	// nothing here should be trusted.
	if expectedMntnsID != 0 {
		currentMntNs, err := containerutils.GetMntNs(int(containerPID))
		if err != nil {
			log.Debugf("container-hook: exec-hold: checking mnt namespace of pid %d before enumeration: %s", containerPID, err)
			return
		}
		if currentMntNs != expectedMntnsID {
			log.Debugf("container-hook: exec-hold: pid %d no longer has the expected mount namespace (want %d, got %d); not enumerating, likely pid reuse",
				containerPID, expectedMntnsID, currentMntNs)
			return
		}
	}

	for _, path := range n.markExecHoldCandidatesInRoot(rootDir, expectedMntnsID) {
		log.Debugf("container-hook: exec-hold: marked %s in container pid %d", path, containerPID)
	}
}

// execHoldExecedPath returns the absolute path — as seen inside the container's
// own mount namespace — of the binary that process execPid is running.
//
// /proc/<pid>/exe is the only thing an exec event can be turned into a path
// with: the exec_events ringbuf record carries a mount namespace id and a tgid,
// nothing more (see struct exec_event in bpf/execruntime.bpf.c). The link is
// already fully dereferenced by the kernel, so no symlink of the container's
// choosing is followed here; the path is nevertheless re-resolved under the
// container root with the full hardening before anything is marked.
func execHoldExecedPath(execPid uint32) (string, error) {
	exe := filepath.Join(host.HostProcFs, strconv.Itoa(int(execPid)), "exe")
	path, err := os.Readlink(exe)
	if err != nil {
		return "", fmt.Errorf("readlink %q: %w", exe, err)
	}
	// A binary unlinked after exec reads back as "<path> (deleted)". There is
	// nothing at that path left to mark, and the suffix is indistinguishable
	// from a real filename ending in " (deleted)", so refuse both.
	if !filepath.IsAbs(path) || strings.HasSuffix(path, " (deleted)") {
		return "", fmt.Errorf("%q does not name a live absolute path: %q", exe, path)
	}
	return path, nil
}

// execHoldAllowlisted reports whether basename is on this notifier's exec-hold
// allowlist.
func (n *ContainerNotifier) execHoldAllowlisted(basename string) bool {
	for _, allowed := range n.execHoldBinaries {
		if allowed == basename {
			return true
		}
	}
	return false
}

// execHoldMarkExecedBinary installs an exec-hold mark on execedPath inside the
// container rootfs rootDir, for the container identified by mntnsID, and
// reports whether it installed one.
//
// This is the testable core of execHoldOnExec: it takes the rootfs and the
// exec'd path already resolved, exactly as markExecHoldCandidatesInRoot is the
// testable core of markExecHoldCandidates.
//
// Marks are deduplicated per (container mount namespace, resolved path) --
// NOT per (mount namespace, basename): a container can have two distinct
// allowlisted objects sharing one basename (e.g. /opt/a/foo and /opt/b/foo),
// and deduplicating by basename alone would record the first one seen and
// permanently skip marking the second. The kernel would fold a repeated
// FAN_MARK_ADD on the same inode into the existing mark anyway, so this set
// is about not paying for the resolution on every exec of a busy binary, not
// about correctness of the mark itself.
func (n *ContainerNotifier) execHoldMarkExecedBinary(mntnsID uint64, rootDir *os.File, execedPath string) bool {
	if n.execHoldNotify == nil || len(n.execHoldBinaries) == 0 {
		return false
	}

	if !n.execHoldAllowlisted(filepath.Base(execedPath)) {
		return false
	}

	// Held across the resolve-and-mark so a container cannot be marked twice
	// for one path by two execs observed concurrently. The only other holder
	// is execHoldForget on container termination, which just deletes.
	n.execHoldMarkedMu.Lock()
	defer n.execHoldMarkedMu.Unlock()

	if _, ok := n.execHoldMarked[mntnsID][execedPath]; ok {
		return false
	}

	root, err := execHoldStatObject(int(rootDir.Fd()))
	if err != nil {
		log.Debugf("container-hook: exec-hold: fstat of container rootfs for mntns %d: %s", mntnsID, err)
		return false
	}

	if err := n.markExecHoldPath(int(rootDir.Fd()), root, mntnsID, execedPath); err != nil {
		log.Debugf("container-hook: exec-hold: not marking exec'd %s in mntns %d: %s", execedPath, mntnsID, err)
		return false
	}

	if n.execHoldMarked == nil {
		n.execHoldMarked = make(map[uint64]map[string]struct{})
	}
	if n.execHoldMarked[mntnsID] == nil {
		n.execHoldMarked[mntnsID] = make(map[string]struct{})
	}
	n.execHoldMarked[mntnsID][execedPath] = struct{}{}

	return true
}

// execHoldOnExec marks an allowlisted binary that has just been exec'd inside a
// tracked container. It closes the gap left by the create-time enumeration
// (markExecHoldCandidates): a binary written into the rootfs after the
// container was created, or living outside execHoldSearchPaths, was never seen
// there and so carries no mark.
//
// It is driven by the existing per-execve exec_events stream (watchExecEvents),
// which is already scoped in-kernel to tracked containers; no new BPF program
// or ringbuf is involved.
//
// THIS exec is never held: by the time the tracepoint fired the execve has
// already succeeded, and nothing here blocks. The mark takes effect for every
// SUBSEQUENT exec of the same binary in that container.
func (n *ContainerNotifier) execHoldOnExec(mntnsID uint64, execPid uint32) {
	if n.execHoldNotify == nil || len(n.execHoldBinaries) == 0 {
		return
	}

	execedPath, err := execHoldExecedPath(execPid)
	if err != nil {
		log.Debugf("container-hook: exec-hold: resolving exec'd binary of pid %d: %s", execPid, err)
		return
	}
	// Checked before opening the container root so an exec of something not on
	// the allowlist — which is nearly every exec — costs one readlink and a
	// slice scan, nothing more.
	if !n.execHoldAllowlisted(filepath.Base(execedPath)) {
		return
	}

	// execPid was observed by watchExecEvents and handed to this worker
	// through execHoldOnExecCh, which can sit queued behind other tasks for an
	// unbounded amount of wall-clock time (it is bounded only in SIZE, not in
	// how long an admitted entry may wait -- see the channel's own doc
	// comment). If the process has since exited, the kernel is free to have
	// recycled execPid for an UNRELATED host process by the time this runs.
	// Re-validate that execPid still has the mount namespace the ORIGINAL
	// event actually carried before trusting /proc/<execPid>/root any
	// further: a mismatch means execPid no longer names the process this
	// event was about, and opening its root would resolve and potentially
	// mark an unrelated -- possibly HOST -- process's binary instead. This is
	// the same TOCTOU class markExecHoldCandidates's expectedMntnsID
	// revalidation closes for the create-time path; narrows rather than fully
	// closes the window (this is still a second, independent /proc/<pid>
	// read), same as that one.
	currentMntNs, err := containerutils.GetMntNs(int(execPid))
	if err != nil {
		log.Debugf("container-hook: exec-hold: checking mnt namespace of pid %d before marking: %s", execPid, err)
		return
	}
	if currentMntNs != mntnsID {
		log.Debugf("container-hook: exec-hold: pid %d no longer has the expected mount namespace (want %d, got %d); not marking, likely pid reuse",
			execPid, mntnsID, currentMntNs)
		return
	}

	// /proc/<pid>/root of the exec'ing process IS the container rootfs, and
	// unlike the container's init pid it is known to be alive right now.
	root := filepath.Join(host.HostProcFs, strconv.Itoa(int(execPid)), "root")
	rootDir, err := os.OpenFile(root, unix.O_PATH, 0)
	if err != nil {
		log.Debugf("container-hook: exec-hold: opening %q: %s", root, err)
		return
	}
	defer rootDir.Close()

	if n.execHoldMarkExecedBinary(mntnsID, rootDir, execedPath) {
		log.Debugf("container-hook: exec-hold: marked %s after first exec in mntns %d (pid %d)", execedPath, mntnsID, execPid)
	}
}

// execHoldForget drops the per-container first-exec mark bookkeeping when a
// container terminates, so the set cannot grow with the node's container
// churn, and releases every kernel mark and dispatcher hold-state this
// notifier installed for that container: the FAN_OPEN_EXEC_PERM marks
// markExecHoldCandidates (create-time enumeration) and
// execHoldMarkExecedBinary (first-exec) installed are otherwise never removed
// -- neither map they update represents them, so without this a marked
// binary that is never actually re-executed leaves its mark, its retained
// marking fd, and its dispatcher execHold.holds entry alive for this
// notifier's entire lifetime, growing with container churn and potentially
// gating a later, unrelated container's exec on a reused (dev, ino).
func (n *ContainerNotifier) execHoldForget(mntnsID uint64) {
	n.execHoldMarkedMu.Lock()
	delete(n.execHoldMarked, mntnsID)
	n.execHoldMarkedMu.Unlock()

	n.execHoldContainerMarksMu.Lock()
	marks := n.execHoldContainerMarks[mntnsID]
	delete(n.execHoldContainerMarks, mntnsID)
	n.execHoldContainerMarksMu.Unlock()

	// Unmark and drop dispatcher state off the lock above: these are
	// syscalls plus execHold.holdsMu, and execHoldContainerMarksMu must stay
	// free for markExecHoldPath's own (different-mntnsID) appends while this
	// runs. execHoldReleaseHeldMark pairs the removal syscall with the
	// holds-map deletion under execHold.holdsMu, same as execHoldSettle,
	// so this cannot interleave with a concurrent execHoldInstallMark for
	// the same key either.
	for _, m := range marks {
		key := m.key
		file := m.file
		n.execHoldReleaseHeldMark(key, func() {
			if err := n.execHoldNotify.Mark(unix.FAN_MARK_REMOVE, unix.FAN_OPEN_EXEC_PERM, int(file.Fd()), ""); err != nil {
				log.Debugf("container-hook: exec-hold: removing mark for %s (mntns %d, container terminated): %s", key, mntnsID, err)
			}
		})
		file.Close()
	}
}

// watchExecHold drains the exec-hold group.
//
// A FAN_OPEN_EXEC_PERM mark with no reader blocks the exec'ing process
// indefinitely, so this loop must exist for as long as anything is marked, and
// it must never spend time it does not have to: every decision that can be made
// off this goroutine is (see execHoldDispatchEvent), and watchExecHoldWatchdog
// closes the group if this loop stops making progress anyway.
func (n *ContainerNotifier) watchExecHold() {
	defer n.wg.Done()

	for {
		err := n.watchExecHoldIterate()
		if n.closed.Load() {
			return
		}
		if err != nil {
			log.Errorf("container-hook: exec-hold: watching marked binaries: %v", err)
			// A non-Close GetEvent error (anything reaching here: the
			// closed.Load() check above already returned on the expected
			// Close-triggered case) still leaves the group's marks in place
			// with this loop now gone -- the ONLY reader for it. Any
			// outstanding or future FAN_OPEN_EXEC_PERM event would then block
			// its process indefinitely with nothing to answer it, which is
			// exactly the hang watchExecHoldWatchdog exists to catch, except
			// the watchdog only trips on a STALLED iteration (busySince set),
			// never on the loop having exited cleanly. Close explicitly here,
			// same action watchExecHoldWatchdog takes on a stall: fanotify(7)
			// documents that closing a group's fd resolves every outstanding
			// permission event as allowed, so this fails open exactly like
			// every other exec-hold error path, rather than leaving the
			// group open with silent, permanent hangs waiting to happen.
			if n.execHoldNotify != nil {
				n.execHoldNotify.File.Close()
			}
			return
		}
	}
}

func (n *ContainerNotifier) watchExecHoldIterate() error {
	data, err := n.execHoldNotify.GetEvent()
	if err != nil {
		return err
	}
	if data == nil {
		return nil
	}

	// Everything from here to the return is what the watchdog considers one
	// iteration; waiting in GetEvent above is idle time and never trips it.
	n.execHold.busySince.Store(time.Now().UnixNano())
	defer n.execHold.busySince.Store(0)

	if !data.MatchMask(unix.FAN_OPEN_EXEC_PERM) {
		// This should not happen: FAN_OPEN_EXEC_PERM is the only mask Marked.
		// No response is written: a non-permission event has nothing to answer.
		log.Errorf("container-hook: exec-hold: unknown event: mask=%d pid=%d", data.Mask, data.Pid)
		data.Close()
		return nil
	}

	// The event fd is NOT closed here. Ownership passes to the ref's allow(),
	// which is called exactly once by whichever of the worker and its timeout
	// resolves the hold, and only after the response has been written: the
	// kernel matches a response by fd number, so closing first would answer a
	// number that may already have been reused.
	ref := execHoldEventRef{
		pid:    uint32(data.Pid),
		dup:    func() (*os.File, error) { return execHoldDupEventFile(data) },
		unmark: func() { n.execHoldUnmark(data) },
		allow: func() {
			if err := n.execHoldNotify.ResponseAllow(data); err != nil {
				log.Debugf("container-hook: exec-hold: allowing exec of pid %d: %s", data.Pid, err)
			}
			data.Close()
		},
	}

	// Cheap and lock-free, on the event's own fd: it is the fact the guard in
	// execHoldDispatchEvent needs, and an event we cannot even identify fails
	// open immediately.
	ref.key, err = execHoldKeyOfFd(int(data.Fd))
	if err != nil {
		log.Errorf("container-hook: exec-hold: identifying event for pid %d: %s", data.Pid, err)
		ref.allow()
		return nil
	}

	n.execHoldDispatchEvent(ref)
	return nil
}

// execHoldDupEventFile returns an independent open file for the binary an event
// refers to. Independent is the point: it stays valid after the event fd is
// closed, so a worker the timeout gave up on cannot end up operating on a
// recycled fd number.
func execHoldDupEventFile(data *fanotify.EventMetadata) (*os.File, error) {
	file := data.File()
	if file == nil {
		return nil, fmt.Errorf("duplicating fanotify event fd %d", data.Fd)
	}
	return file, nil
}

// execHoldUnmark removes the FAN_OPEN_EXEC_PERM mark on the object an event
// refers to, so a binary whose hold has resolved is not held again.
//
// It marks through the event's own fd (dirFd with an empty path, as
// markExecHoldPath does) rather than by path: the path is the container's to
// change, the fd is not.
func (n *ContainerNotifier) execHoldUnmark(data *fanotify.EventMetadata) {
	if err := n.execHoldNotify.Mark(unix.FAN_MARK_REMOVE, unix.FAN_OPEN_EXEC_PERM, int(data.Fd), ""); err != nil {
		log.Debugf("container-hook: exec-hold: removing mark for pid %d: %s", data.Pid, err)
	}
}
