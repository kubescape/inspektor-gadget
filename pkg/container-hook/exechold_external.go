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
	"os"
	"path/filepath"
	"strconv"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// ExecHoldMarkResult is the outcome of an externally requested exec-hold mark.
//
// Every value is a routine outcome, which is why MarkExecHoldCandidate returns
// no error: a caller driven by its own file-open stream races container
// lifecycle by construction, and "the container is gone" or "exec-hold is not
// enabled" must not read as a failure it should report or retry. The reasons a
// candidate was refused are logged at debug level by the shared marking path.
type ExecHoldMarkResult int

const (
	// ExecHoldMarkNotApplicable means there was nothing to do: exec-hold is not
	// enabled on this notifier, or the container is no longer reachable (it
	// exited, or its pid is not in this pid namespace). It is the zero value so
	// that a caller ignoring the result gets the routine, silent outcome.
	ExecHoldMarkNotApplicable ExecHoldMarkResult = iota

	// ExecHoldMarkNotAllowlisted means the path's basename is not on the
	// exec-hold allowlist. This is the cheap no-op case: it costs one slice scan
	// and nothing else — no openat2, no fstat, no fanotify call — which is what
	// makes the entry point safe to call on every file open a container does.
	ExecHoldMarkNotAllowlisted

	// ExecHoldMarkInstalled means a FAN_OPEN_EXEC_PERM mark was installed on the
	// object the path resolved to. Every SUBSEQUENT exec of it in that container
	// is held.
	ExecHoldMarkInstalled

	// ExecHoldMarkNotInstalled means the candidate was allowlisted and the
	// container was reachable, but no new mark resulted: either this
	// (container, basename) was already marked, or the openat2 RESOLVE_IN_ROOT /
	// st_dev hardening refused the candidate. The two are deliberately not
	// distinguished here, because neither is actionable by the caller and
	// telling them apart would mean duplicating the marking path rather than
	// reusing it.
	ExecHoldMarkNotInstalled
)

func (r ExecHoldMarkResult) String() string {
	switch r {
	case ExecHoldMarkNotApplicable:
		return "not-applicable"
	case ExecHoldMarkNotAllowlisted:
		return "not-allowlisted"
	case ExecHoldMarkInstalled:
		return "installed"
	case ExecHoldMarkNotInstalled:
		return "not-installed"
	}
	return "unknown"
}

// MarkExecHoldCandidate installs an exec-hold mark on candidatePath inside the
// container identified by mntnsID, whose rootfs is reached through containerPID.
// candidatePath is a path as seen INSIDE the container.
//
// It is the entry point for an EXTERNAL trigger — a consumer that observes
// container activity this package does not, typically a file-open stream — to
// pre-mark a binary BEFORE it is ever executed. The create-time enumeration
// (markExecHoldCandidates) only sees what already existed in the rootfs, and the
// first-exec path (execHoldOnExec) by definition arrives one exec too late for
// the binary's first run; a caller that watched the binary being written closes
// exactly that gap.
//
// The path itself is never trusted beyond its string form: it is resolved
// with the same openat2 RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS and st_dev
// controls as every other mark, through the same markExecHoldPath, and the
// allowlist is this notifier's own — the caller cannot widen it or name a host
// binary. containerPID and mntnsID ARE trusted to correspond to the same
// container by the caller (see the mount-namespace re-check below for why
// that is checked, not merely assumed): a caller racing its own event stream
// against container lifecycle could supply a stale containerPID for a given
// mntnsID after the container that pid belonged to exited and the pid was
// recycled by the kernel for an unrelated process.
//
// It is safe to call from any goroutine, concurrently with the notifier's own
// event loops: the resolve-and-mark runs under the same execHoldMarkedMu that
// the first-exec path takes, so the two cannot mark one (container, basename)
// twice or interleave with each other, and the dispatcher's hold-state is
// recorded before the mark by the shared path regardless of who called it.
func (n *ContainerNotifier) MarkExecHoldCandidate(mntnsID uint64, containerPID uint32, candidatePath string) ExecHoldMarkResult {
	if n == nil || n.execHoldNotify == nil || len(n.execHoldBinaries) == 0 || n.closed.Load() {
		return ExecHoldMarkNotApplicable
	}

	// A relative path has no meaning as a container-absolute path and openat2
	// would resolve it against the rootfs fd anyway, silently turning "foo" into
	// "/foo". Refuse it rather than mark something the caller did not name.
	if !filepath.IsAbs(candidatePath) {
		return ExecHoldMarkNotApplicable
	}

	// Checked before anything is opened, so a path that is not an exec-hold
	// candidate — which is nearly every file a container writes — costs one
	// slice scan.
	if !n.execHoldAllowlisted(filepath.Base(candidatePath)) {
		return ExecHoldMarkNotAllowlisted
	}

	// /proc/<pid>/root is how this package reaches a container's filesystem from
	// the host. Failing to open it is the expected outcome for a container that
	// exited between the caller observing the write and calling here, so it is a
	// not-applicable result rather than an error.
	root := filepath.Join(host.HostProcFs, strconv.Itoa(int(containerPID)), "root")
	rootDir, err := os.OpenFile(root, unix.O_PATH, 0)
	if err != nil {
		log.Debugf("container-hook: exec-hold: external mark: opening %q: %s", root, err)
		return ExecHoldMarkNotApplicable
	}
	defer rootDir.Close()

	// Re-check that containerPID still has the mntnsID the caller supplied
	// for it, narrowing (a second, independent /proc/<pid> read cannot
	// atomically tie itself to the already-open rootDir fd above, so this is
	// not a full close of the window) the pid-reuse race described on this
	// function's doc comment. Without this, execHoldMarkExecedBinary would
	// mark whatever process containerPID now names against the WRONG
	// mntnsID's dedup bookkeeping (n.execHoldMarked[mntnsID]) -- marking the
	// wrong process's binary while permanently desyncing that dedup entry
	// from what was actually marked on disk.
	currentMntNs, err := containerutils.GetMntNs(int(containerPID))
	if err != nil {
		log.Debugf("container-hook: exec-hold: external mark: checking mnt namespace of pid %d: %s", containerPID, err)
		return ExecHoldMarkNotApplicable
	}
	if currentMntNs != mntnsID {
		log.Debugf("container-hook: exec-hold: external mark: pid %d no longer has the expected mount namespace (want %d, got %d); not marking, likely pid reuse",
			containerPID, mntnsID, currentMntNs)
		return ExecHoldMarkNotApplicable
	}

	if n.execHoldMarkExecedBinary(mntnsID, rootDir, candidatePath) {
		log.Debugf("container-hook: exec-hold: marked %s in mntns %d on external request", candidatePath, mntnsID)
		return ExecHoldMarkInstalled
	}
	return ExecHoldMarkNotInstalled
}
