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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// execHoldTrustedCrossDeviceMounts is the operator-configurable set of
// CONTAINER-ABSOLUTE mount paths whose filesystem may be marked even though it
// is not the container rootfs device. Empty by default.
//
// SECURITY: the anchor is resolved through the CONTAINER's mount table, so a
// workload able to mount a host path AT a declared path obtains the exemption.
// The node-root-device refusal removes the common form ON SINGLE-ROOT NODE
// IMAGES ONLY (not Flatcar/Bottlerocket/Talos split-/usr, not a separate
// /var); the rest is bounded by cluster pod-admission policy and by the
// declared mount's StorageClass. See the feature's operator documentation.
var execHoldTrustedCrossDeviceMounts []string

// execHoldStatDevOfPath is the real statDev injected into
// execHoldDeriveNodeRootDevice. Follows symlinks deliberately: the paths it is
// given (HostProcFs/1/root, HOST_ROOT) are host-supplied, not container
// content, and /proc/1/root is a magic link that must be followed to mean
// anything at all.
func execHoldStatDevOfPath(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil
}

// execHoldSelfMntNs reads THIS process's mount namespace id from
// /proc/self/ns/mnt.
//
// Deliberately NOT containerutils.GetMntNs(os.Getpid()): that resolves through
// host.HostProcFs, so by pid number it reads our own process only under
// hostPID -- the one case this check was already going to get right -- and
// reads whatever unrelated host process carries our container-local pid number
// otherwise. /proc/self is resolved by the kernel against the CALLING process
// regardless of pid namespace or procfs mount, so it is the comparison the
// self-check actually intends.
func execHoldSelfMntNs() (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/mnt", &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// execHoldDeriveNodeRootDevice is the whole node-root-device decision table as
// a PURE function: no sync.Once, every input injected, so the table can be
// driven deterministically in any order.
//
// Primary source: filepath.Join(host.HostProcFs, "1", "root"). Under
// hostPID: true -- which the node-agent DaemonSet sets -- pid 1 is the node's
// init and its root is the node's /. The decisive advantage over host.HostRoot
// is that exec-hold ALREADY stakes its correctness on HostProcFs (every mark
// route resolves container roots through it), so this introduces no new
// environment dependency and no new failure mode.
//
// Self-check: pid 1's root is only informative if pid 1 is OUTSIDE our own
// mount namespace. If the two mount namespaces are equal then /proc/1/root IS
// our own root by definition, and the derivation tells us nothing we did not
// already know -- the fail-open shape this self-check exists to catch.
//
//	pid1 vs self mntns | HOST_ROOT | result
//	-------------------+-----------+---------------------------------------
//	differ             | anything  | stat(HostProcFs/1/root) -> KNOWN (1)
//	same               | set       | stat(hostRoot)          -> KNOWN (2)
//	same               | unset     | UNKNOWN, fail closed
//	any                | any       | any error               -> UNKNOWN
//
// (1) assumes pid 1 is the node's init. That holds under hostPID: true and
// fails under pod-level shareProcessNamespace: true (without hostPID), where
// pid 1 is the pause container. Kubernetes forbids the two together and the
// shipped DaemonSet sets hostPID: true, so this is excluded in practice; the
// published device in the startup line plus the live-fire `stat -c %d /`
// cross-check are the safety net if a custom manifest ever reaches it.
//
// (2) takes an operator assertion at face value, and is re-enterable into the
// same fail-open shape by an explicit HOST_ROOT=/ in a containerized
// deployment WITHOUT hostPID: stat("/") then returns the agent container's own
// overlay device and the derivation is confidently wrong. That residual is
// pinned by TestExecHoldResolveTrustedAnchorsAcceptsNodeRootAnchorWhenDeviceIsMisderived;
// the defense is the same as row 1's -- publication and the live-fire
// cross-check.
//
// ANY error (nsErr non-nil, or statDev failing) yields known == false: an
// undefined branch in a security control is not acceptable in a design whose
// posture is explicit fail-closed.
func execHoldDeriveNodeRootDevice(
	pid1MntNs, selfMntNs uint64,
	nsErr error,
	hostRoot string, hostRootSet bool,
	statDev func(string) (uint64, error),
) (dev uint64, known bool) {
	if nsErr != nil {
		return 0, false
	}
	if pid1MntNs != selfMntNs {
		dev, err := statDev(filepath.Join(host.HostProcFs, "1", "root"))
		if err != nil {
			return 0, false
		}
		return dev, true
	}
	if !hostRootSet {
		return 0, false
	}
	dev, err := statDev(hostRoot)
	if err != nil {
		return 0, false
	}
	return dev, true
}

var (
	execHoldNodeRootDevOnce  sync.Once
	execHoldNodeRootDevValue uint64
	execHoldNodeRootDevKnown bool
)

// execHoldNodeRootDevice reads the real inputs, delegates to the pure
// execHoldDeriveNodeRootDevice above, memoizes for the process and emits the
// single failure Error.
//
// The sync.Once has two real jobs: the Error fires once rather than once per
// container create (execHoldResolveTrustedAnchors runs per enumeration), and
// the setter's startup log and the notifier's snapshot can never disagree.
func execHoldNodeRootDevice() (uint64, bool) {
	execHoldNodeRootDevOnce.Do(func() {
		pid1MntNs, nsErr := containerutils.GetMntNs(1)
		var selfMntNs uint64
		if nsErr == nil {
			selfMntNs, nsErr = execHoldSelfMntNs()
		}
		hostRoot, hostRootSet := os.LookupEnv("HOST_ROOT")

		// The failing path and error are captured here rather than returned by
		// the pure function, so the single Error below can name WHICH input
		// produced "unknown": the remedy differs per cause (add hostPID: true,
		// fix the /host mount, or unset a bogus HOST_ROOT).
		var statErrPath string
		var statErr error
		statDev := func(path string) (uint64, error) {
			dev, err := execHoldStatDevOfPath(path)
			if err != nil {
				statErrPath, statErr = path, err
			}
			return dev, err
		}

		execHoldNodeRootDevValue, execHoldNodeRootDevKnown = execHoldDeriveNodeRootDevice(
			pid1MntNs, selfMntNs, nsErr, hostRoot, hostRootSet, statDev)
		if execHoldNodeRootDevKnown {
			return
		}

		var cause string
		switch {
		case nsErr != nil:
			// Note the non-obvious remedy in the third case: hostPID: true plus
			// a bogus HOST_ROOT poisons HostProcFs, so GetMntNs(1) fails even
			// though plain /proc/1 would have derived correctly.
			cause = fmt.Sprintf("the mount-namespace self-check failed (%s); pid 1 is read through %q, so check hostPID: true, the HOST_ROOT mount, or an unnecessary HOST_ROOT setting",
				nsErr, host.HostProcFs)
		case statErr != nil:
			cause = fmt.Sprintf("stat of %q failed (%s)", statErrPath, statErr)
		default:
			cause = "pid 1 shares this process's mount namespace and HOST_ROOT is unset, so /proc/1/root is our own root and says nothing about the node; set hostPID: true, or set HOST_ROOT to the node's root"
		}
		log.Errorf("container-hook: exec-hold: node root device unknown -- ALL trusted cross-device exemptions will be refused: %s", cause)
	})
	return execHoldNodeRootDevValue, execHoldNodeRootDevKnown
}

// SetExecHoldTrustedCrossDeviceMounts sets the trusted cross-device mount list.
// Same timing contract as SetExecHoldBinaries: call it before
// NewContainerNotifier. Clones for the same reason SetExecHoldBinaries does.
//
// DELIBERATELY unlike SetExecHoldBinaries, which is a pure sink:
//   - the whole list is DROPPED with an Error unless acknowledged is true (the
//     operator must assert they read the prerequisites);
//   - entries that are empty, relative, or resolve to "/" are DROPPED with a
//     Warn ("/" would silently disable the control this list excepts);
//   - entries that are or contain an execHoldSearchPaths entry, and depth-1
//     entries such as "/data", are ACCEPTED with a Warn (high blast radius).
//
// Because dropping can otherwise leave a misconfiguration silent, this ALSO
// logs at Info the accepted list, the drop count, AND the derived node root
// device (or "unknown"), so "is this armed, with what, and against which host
// anchor" is answerable without a successful mark.
func SetExecHoldTrustedCrossDeviceMounts(paths []string, acknowledged bool) {
	if len(paths) == 0 {
		// Nothing was configured, so there is nothing to arm, nothing to log,
		// and no reason to force the node-root-device derivation (and its
		// possible Error) on a deployment that never asked for the feature.
		execHoldTrustedCrossDeviceMounts = nil
		return
	}

	dropped := 0
	if !acknowledged {
		log.Errorf("container-hook: exec-hold: %d trusted cross-device mount(s) configured without execHoldTrustedCrossDeviceMountsAcknowledgeRisk; dropping the whole list. Declaring a trusted cross-device mount extends marking to whatever mount appears at that path inside a container: enable it only where pod admission prevents untrusted workloads from mounting host paths AND the declared mount is backed by a network or block CSI volume.",
			len(paths))
		dropped = len(paths)
		paths = nil
	}

	var accepted []string
	for _, p := range paths {
		clean := filepath.Clean(p)
		if p == "" || !filepath.IsAbs(clean) || clean == "/" {
			log.Warnf("container-hook: exec-hold: dropping unsafe trusted cross-device mount %q: entries must be absolute container paths other than %q", p, "/")
			dropped++
			continue
		}

		var reasons []string
		for _, sp := range execHoldSearchPaths {
			if clean == sp || strings.HasPrefix(sp, clean+"/") || strings.HasPrefix(clean, sp+"/") {
				reasons = append(reasons, fmt.Sprintf("it is or contains the default search path %q", sp))
				break
			}
		}
		if strings.Count(clean, "/") == 1 {
			reasons = append(reasons, "it is a top-level path, which any container can collide with")
		}
		if len(reasons) > 0 {
			log.Warnf("container-hook: exec-hold: trusted cross-device mount %q has a high blast radius (%s); prefer a more specific path", clean, strings.Join(reasons, "; "))
		}
		accepted = append(accepted, clean)
	}

	execHoldTrustedCrossDeviceMounts = accepted

	if dev, known := execHoldNodeRootDevice(); known {
		log.Infof("container-hook: exec-hold: trusted cross-device mounts armed: %q (node root device %d) (%d entries dropped as unsafe)", accepted, dev, dropped)
	} else {
		log.Infof("container-hook: exec-hold: trusted cross-device mounts armed: %q (node root device unknown -- ALL exemptions refused) (%d entries dropped as unsafe)", accepted, dropped)
	}
}

// execHoldTrustedAnchor is a declared trusted mount, resolved ONCE per
// enumeration against a container's rootFd, with its fd held open for the
// batch so the mount cannot be swapped underneath it.
type execHoldTrustedAnchor struct {
	path string
	id   execHoldRootIdentity
	file *os.File // O_PATH, held open for the batch
}

// execHoldResolveTrustedAnchors resolves this notifier's declared trusted
// mounts against rootFd, once per enumeration. The returned anchors' fds are
// held open for the whole batch and must be released with
// execHoldCloseTrustedAnchors.
func (n *ContainerNotifier) execHoldResolveTrustedAnchors(rootFd int) []execHoldTrustedAnchor {
	if len(n.execHoldTrustedMounts) == 0 {
		return nil
	}
	if !n.execHoldNodeRootDevValid {
		// Fail closed: without a KNOWN node root device there is no host-pinned
		// conjunct left, and an unverified exemption is worse than none. No log
		// here -- execHoldNodeRootDevice() already emitted one Error under its
		// sync.Once, while this runs once per container create.
		return nil
	}

	var anchors []execHoldTrustedAnchor
	for _, p := range n.execHoldTrustedMounts { // already cleaned/validated by the setter
		// RESOLVE_NO_SYMLINKS is what makes the declared path an UNFORGEABLE
		// selector: without it a symlink at /home/coder pointing at
		// /mnt/hostroot would make that mount the anchor under a declaration
		// written for /home/coder, i.e. container content redirecting the
		// operator's intent. A Kubernetes mountPath is always a real directory,
		// so the legitimate cost is zero.
		how := unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_DIRECTORY,
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		}
		fd, err := unix.Openat2(rootFd, p, &how)
		if err != nil {
			// ENOENT is the expected, high-volume "not present in THIS
			// container" case. Anything else -- ELOOP (symlinked path), ENOTDIR
			// (not a directory) -- is always misconfiguration, never "not
			// here", and would otherwise be as silently inert as a dropped
			// entry.
			if errors.Is(err, unix.ENOENT) {
				log.Debugf("container-hook: exec-hold: trusted mount %q not present in this container", p)
			} else {
				log.Warnf("container-hook: exec-hold: trusted mount %q could not be resolved (%s); this declaration will never take effect", p, err)
			}
			continue
		}
		file := os.NewFile(uintptr(fd), p)
		id, err := execHoldStatObject(fd)
		if err != nil {
			log.Warnf("container-hook: exec-hold: identifying trusted mount %q: %s", p, err)
			file.Close()
			continue
		}
		if id.dev == n.execHoldNodeRootDev {
			// The one conjunct the container cannot forge: an anchor on the
			// NODE's root filesystem is a host path, whatever the pod spec
			// called it. Warn, not Debug: this is either an attack or a
			// declaration that will never work. NOTE this covers /usr, /bin and
			// /etc only on single-root node images -- not Flatcar, Bottlerocket
			// or Talos (split /usr), and not a node with a separate /var.
			log.Warnf("container-hook: exec-hold: trusted mount %q resolves to the node root device %d; refusing the exemption", p, id.dev)
			file.Close()
			continue
		}
		anchors = append(anchors, execHoldTrustedAnchor{path: p, id: id, file: file})
	}
	return anchors
}

// execHoldCloseTrustedAnchors releases the fds execHoldResolveTrustedAnchors
// held open for a batch.
func execHoldCloseTrustedAnchors(anchors []execHoldTrustedAnchor) {
	for _, a := range anchors {
		a.file.Close()
	}
}

// execHoldMatchTrustedAnchor reports the anchor whose declared path is
// unsafePath itself or a parent directory of it. First match wins.
//
// A pure string match: the identity comparison that actually gates the mark is
// execHoldOpenCandidate's, not this. See that function's comment for why the
// string's influence is monotone.
func execHoldMatchTrustedAnchor(anchors []execHoldTrustedAnchor, unsafePath string) (execHoldTrustedAnchor, bool) {
	clean := filepath.Clean(unsafePath)
	for _, a := range anchors {
		if clean == a.path || strings.HasPrefix(clean, a.path+"/") {
			return a, true
		}
	}
	return execHoldTrustedAnchor{}, false
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
//
// anchors are the operator-declared trusted cross-device mounts already
// resolved for this enumeration (see execHoldResolveTrustedAnchors). The
// returned string names the anchor a cross-device candidate was accepted
// through, or "" when no exemption was used.
func execHoldOpenCandidate(rootFd int, root execHoldRootIdentity, anchors []execHoldTrustedAnchor, unsafePath string) (*os.File, string, error) {
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
		return nil, "", fmt.Errorf("openat2 %q in container rootfs: %w", unsafePath, err)
	}
	pathFile := os.NewFile(uintptr(pathFd), unsafePath)
	defer pathFile.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(pathFd, &stat); err != nil {
		return nil, "", fmt.Errorf("fstat %q in container rootfs: %w", unsafePath, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, "", fmt.Errorf("%q in container rootfs is not a regular file: expected %d, got %d",
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
	//
	// An operator may declare container-absolute mount paths trusted for
	// cross-device marking. Be precise about what that buys:
	//
	//   - A mount landing UNDER a declared path is still refused: different
	//     mntID than the anchor. Retargeted here, and genuinely holds
	//     (kernels >= 5.8 only).
	//   - A mount landing AT the declared path IS the anchor, so the control
	//     is genuinely WAIVED there. What remains is the node-root-device
	//     refusal in execHoldResolveTrustedAnchors (host-pinned, unforgeable
	//     by the container, but see its own comment for which node images it
	//     actually covers), the AND with the basename allowlist, and the
	//     cluster's pod-admission policy and StorageClass choice. This is the
	//     accepted contract; see the feature docs.
	//
	// anchors are resolved ONCE per enumeration with their fds held open, the
	// same way root is, so a container remounting mid-batch cannot present
	// different anchors to different candidates. Nothing below performs a new
	// PATH RESOLUTION; the one identity read (execHoldStatObject of the
	// already-open candidate fd) is the same read the rootfs branch performs.
	//
	// The declared path is matched against unsafePath as a STRING, and that
	// string's influence is monotone: it can only fail to select an anchor, or
	// select one whose identity then mismatches -- never widen acceptance.
	// (unsafePath's three sources: filepath.Join of a search path and an
	// allowlisted basename; readlink /proc/<pid>/exe, kernel-resolved and
	// absolute; an absolute caller-supplied path via MarkExecHoldCandidate.)
	// A future refactor must preserve that property.
	//
	// Related asymmetry, safe in both directions: the path is matched as a
	// string while pathFd is the independently resolved object. So an
	// allowlisted binary reached via an in-root symlink from /usr/bin onto the
	// trusted mount is refused (the string does not match -- a functional
	// surprise, but safe), and a symlink from UNDER the trusted prefix onto a
	// different cross-device mount is refused on identity.
	var viaTrustedMount string
	if uint64(stat.Dev) != root.dev {
		anchor, ok := execHoldMatchTrustedAnchor(anchors, unsafePath)
		if !ok {
			return nil, "", fmt.Errorf("%q in container rootfs is on device %d, not the rootfs device %d: refusing to mark",
				unsafePath, uint64(stat.Dev), root.dev)
		}
		// Fails CLOSED, deliberately unlike the rootfs mntID branch below,
		// which fails open on the same error. Closed is the better posture; the
		// rootfs branch is not changed here because that would alter default
		// behavior. Tracked as a follow-up on PR #5.
		candID, err := execHoldStatObject(pathFd)
		if err != nil {
			return nil, "", fmt.Errorf("identifying %q against trusted mount %q: %w", unsafePath, anchor.path, err)
		}
		if candID.dev != anchor.id.dev {
			return nil, "", fmt.Errorf("%q is on device %d, but trusted mount %q is on device %d: refusing to mark",
				unsafePath, candID.dev, anchor.path, anchor.id.dev)
		}
		// Mount identity, retargeted from the rootfs mount to the anchor.
		// Both-invalid is a pre-5.8 kernel and degrades to the device
		// comparison above, the same posture the rootfs path already accepts.
		// A mixed result cannot occur for two real fds on one kernel, so it is
		// not special-cased.
		if anchor.id.mntIDValid && candID.mntIDValid && candID.mntID != anchor.id.mntID {
			return nil, "", fmt.Errorf("%q is on mount %d, not trusted mount %q's mount %d: refusing to mark (bind mount under a trusted mount)",
				unsafePath, candID.mntID, anchor.path, anchor.id.mntID)
		}
		viaTrustedMount = anchor.path
	} else if root.mntIDValid {
		// st_dev alone is not enough: a bind mount of a HOST path that happens
		// to live on the SAME filesystem as the rootfs (a same-device bind
		// mount, e.g. bind-mounting another directory from the node's root
		// filesystem into the container) carries the same st_dev and passes the
		// check above untouched, even though the candidate is not actually part
		// of the container's own rootfs mount. Comparing the candidate's mount
		// identity against the rootfs's closes that gap; see execHoldStatObject
		// for why this is kernel-version-gated (pre-5.8: mntIDValid is false and
		// this check is skipped, same posture as before this hardening existed).
		candID, err := execHoldStatObject(pathFd)
		if err == nil && candID.mntIDValid && candID.mntID != root.mntID {
			// A trusted cross-device declaration cannot reach this branch --
			// it is only consulted for a candidate that IS cross-device -- so
			// an operator who declared a same-device mount would otherwise be
			// sent chasing a bind mount they did not create.
			hint := ""
			if _, matched := execHoldMatchTrustedAnchor(anchors, unsafePath); matched {
				hint = " (a trusted cross-device declaration does not apply to a same-device mount)"
			}
			return nil, "", fmt.Errorf("%q in container rootfs is on mount %d, not the rootfs mount %d: refusing to mark (bind mount)%s",
				unsafePath, candID.mntID, root.mntID, hint)
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
		return nil, "", fmt.Errorf("re-opening validated candidate %q for marking: %w", unsafePath, err)
	}
	return os.NewFile(uintptr(fd), unsafePath), viaTrustedMount, nil
}

// execHoldMark issues a fanotify_mark(2) call against execHoldNotify,
// synchronized against Close via execHoldNotifyMu (see its own doc comment).
// Every ADD or REMOVE this notifier performs -- from markExecHoldPath's
// install, execHoldUnmark's per-event removal, or execHoldForget's
// container-termination cleanup -- goes through here rather than calling
// n.execHoldNotify.Mark directly, so none of them can ever race Close()
// closing (and the OS potentially reusing) the group's fd.
func (n *ContainerNotifier) execHoldMark(flags uint, mask uint64, dirFd int, path string) error {
	n.execHoldNotifyMu.RLock()
	defer n.execHoldNotifyMu.RUnlock()
	if n.closed.Load() {
		return errors.New("container-hook: exec-hold: notifier is closed")
	}
	return n.execHoldNotify.Mark(flags, mask, dirFd, path)
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

// execHoldCandidateInstall pairs a successfully installed mark with the path
// it was installed for, so execHoldEndInstall can roll back (or record into
// execHoldMarked) exactly the right entries -- see markExecHoldCandidatesInRoot
// and execHoldMarkExecedBinary, the two callers.
type execHoldCandidateInstall struct {
	path string
	mark execHoldMarkedFile
}

// execHoldBeginInstall records that a markExecHoldPath install (or batch of
// them, for the whole create-time enumeration) for mntnsID is starting, and
// returns the CURRENT forget-epoch for mntnsID -- the snapshot
// execHoldEndInstall later compares against to detect whether execHoldForget
// ran for mntnsID at any point during this window. Paired with
// execHoldEndInstall; see ContainerNotifier's own doc comment on
// execHoldForgetEpoch/execHoldInstallsInFlight for why this exists.
func (n *ContainerNotifier) execHoldBeginInstall(mntnsID uint64) uint64 {
	n.execHoldContainerMarksMu.Lock()
	defer n.execHoldContainerMarksMu.Unlock()
	if n.execHoldInstallsInFlight == nil {
		n.execHoldInstallsInFlight = make(map[uint64]int)
	}
	n.execHoldInstallsInFlight[mntnsID]++
	return n.execHoldForgetEpoch[mntnsID] // zero-value map miss == epoch 0, a valid baseline
}

// execHoldEndInstall closes the in-flight window execHoldBeginInstall opened
// for mntnsID. installed is exactly the set of marks THIS caller's
// markExecHoldPath calls contributed during the window -- each one already
// individually, immediately visible via execHoldContainerMarks the moment it
// was installed (see markExecHoldPath), so cross-container ownership
// (execHoldKeyStillOwned) sees it right away, not just at the end of a whole
// enumeration.
//
// If execHoldForget ran for mntnsID at any point during this window
// (detected via the epoch snapshotted at Begin no longer matching), this
// call rolls back exactly ITS OWN contributions -- removing them from
// execHoldContainerMarks and releasing them -- rather than leaving them as
// orphans forget already looked for and did not find. Rollback only
// releases entries STILL PRESENT in execHoldContainerMarks[mntnsID] at this
// point: forget's own normal removal loop may already have released some of
// this same batch's earlier entries (if forget landed mid-batch, after some
// candidates published but before others), and releasing those again would
// double-Close/double-unmark them.
//
// callerHoldsMarkedMu: true when the caller (execHoldMarkExecedBinary)
// already holds execHoldMarkedMu via its own outer defer across its whole
// body -- this must NOT re-acquire it then (sync.Mutex is not reentrant).
// false when the caller (markExecHoldCandidatesInRoot) does not hold it, in
// which case this takes/releases it itself for the execHoldMarked
// write/delete below, AFTER releasing execHoldContainerMarksMu. That
// ordering leaves one narrow, accepted residual: a forget landing in the
// gap between this call releasing execHoldContainerMarksMu and (re)acquiring
// execHoldMarkedMu can leave a stale execHoldMarked dedup-cache entry (a few
// bytes, one map key) for an already-forgotten mntnsID. Closing it fully
// would require either nesting execHoldMarkedMu inside execHoldContainerMarksMu
// here -- which would deadlock against execHoldMarkExecedBinary's existing
// OPPOSITE nesting (execHoldMarkedMu outer) -- or holding execHoldMarkedMu
// externally across the whole enumeration's syscalls, serializing every
// OTHER container's first-exec marking against it for that duration. Both
// are worse than the bug: the kernel mark, fd and dispatcher hold-state --
// the actual leak this function exists to prevent -- are NOT affected by
// this residual; a stale execHoldMarked entry only risks skipping a
// re-resolve, and even then only in the compound, narrow case of mntnsID
// reuse landing on a coincidentally-matching inode, self-correcting via the
// cheap-stat comparison in execHoldMarkExecedBinary otherwise.
func (n *ContainerNotifier) execHoldEndInstall(mntnsID uint64, startEpoch uint64, installed []execHoldCandidateInstall, callerHoldsMarkedMu bool) (published bool) {
	n.execHoldContainerMarksMu.Lock()
	n.execHoldInstallsInFlight[mntnsID]--
	lastOut := n.execHoldInstallsInFlight[mntnsID] <= 0
	if lastOut {
		delete(n.execHoldInstallsInFlight, mntnsID)
	}
	forgotten := n.execHoldForgetEpoch[mntnsID] != startEpoch

	var toRelease []execHoldCandidateInstall
	if forgotten && len(installed) > 0 {
		installedByFile := make(map[*os.File]execHoldCandidateInstall, len(installed))
		for _, ci := range installed {
			installedByFile[ci.mark.file] = ci
		}
		// Fresh slice, not an in-place filter over the same backing array
		// being ranged: that would alias and corrupt not-yet-visited
		// elements while writing already-visited ones.
		var remaining []execHoldMarkedFile
		for _, m := range n.execHoldContainerMarks[mntnsID] {
			if ci, ours := installedByFile[m.file]; ours {
				toRelease = append(toRelease, ci) // still present -- genuinely ours to roll back
				continue
			}
			remaining = append(remaining, m)
		}
		if len(remaining) == 0 {
			delete(n.execHoldContainerMarks, mntnsID)
		} else {
			n.execHoldContainerMarks[mntnsID] = remaining
		}
	}
	if lastOut {
		delete(n.execHoldForgetEpoch, mntnsID)
	}
	n.execHoldContainerMarksMu.Unlock()

	markedMu := func(fn func()) {
		if callerHoldsMarkedMu {
			fn()
			return
		}
		n.execHoldMarkedMu.Lock()
		fn()
		n.execHoldMarkedMu.Unlock()
	}

	published = !forgotten && len(installed) > 0
	if published {
		markedMu(func() {
			if n.execHoldMarked == nil {
				n.execHoldMarked = make(map[uint64]map[string]execHoldKey)
			}
			if n.execHoldMarked[mntnsID] == nil {
				n.execHoldMarked[mntnsID] = make(map[string]execHoldKey)
			}
			for _, ci := range installed {
				n.execHoldMarked[mntnsID][ci.path] = ci.mark.key
			}
		})
		return published
	}

	if len(toRelease) > 0 {
		for _, ci := range toRelease {
			n.execHoldReleaseOneMark(mntnsID, ci.mark)
		}
		markedMu(func() {
			if inner, ok := n.execHoldMarked[mntnsID]; ok {
				for _, ci := range toRelease {
					delete(inner, ci.path)
				}
			}
		})
	}
	return published
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
//
// Returns the installed execHoldMarkedFile (not just its key): callers wrap
// this in execHoldBeginInstall/execHoldEndInstall (see their own doc
// comments), which needs the retained file to roll a mark back if
// execHoldForget ran for mntnsID while this call -- or a sibling call in the
// same batch -- was still in flight. The append into execHoldContainerMarks
// below happens immediately, not deferred to that later rollback decision:
// execHoldKeyStillOwned (consulted by execHoldSettle and by OTHER
// containers' execHoldForget) must see this mark within microseconds, not
// for the duration of a whole enumeration, or a sibling container settling a
// shared-inode hold could strip protection this call is still installing.
func (n *ContainerNotifier) markExecHoldPath(rootFd int, root execHoldRootIdentity, anchors []execHoldTrustedAnchor, mntnsID uint64, candidatePath string) (execHoldMarkedFile, error) {
	file, viaTrustedMount, err := execHoldOpenCandidate(rootFd, root, anchors, candidatePath)
	if err != nil {
		return execHoldMarkedFile{}, err
	}

	// The dispatcher's hold-state is keyed on the object's (dev, ino), which is
	// read from the very fd about to be marked, so the state and the mark can
	// never describe different objects.
	key, err := execHoldKeyOfFd(int(file.Fd()))
	if err != nil {
		file.Close()
		return execHoldMarkedFile{}, fmt.Errorf("identifying %q for marking: %w", candidatePath, err)
	}

	// Mark the ALREADY-OPEN, already-validated fd: passing it as dirFd
	// together with an EMPTY path forwards a NULL pathname to fanotify_mark,
	// so the kernel marks this exact object instead of resolving the path a
	// second time, which is a window the container could use to swap the
	// target between validation and mark.
	err = n.execHoldInstallMark(key, func() error {
		return n.execHoldMark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, int(file.Fd()), "")
	})
	if err != nil {
		file.Close()
		return execHoldMarkedFile{}, fmt.Errorf("marking %q: %w", candidatePath, err)
	}

	if viaTrustedMount != "" {
		// Info, deliberately unlike every other exec-hold mark log (Debug):
		// this records a security-relevant exception to the rootfs-device
		// control and must be auditable without fleet-wide debug logging. Note
		// this is a library path other consumers embed, so the unconditional
		// Info is a deliberate choice; the volume is bounded by one line per
		// (container, marked path) at container-create rate.
		n.execHold.trustedCrossDeviceExceptions.Add(1)
		log.Infof("container-hook: exec-hold: marked %s in mntns %d via trusted cross-device mount %q (device %d) -- operator-declared exception to the rootfs-device control",
			candidatePath, mntnsID, viaTrustedMount, key.dev)
	}

	m := execHoldMarkedFile{key: key, file: file}
	if mntnsID == 0 {
		file.Close()
		return m, nil
	}
	n.execHoldContainerMarksMu.Lock()
	if n.execHoldContainerMarks == nil {
		n.execHoldContainerMarks = make(map[uint64][]execHoldMarkedFile)
	}
	n.execHoldContainerMarks[mntnsID] = append(n.execHoldContainerMarks[mntnsID], m)
	n.execHoldContainerMarksMu.Unlock()

	return m, nil
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

	// Once per enumeration, not once per candidate, with the fds held open for
	// the batch: a container remounting mid-enumeration cannot present
	// different anchors to different candidates.
	anchors := n.execHoldResolveTrustedAnchors(int(rootDir.Fd()))
	defer execHoldCloseTrustedAnchors(anchors)

	var marked []string
	var installed []execHoldCandidateInstall

	// Begin/End bracket the WHOLE enumeration below, not each individual
	// markExecHoldPath call: an earlier version of this bracketing scoped it
	// per-candidate, which let a forget landing between candidate i and i+1
	// clear its own signal before i+1 even started, letting i+1 publish into
	// an already-forgotten mntnsID -- reproducing the exact race this exists
	// to close. Deferred so End always runs even on an early return (there
	// is none today, but this makes that safe if one is added later) and so
	// the in-flight/epoch bookkeeping in execHoldInstallsInFlight/
	// execHoldForgetEpoch never outlives the call that created it.
	var startEpoch uint64
	if mntnsID != 0 {
		startEpoch = n.execHoldBeginInstall(mntnsID)
	}
	defer func() {
		if mntnsID != 0 {
			n.execHoldEndInstall(mntnsID, startEpoch, installed, false)
		}
	}()

	for _, basename := range n.execHoldBinaries {
		for _, dir := range execHoldSearchPaths {
			candidatePath := filepath.Join(dir, basename)

			m, err := n.markExecHoldPath(int(rootDir.Fd()), root, anchors, mntnsID, candidatePath)
			if err != nil {
				// Expected for every search path the binary is not in, so this
				// stays at debug level: the rejection cases are logged by the
				// error text they carry.
				log.Debugf("container-hook: exec-hold: not marking %s: %s", candidatePath, err)
				continue
			}

			// execHoldMarked -- the first-exec dedup cache -- is populated by
			// the deferred execHoldEndInstall call above, not here: a binary
			// already present at container create time still needs an entry
			// there (without one, its actual first exec would ALWAYS miss
			// execHoldMarkExecedBinary's dedup lookup and pay a second,
			// redundant FAN_MARK_ADD, holds increment, and retained fd for
			// the identical object), but recording it must go through the
			// same forget-epoch check as the kernel mark itself, or a forget
			// landing after this specific write could resurrect a dedup
			// entry for an already-dead mntnsID.
			marked = append(marked, candidatePath)
			installed = append(installed, execHoldCandidateInstall{path: candidatePath, mark: m})
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

	if lastKey, ok := n.execHoldMarked[mntnsID][execedPath]; ok {
		// A repeat exec of the same PATH is only a genuine repeat if the
		// object behind it has not changed since. A cheap stat (relative to
		// rootDir, NOT the full openat2 RESOLVE_IN_ROOT + mount-identity
		// resolve markExecHoldPath does) is enough to tell a real repeat from
		// a replaced binary: on a match, skip, exactly as before; on a
		// mismatch (or the stat itself failing, e.g. deleted) fall through
		// to the full, hardened resolve+mark path below, exactly as a
		// never-before-seen path would take.
		// filepath.Clean collapses a repeated leading slash ("//usr/bin/x")
		// down to a single one before TrimLeft strips it -- TrimPrefix alone
		// only removes ONE leading slash, so "//usr/bin/x" would still start
		// with "/" afterwards. Fstatat treats an absolute path as ignoring
		// dirfd entirely and resolving from the process's real root, so an
		// un-normalized rel here would stat the HOST's copy of the path
		// instead of the container's, silently basing the dedup decision (and
		// this cheap check's whole reason to exist off rootDir) on the wrong
		// object. rel=="" (execedPath was "/" or empty) or somehow still
		// absolute after cleaning both fall through to the full, hardened
		// resolve+mark path below rather than calling Fstatat at all.
		rel := strings.TrimLeft(filepath.Clean(execedPath), "/")
		if rel != "" && !filepath.IsAbs(rel) {
			var stat unix.Stat_t
			if err := unix.Fstatat(int(rootDir.Fd()), rel, &stat, 0); err == nil {
				if (execHoldKey{dev: uint64(stat.Dev), ino: stat.Ino}) == lastKey {
					return false
				}
				log.Debugf("container-hook: exec-hold: %s in mntns %d changed identity since its last mark (dev=%d ino=%d -> dev=%d ino=%d); re-marking",
					execedPath, mntnsID, lastKey.dev, lastKey.ino, stat.Dev, stat.Ino)
			}
		}
	}

	root, err := execHoldStatObject(int(rootDir.Fd()))
	if err != nil {
		log.Debugf("container-hook: exec-hold: fstat of container rootfs for mntns %d: %s", mntnsID, err)
		return false
	}

	// Resolved here rather than per markExecHoldPath call, so this one site
	// covers BOTH the first-exec route and the external premark route
	// (MarkExecHoldCandidate delegates here rather than calling
	// markExecHoldPath directly). These syscalls run under execHoldMarkedMu,
	// which the outer defer above holds across this whole body -- the dedup
	// fast path returns before reaching here, so deduped execs still pay
	// nothing; a future reorder must not lose that.
	anchors := n.execHoldResolveTrustedAnchors(int(rootDir.Fd()))
	defer execHoldCloseTrustedAnchors(anchors)

	if mntnsID == 0 {
		// No container identity to track ownership under -- markExecHoldPath
		// itself already treats this as fire-and-forget (closes the file
		// immediately, never retained in execHoldContainerMarks); skip the
		// in-flight/epoch bookkeeping entirely rather than key it on a value
		// that never names a real container, and skip the execHoldMarked
		// dedup write too, matching markExecHoldPath's own mntnsID==0
		// handling.
		_, err := n.markExecHoldPath(int(rootDir.Fd()), root, anchors, mntnsID, execedPath)
		if err != nil {
			log.Debugf("container-hook: exec-hold: not marking exec'd %s: %s", execedPath, err)
			return false
		}
		return true
	}

	// execHoldMarkedMu is already held (the outer defer above): passing
	// callerHoldsMarkedMu=true tells execHoldEndInstall not to re-acquire it
	// for the execHoldMarked write/delete below, which would self-deadlock
	// (sync.Mutex is not reentrant).
	startEpoch := n.execHoldBeginInstall(mntnsID)
	m, err := n.markExecHoldPath(int(rootDir.Fd()), root, anchors, mntnsID, execedPath)
	var installed []execHoldCandidateInstall
	if err != nil {
		log.Debugf("container-hook: exec-hold: not marking exec'd %s in mntns %d: %s", execedPath, mntnsID, err)
	} else {
		installed = []execHoldCandidateInstall{{path: execedPath, mark: m}}
	}
	return n.execHoldEndInstall(mntnsID, startEpoch, installed, true)
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
	if n.execHoldInstallsInFlight[mntnsID] > 0 {
		// A markExecHoldPath install (or batch of them, for a create-time
		// enumeration) for mntnsID is currently between installing its
		// kernel mark and finishing -- exactly the race
		// execHoldBeginInstall/execHoldEndInstall exist to close. Its own
		// entries are not (yet) visible above, so bump the forget-epoch:
		// execHoldEndInstall compares against the epoch it snapshotted at
		// Begin, and self-cleans its own contribution instead of leaving it
		// as an orphan this call already looked for and did not find.
		//
		// Left unbumped (the common, non-racing case: nothing in flight)
		// deliberately -- an epoch entry only ever exists while something is
		// actively racing it, so this map's growth stays bounded to that
		// window rather than accumulating one entry per container that ever
		// existed on the node.
		if n.execHoldForgetEpoch == nil {
			n.execHoldForgetEpoch = make(map[uint64]uint64)
		}
		n.execHoldForgetEpoch[mntnsID]++
	}
	n.execHoldContainerMarksMu.Unlock()

	// Unmark and drop dispatcher state off the lock above: these are
	// syscalls plus execHold.holdsMu, and execHoldContainerMarksMu must stay
	// free for markExecHoldPath's own (different-mntnsID) appends while this
	// runs.
	for _, m := range marks {
		n.execHoldReleaseOneMark(mntnsID, m)
	}
}

// execHoldReleaseOneMark releases the local resources of mark m, which
// belonged to mntnsID: unless another tracked container still owns the same
// object (execHoldKeyStillOwned -- most commonly a shared, unmodified
// base-image layer where several containers resolve the same allowlisted
// binary to the identical host inode), removes the kernel mark and
// dispatcher hold-state via execHoldReleaseHeldMark (which pairs the
// FAN_MARK_REMOVE syscall with the holds-map deletion under one holdsMu
// span, so this cannot interleave with a concurrent execHoldInstallMark for
// the same key); always closes the retained fd. Used by execHoldForget (a
// container terminating with marks still outstanding) and execHoldEndInstall
// (an in-flight install rolling back its own contribution because
// execHoldForget already ran for its mntnsID).
func (n *ContainerNotifier) execHoldReleaseOneMark(mntnsID uint64, m execHoldMarkedFile) {
	if n.execHoldKeyStillOwned(m.key, 0) {
		m.file.Close()
		return
	}
	key := m.key
	file := m.file
	n.execHoldReleaseHeldMark(key, func() {
		if err := n.execHoldMark(unix.FAN_MARK_REMOVE, unix.FAN_OPEN_EXEC_PERM, int(file.Fd()), ""); err != nil {
			log.Debugf("container-hook: exec-hold: removing mark for %s (mntns %d): %s", key, mntnsID, err)
		}
	})
	file.Close()
}

// execHoldKeyStillOwned reports whether any tracked container OTHER than
// exceptMntnsID still retains a marking fd for key in execHoldContainerMarks
// -- i.e., whether removing key's kernel mark right now would also strip
// protection some OTHER container (most commonly: sharing this exact object
// via a common, unmodified base-image layer -- overlayfs preserves the same
// host inode for an un-copied-up lower-layer file across every container
// using that layer) still needs for its own first exec of the same binary.
//
// exceptMntnsID=0 excludes nothing (0 is never a real mntnsID -- see
// markExecHoldPath, which never appends to execHoldContainerMarks for it):
// callers that have already removed their own entry from the map (like
// execHoldForget, above) pass 0 and rely on their own entry already being
// gone from what this scans.
func (n *ContainerNotifier) execHoldKeyStillOwned(key execHoldKey, exceptMntnsID uint64) bool {
	n.execHoldContainerMarksMu.Lock()
	defer n.execHoldContainerMarksMu.Unlock()
	for mntnsID, marks := range n.execHoldContainerMarks {
		if mntnsID == exceptMntnsID {
			continue
		}
		for _, m := range marks {
			if m.key == key {
				return true
			}
		}
	}
	return false
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
			//
			// Synchronized the same way Close() is: execHoldNotifyMu.Lock()
			// waits for any fanotify_mark call already in flight through
			// execHoldMark (external marking, or termination cleanup) to
			// finish before this fd is actually closed, so a mark call can
			// never run on an fd this has already closed (and the OS may
			// have already reused).
			if n.execHoldNotify != nil {
				n.execHoldNotifyMu.Lock()
				n.execHoldNotify.File.Close()
				n.execHoldNotifyMu.Unlock()
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
	if err := n.execHoldMark(unix.FAN_MARK_REMOVE, unix.FAN_OPEN_EXEC_PERM, int(data.Fd), ""); err != nil {
		log.Debugf("container-hook: exec-hold: removing mark for pid %d: %s", data.Pid, err)
	}
}
