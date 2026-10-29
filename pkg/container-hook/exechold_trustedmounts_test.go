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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	logrus "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// bogusNodeRootDev is a device number no real filesystem has, used wherever a
// test needs the node-root-device refusal to be ARMED (so the fail-closed
// branch is not what is being exercised) without any staged mount matching it.
const bogusNodeRootDev = ^uint64(0)

// logCapture collects logrus entries for the duration of one test. A ~10-line
// local hook rather than logrus/hooks/test on purpose: this is a fork with an
// open upstream PR, and go.sum must stay untouched.
type logCapture struct {
	mu      sync.Mutex
	entries []logrus.Entry
}

func (c *logCapture) Levels() []logrus.Level { return logrus.AllLevels }

func (c *logCapture) Fire(e *logrus.Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, *e)
	return nil
}

func (c *logCapture) matching(level logrus.Level, substr string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, e := range c.entries {
		if e.Level == level && strings.Contains(e.Message, substr) {
			out = append(out, e.Message)
		}
	}
	return out
}

func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	std := logrus.StandardLogger()
	prevLevel := std.Level
	prevHooks := std.Hooks
	std.Hooks = make(logrus.LevelHooks)
	for level, hooks := range prevHooks {
		std.Hooks[level] = append([]logrus.Hook(nil), hooks...)
	}
	std.SetLevel(logrus.DebugLevel)
	std.Hooks.Add(c)
	t.Cleanup(func() {
		std.SetLevel(prevLevel)
		std.Hooks = prevHooks
	})
	return c
}

// withTrustedMountsPackageVar saves and restores the package-level trusted
// mount list around a test that calls the setter.
func withTrustedMountsPackageVar(t *testing.T) {
	t.Helper()
	previous := execHoldTrustedCrossDeviceMounts
	t.Cleanup(func() { execHoldTrustedCrossDeviceMounts = previous })
}

// newExecHoldTrustTestNotifier is newExecHoldTestNotifier plus the trusted
// cross-device configuration. nodeRootDev/nodeRootDevValid are EXPLICIT rather
// than derived from the real node, so tests can control precisely whether the
// node-root-device conjunct is armed, correct, or misderived.
func newExecHoldTrustTestNotifier(t *testing.T, basenames, trusted []string, nodeRootDev uint64, nodeRootDevValid bool) *ContainerNotifier {
	t.Helper()
	n := newExecHoldTestNotifier(t, basenames)
	n.execHoldTrustedMounts = trusted
	n.execHoldNodeRootDev = nodeRootDev
	n.execHoldNodeRootDevValid = nodeRootDevValid
	return n
}

// mountTmpfs mounts a fresh tmpfs at path and unmounts it when the test ends.
// A distinct tmpfs mount always carries its own st_dev, on any host, which is
// what makes the cross-device staging below independent of the developer
// machine's filesystem topology.
func mountTmpfs(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(path, 0o755))
	if err := unix.Mount("tmpfs", path, "tmpfs", 0, ""); err != nil {
		t.Skipf("cannot mount a tmpfs at %s: %s", path, err)
	}
	t.Cleanup(func() { unix.Unmount(path, unix.MNT_DETACH) })
}

// stageTrustedCrossDeviceMount mounts a tmpfs at <rootPath><at> and writes an
// executable at <at>/<rel>. It asserts the tmpfs produced BOTH a different
// st_dev AND (when the kernel reports it) a different mntID than the rootfs,
// so a test built on it cannot pass without the trusted branch being entered.
func stageTrustedCrossDeviceMount(t *testing.T, at, rel string) string {
	t.Helper()
	rootPath := t.TempDir()
	stageTrustedCrossDeviceMountIn(t, rootPath, at, rel)
	return rootPath
}

func stageTrustedCrossDeviceMountIn(t *testing.T, rootPath, at, rel string) string {
	t.Helper()
	mountPoint := filepath.Join(rootPath, strings.TrimPrefix(at, "/"))
	mountTmpfs(t, mountPoint)

	binPath := filepath.Join(mountPoint, strings.TrimPrefix(rel, "/"))
	require.NoError(t, os.MkdirAll(filepath.Dir(binPath), 0o755))
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	rootID := statObjectOfPath(t, rootPath)
	mountID := statObjectOfPath(t, mountPoint)
	require.NotEqual(t, rootID.dev, mountID.dev,
		"the staged mount must be on a different device than the rootfs, or the trusted branch is never entered")
	if rootID.mntIDValid && mountID.mntIDValid {
		require.NotEqual(t, rootID.mntID, mountID.mntID, "the staged mount must be a distinct mount")
	}
	return binPath
}

// stageTmpfsRootfsWithHostAnchor builds a fake rootfs ON A TMPFS -- guaranteeing
// a device distinct from / on ANY host -- and bind-mounts a directory FROM the
// node's root filesystem as the anchor at <at>. It asserts (i) the fake-rootfs
// device != the anchor device, so the trusted branch is actually entered, and
// (ii) the anchor device == the node root device, so the refusal under test is
// the one being exercised.
//
// DO NOT add a `rel` parameter or otherwise write a candidate file onto the
// anchor: the anchor's backing store IS the real host /, so os.WriteFile there
// would mutate the developer's own filesystem. This suite must never do that.
// Instead it binds a / directory that ALREADY contains a regular file and
// returns that file's container-absolute path as the candidate, exactly as
// TestMarkExecHoldCandidatesMntnsMatchStillEnumerates allowlists the existing
// "sh".
func stageTmpfsRootfsWithHostAnchor(t *testing.T, at string) (rootPath string, anchorDev uint64, candidate string) {
	t.Helper()

	nodeRootDev := statDev(t, "/")
	var src, srcFile string
	for _, dir := range []string{"/etc", "/bin", "/usr/bin", "/lib"} {
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() || statDev(t, dir) != nodeRootDev {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.Type().IsRegular() {
				src, srcFile = dir, e.Name()
				break
			}
		}
		if src != "" {
			break
		}
	}
	if src == "" {
		// A genuine environmental limit, not a topology accident this helper
		// could have controlled: nothing on the node root device to bind.
		t.Skip("no directory on the node root device with a regular file in it; cannot stage a host-backed anchor")
	}

	rootPath = filepath.Join(t.TempDir(), "root")
	mountTmpfs(t, rootPath)

	anchorPoint := filepath.Join(rootPath, strings.TrimPrefix(at, "/"))
	require.NoError(t, os.MkdirAll(anchorPoint, 0o755))
	if err := unix.Mount(src, anchorPoint, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("cannot bind-mount %s over %s: %s", src, anchorPoint, err)
	}
	t.Cleanup(func() { unix.Unmount(anchorPoint, unix.MNT_DETACH) })

	anchorDev = statDev(t, anchorPoint)
	require.NotEqual(t, statDev(t, rootPath), anchorDev,
		"the fake rootfs must be on a different device than the anchor, or the trusted branch is never entered")
	require.Equal(t, nodeRootDev, anchorDev,
		"the anchor must really be backed by the node root filesystem, or the refusal under test is not exercised")

	return rootPath, anchorDev, filepath.Join(at, srcFile)
}

func statObjectOfPath(t *testing.T, path string) execHoldRootIdentity {
	t.Helper()
	f, err := os.OpenFile(path, unix.O_PATH, 0)
	require.NoError(t, err)
	defer f.Close()
	id, err := execHoldStatObject(int(f.Fd()))
	require.NoError(t, err)
	return id
}

// requireMntIDs skips when the kernel cannot report mount identities (pre-5.8),
// which is a genuine environmental limit rather than a staging mistake: the
// mount-scoping conjunct does not exist there at all.
func requireMntIDs(t *testing.T, ids ...execHoldRootIdentity) {
	t.Helper()
	for _, id := range ids {
		if !id.mntIDValid {
			t.Skip("kernel does not report STATX_MNT_ID (pre-5.8); mount-scoping cannot be exercised")
		}
	}
}

// resolveAnchors resolves n's declared anchors against rootPath and releases
// them when the test ends.
func resolveAnchors(t *testing.T, n *ContainerNotifier, rootPath string) []execHoldTrustedAnchor {
	t.Helper()
	root := openRoot(t, rootPath)
	anchors := n.execHoldResolveTrustedAnchors(int(root.Fd()))
	t.Cleanup(func() { execHoldCloseTrustedAnchors(anchors) })
	return anchors
}

// --- Test 12c: the derivation decision table, driven through the PURE function.

// TestExecHoldDeriveNodeRootDeviceDecisionTable drives every row of the
// node-root-device decision table directly, which is possible only because the
// derivation is split into a pure, fully injectable function and a thin
// sync.Once wrapper: a Once executes once per process, so a table driven
// through it would be order-dependent, and its row 1 would need
// unshare(CLONE_NEWNS) while rows 2-3 would need HOST_ROOT set before the host
// package's init() ran.
func TestExecHoldDeriveNodeRootDeviceDecisionTable(t *testing.T) {
	pid1Root := filepath.Join(host.HostProcFs, "1", "root")
	statErr := errors.New("stat failed")

	for _, tt := range []struct {
		name        string
		pid1MntNs   uint64
		selfMntNs   uint64
		nsErr       error
		hostRoot    string
		hostRootSet bool
		statDev     func(string) (uint64, error)
		wantDev     uint64
		wantKnown   bool
		wantStatted string
	}{
		{
			name:      "namespaces differ: pid 1's root is the node's root",
			pid1MntNs: 1000, selfMntNs: 2000,
			hostRoot: "/", hostRootSet: false,
			statDev:   func(string) (uint64, error) { return 51, nil },
			wantDev:   51,
			wantKnown: true, wantStatted: pid1Root,
		},
		{
			name:      "namespaces differ: HOST_ROOT is ignored, pid 1 still wins",
			pid1MntNs: 1000, selfMntNs: 2000,
			hostRoot: "/host", hostRootSet: true,
			statDev:   func(string) (uint64, error) { return 51, nil },
			wantDev:   51,
			wantKnown: true, wantStatted: pid1Root,
		},
		{
			name:      "same namespace, HOST_ROOT set: the operator's assertion is taken",
			pid1MntNs: 1000, selfMntNs: 1000,
			hostRoot: "/host", hostRootSet: true,
			statDev:   func(string) (uint64, error) { return 66, nil },
			wantDev:   66,
			wantKnown: true, wantStatted: "/host",
		},
		{
			name:      "same namespace, HOST_ROOT unset: no information, fail closed",
			pid1MntNs: 1000, selfMntNs: 1000,
			hostRoot: "/", hostRootSet: false,
			statDev:   func(string) (uint64, error) { return 51, nil },
			wantKnown: false,
		},
		{
			name:      "self-check error: fail closed",
			pid1MntNs: 1000, selfMntNs: 2000, nsErr: errors.New("no such file"),
			hostRoot: "/host", hostRootSet: true,
			statDev:   func(string) (uint64, error) { return 51, nil },
			wantKnown: false,
		},
		{
			// Both statDev call sites must check their error, so both get a row:
			// an implementer who checked only one would otherwise ship a
			// fail-open on a shape the table claims to cover.
			name:      "stat error on the pid-1 path: fail closed",
			pid1MntNs: 1000, selfMntNs: 2000,
			hostRoot: "/", hostRootSet: false,
			statDev:   func(string) (uint64, error) { return 0, statErr },
			wantKnown: false,
		},
		{
			name:      "stat error on the HOST_ROOT path: fail closed",
			pid1MntNs: 1000, selfMntNs: 1000,
			hostRoot: "/host", hostRootSet: true,
			statDev:   func(string) (uint64, error) { return 0, statErr },
			wantKnown: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var statted []string
			dev, known := execHoldDeriveNodeRootDevice(
				tt.pid1MntNs, tt.selfMntNs, tt.nsErr, tt.hostRoot, tt.hostRootSet,
				func(path string) (uint64, error) {
					statted = append(statted, path)
					return tt.statDev(path)
				})

			require.Equal(t, tt.wantKnown, known)
			if !tt.wantKnown {
				require.Zero(t, dev, "an unknown derivation must not hand back a device to compare against")
				return
			}
			require.Equal(t, tt.wantDev, dev)
			require.Equal(t, []string{tt.wantStatted}, statted, "the wrong source was stat'd")
		})
	}
}

// TestExecHoldNodeRootDeviceEmitsOneErrorPerProcess smoke-tests the thin
// sync.Once wrapper only -- memoization and Error dedup are its whole job; the
// logic itself is pinned by the decision-table test above.
//
// It asserts AT MOST one Error rather than exactly one, deliberately: by the
// time this runs, another test in the package may already have consumed the
// Once, in which case zero Errors are observed here and the memoization
// assertion still holds. Do NOT "strengthen" this to exactly one -- that
// reintroduces exactly the test-ordering hazard the pure/wrapper split exists
// to remove.
func TestExecHoldNodeRootDeviceEmitsOneErrorPerProcess(t *testing.T) {
	capture := captureLogs(t)

	dev1, known1 := execHoldNodeRootDevice()
	dev2, known2 := execHoldNodeRootDevice()
	dev3, known3 := execHoldNodeRootDevice()

	require.Equal(t, dev1, dev2)
	require.Equal(t, dev2, dev3)
	require.Equal(t, known1, known2)
	require.Equal(t, known2, known3)

	errLines := capture.matching(logrus.ErrorLevel, "node root device unknown")
	require.LessOrEqual(t, len(errLines), 1, "the failure Error must be emitted at most once per process, not once per call")
	if len(errLines) == 1 {
		require.False(t, known1)
		require.Contains(t, errLines[0], "ALL trusted cross-device exemptions will be refused")
	}
}

// TestNewContainerNotifierClonesTrustedCrossDeviceMounts asserts the notifier
// snapshots the package-level list at construction, so a later setter call
// cannot move the list under the marking goroutines reading it.
func TestNewContainerNotifierClonesTrustedCrossDeviceMounts(t *testing.T) {
	utils.RequireRoot(t)
	withTrustedMountsPackageVar(t)

	SetExecHoldTrustedCrossDeviceMounts([]string{"/home/coder"}, true)

	notifier, err := NewContainerNotifier(func(ContainerEvent) {})
	if err != nil {
		// A genuine environmental limit (no container runtime or no BPF on this
		// machine), not something the test could stage around.
		t.Skipf("cannot construct a real ContainerNotifier here: %s", err)
	}
	t.Cleanup(notifier.Close)

	require.Equal(t, []string{"/home/coder"}, notifier.execHoldTrustedMounts)

	SetExecHoldTrustedCrossDeviceMounts([]string{"/somewhere/else"}, true)
	require.Equal(t, []string{"/home/coder"}, notifier.execHoldTrustedMounts,
		"an existing notifier's snapshot must not follow later setter calls")
}

// --- Setter semantics.

// TestSetExecHoldTrustedCrossDeviceMounts asserts the setter stores a clone, so
// a caller mutating its own slice afterwards cannot change the armed list.
func TestSetExecHoldTrustedCrossDeviceMounts(t *testing.T) {
	withTrustedMountsPackageVar(t)

	paths := []string{"/home/coder"}
	SetExecHoldTrustedCrossDeviceMounts(paths, true)
	require.Equal(t, []string{"/home/coder"}, execHoldTrustedCrossDeviceMounts)

	paths[0] = "/mutated"
	require.Equal(t, []string{"/home/coder"}, execHoldTrustedCrossDeviceMounts,
		"the armed list must not alias the caller's slice")
}

// TestSetExecHoldTrustedCrossDeviceMountsDropsUnsafeEntries pins the validating
// setter: "/" would silently disable the very control this list excepts, and an
// empty or relative entry has no meaning as a container-absolute mount path.
func TestSetExecHoldTrustedCrossDeviceMountsDropsUnsafeEntries(t *testing.T) {
	withTrustedMountsPackageVar(t)
	capture := captureLogs(t)

	SetExecHoldTrustedCrossDeviceMounts([]string{"/", "", "relative/path", "/data"}, true)

	require.Equal(t, []string{"/data"}, execHoldTrustedCrossDeviceMounts)
	require.Len(t, capture.matching(logrus.WarnLevel, "dropping unsafe trusted cross-device mount"), 3)
}

// TestSetExecHoldTrustedCrossDeviceMountsWarnsOnHighBlastRadiusEntries: a path
// that is or contains a default search path, and a top-level path any container
// can collide with, are accepted but must be loud.
func TestSetExecHoldTrustedCrossDeviceMountsWarnsOnHighBlastRadiusEntries(t *testing.T) {
	withTrustedMountsPackageVar(t)
	capture := captureLogs(t)

	SetExecHoldTrustedCrossDeviceMounts([]string{"/usr/bin", "/data", "/home/coder"}, true)

	require.Equal(t, []string{"/usr/bin", "/data", "/home/coder"}, execHoldTrustedCrossDeviceMounts)
	require.Len(t, capture.matching(logrus.WarnLevel, `"/usr/bin" has a high blast radius`), 1)
	require.Len(t, capture.matching(logrus.WarnLevel, `"/data" has a high blast radius`), 1)
	require.Empty(t, capture.matching(logrus.WarnLevel, `"/home/coder" has a high blast radius`),
		"a specific, non-search-path declaration is the intended shape and must not warn")
}

// TestSetExecHoldTrustedCrossDeviceMountsRequiresAcknowledgement pins the
// acknowledgment key: the primary control for this feature is an operator
// prerequisite, not a code check, so the list does not arm at all until the
// operator asserts they read it.
func TestSetExecHoldTrustedCrossDeviceMountsRequiresAcknowledgement(t *testing.T) {
	withTrustedMountsPackageVar(t)
	capture := captureLogs(t)

	SetExecHoldTrustedCrossDeviceMounts([]string{"/home/coder"}, false)
	require.Empty(t, execHoldTrustedCrossDeviceMounts, "an unacknowledged list must be dropped WHOLE")
	require.Len(t, capture.matching(logrus.ErrorLevel, "without execHoldTrustedCrossDeviceMountsAcknowledgeRisk"), 1)

	SetExecHoldTrustedCrossDeviceMounts([]string{"/home/coder"}, true)
	require.Equal(t, []string{"/home/coder"}, execHoldTrustedCrossDeviceMounts)
}

// TestSetExecHoldTrustedCrossDeviceMountsLogsAcceptedListAtInfo pins the
// startup armed-config line. It names the ACCEPTED entries (not the configured
// count, which would disagree with reality at exactly the moment you need it to
// agree), the drop count, and the derived node root device -- the only place
// from which a misderived or absent host-pinned conjunct is visible on a
// running cluster.
func TestSetExecHoldTrustedCrossDeviceMountsLogsAcceptedListAtInfo(t *testing.T) {
	withTrustedMountsPackageVar(t)
	capture := captureLogs(t)

	SetExecHoldTrustedCrossDeviceMounts([]string{"/home/coder", "relative"}, true)

	lines := capture.matching(logrus.InfoLevel, "trusted cross-device mounts armed")
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], `"/home/coder"`)
	require.Contains(t, lines[0], "1 entries dropped as unsafe")

	dev, known := execHoldNodeRootDevice()
	if known {
		require.Contains(t, lines[0], fmt.Sprintf("node root device %d", dev))
	} else {
		require.Contains(t, lines[0], "node root device unknown -- ALL exemptions refused")
	}
}

// TestSetExecHoldTrustedCrossDeviceMountsEmptyIsSilent asserts the zero-config
// default costs nothing and says nothing: no derivation is forced, so a
// deployment that never asked for the feature never sees its Error either.
func TestSetExecHoldTrustedCrossDeviceMountsEmptyIsSilent(t *testing.T) {
	withTrustedMountsPackageVar(t)
	capture := captureLogs(t)

	SetExecHoldTrustedCrossDeviceMounts(nil, false)

	require.Empty(t, execHoldTrustedCrossDeviceMounts)
	require.Empty(t, capture.matching(logrus.InfoLevel, "trusted cross-device mounts armed"))
}

// --- Pure prefix matching.

// TestExecHoldMatchTrustedAnchorPrefixBoundaries pins the +"/" boundary:
// "/database" must not match a declaration of "/data".
func TestExecHoldMatchTrustedAnchorPrefixBoundaries(t *testing.T) {
	anchors := []execHoldTrustedAnchor{{path: "/data"}, {path: "/home/coder"}}

	for _, tt := range []struct {
		path      string
		wantMatch bool
		wantPath  string
	}{
		{"/data/bin/allowed", true, "/data"},
		{"/data", true, "/data"},
		{"//data/bin/allowed", true, "/data"}, // cleaned before matching
		{"/database/bin/allowed", false, ""},
		{"/datax", false, ""},
		{"/home/coder/.local/bin/allowed", true, "/home/coder"},
		{"/usr/bin/allowed", false, ""},
	} {
		got, ok := execHoldMatchTrustedAnchor(anchors, tt.path)
		require.Equal(t, tt.wantMatch, ok, tt.path)
		require.Equal(t, tt.wantPath, got.path, tt.path)
	}
}

// --- Regression pins: the default must not change.

// TestExecHoldOpenCandidateIgnoresNonMatchingTrustedMount asserts a non-empty
// trusted list naming an UNRELATED path leaves the refusal exactly as it was:
// the trusted branch is selected by the declared path, and a path that does not
// match it cannot be widened by the feature existing.
func TestExecHoldOpenCandidateIgnoresNonMatchingTrustedMount(t *testing.T) {
	const crossDevicePath = "/proc/version"

	rootDev := statDev(t, "/")
	if statDev(t, crossDevicePath) == rootDev {
		t.Skipf("%s is on the same device as /; cannot exercise the st_dev mismatch", crossDevicePath)
	}

	n := &ContainerNotifier{
		execHoldTrustedMounts:    []string{"/etc"},
		execHoldNodeRootDev:      bogusNodeRootDev,
		execHoldNodeRootDevValid: true,
	}
	anchors := resolveAnchors(t, n, "/")
	require.NotEmpty(t, anchors, "the control's premise: a declared anchor really was resolved")

	root := openRoot(t, "/")
	file, via, err := execHoldOpenCandidate(int(root.Fd()), execHoldRootIdentity{dev: rootDev}, anchors, crossDevicePath)
	if file != nil {
		file.Close()
	}
	require.Nil(t, file)
	require.Empty(t, via)
	require.EqualError(t, err, fmt.Sprintf("%q in container rootfs is on device %d, not the rootfs device %d: refusing to mark",
		crossDevicePath, statDev(t, crossDevicePath), rootDev))
}

// --- Trusted anchor accepted.

// TestExecHoldOpenCandidateAcceptsTrustedCrossDeviceMount is the positive case:
// a binary on a mount the operator declared trusted is returned for marking,
// and names the anchor it was accepted through.
func TestExecHoldOpenCandidateAcceptsTrustedCrossDeviceMount(t *testing.T) {
	utils.RequireRoot(t)
	rootPath := stageTrustedCrossDeviceMount(t, "/data", "bin/allowed")

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/data"}, statDev(t, "/"), true)
	anchors := resolveAnchors(t, n, rootPath)
	require.Len(t, anchors, 1)

	root := openRoot(t, rootPath)
	file, via, err := execHoldOpenCandidate(int(root.Fd()), statObjectOfPath(t, rootPath), anchors, "/data/bin/allowed")
	require.NoError(t, err)
	require.NotNil(t, file)
	defer file.Close()
	require.Equal(t, "/data", via)

	var st unix.Stat_t
	require.NoError(t, unix.Fstat(int(file.Fd()), &st))
	require.Equal(t, statDev(t, filepath.Join(rootPath, "data")), uint64(st.Dev),
		"the returned fd must be the object on the trusted mount")
}

// --- Trusted anchor refused.

// TestExecHoldOpenCandidateRefusesBindMountUnderTrustedMount is the retargeted
// mount-identity control: a mount landing UNDERNEATH the declared path is a
// DIFFERENT mount than the anchor and is refused, even though it shares the
// anchor's device and matches the declared prefix as a string.
//
// The positive control in the same test is what stops the guard passing by
// simply breaking everything.
func TestExecHoldOpenCandidateRefusesBindMountUnderTrustedMount(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := t.TempDir()
	stageTrustedCrossDeviceMountIn(t, rootPath, "/data", "real/bin/allowed")
	dataPath := filepath.Join(rootPath, "data")

	// A bind mount WITHIN the trusted tmpfs: same device as the anchor, so only
	// the mount identity can tell it apart.
	nested := filepath.Join(dataPath, "bin")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	if err := unix.Mount(filepath.Join(dataPath, "real/bin"), nested, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("cannot stage a nested bind mount: %s", err)
	}
	t.Cleanup(func() { unix.Unmount(nested, unix.MNT_DETACH) })

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/data"}, statDev(t, "/"), true)
	anchors := resolveAnchors(t, n, rootPath)
	require.Len(t, anchors, 1)
	requireMntIDs(t, anchors[0].id, statObjectOfPath(t, nested))

	root := openRoot(t, rootPath)
	rootID := statObjectOfPath(t, rootPath)

	file, via, err := execHoldOpenCandidate(int(root.Fd()), rootID, anchors, "/data/bin/allowed")
	if file != nil {
		file.Close()
	}
	require.Nil(t, file)
	require.Empty(t, via)
	require.ErrorContains(t, err, "bind mount under a trusted mount")

	// Positive control: the very same layout without the nested mount is
	// accepted, so the refusal above is the mount-scoping check firing and not
	// the whole trusted branch being broken.
	control, via, err := execHoldOpenCandidate(int(root.Fd()), rootID, anchors, "/data/real/bin/allowed")
	require.NoError(t, err)
	require.NotNil(t, control)
	control.Close()
	require.Equal(t, "/data", via)
}

// TestExecHoldOpenCandidateTrustedMountRejectsSiblingDevice: a candidate under
// the declared prefix but on a DIFFERENT filesystem than the anchor is refused
// on the device comparison, before mount identity is even consulted.
func TestExecHoldOpenCandidateTrustedMountRejectsSiblingDevice(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := t.TempDir()
	stageTrustedCrossDeviceMountIn(t, rootPath, "/data", "bin/allowed")
	// A SECOND, independent tmpfs mounted under the trusted one.
	sibling := filepath.Join(rootPath, "data/other")
	mountTmpfs(t, sibling)
	require.NoError(t, os.WriteFile(filepath.Join(sibling, "allowed"), []byte("#!/bin/sh\n"), 0o755))

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/data"}, statDev(t, "/"), true)
	anchors := resolveAnchors(t, n, rootPath)
	require.Len(t, anchors, 1)

	root := openRoot(t, rootPath)
	file, via, err := execHoldOpenCandidate(int(root.Fd()), statObjectOfPath(t, rootPath), anchors, "/data/other/allowed")
	if file != nil {
		file.Close()
	}
	require.Nil(t, file)
	require.Empty(t, via)
	require.ErrorContains(t, err, `but trusted mount "/data" is on device`)
}

// TestExecHoldOpenCandidateTrustedPrefixIsNotASubstringMatch is the end-to-end
// form of the +"/" boundary: "/database" must not inherit "/data"'s exemption.
func TestExecHoldOpenCandidateTrustedPrefixIsNotASubstringMatch(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := t.TempDir()
	stageTrustedCrossDeviceMountIn(t, rootPath, "/database", "bin/allowed")

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/data"}, statDev(t, "/"), true)
	anchors := resolveAnchors(t, n, rootPath)
	require.Empty(t, anchors, `"/data" does not exist in this rootfs, so nothing may resolve for it`)

	root := openRoot(t, rootPath)
	file, via, err := execHoldOpenCandidate(int(root.Fd()), statObjectOfPath(t, rootPath), anchors, "/database/bin/allowed")
	if file != nil {
		file.Close()
	}
	require.Nil(t, file)
	require.Empty(t, via)
	require.ErrorContains(t, err, "refusing to mark")
}

// TestExecHoldOpenCandidateTrustedMountThatIsNotAMountIsInert: declaring an
// ordinary rootfs directory grants nothing to the mounts under it. The anchor
// resolves (it is a real directory) but carries the ROOTFS device, so a
// genuinely cross-device candidate beneath it still mismatches.
func TestExecHoldOpenCandidateTrustedMountThatIsNotAMountIsInert(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr"), 0o755))
	stageTrustedCrossDeviceMountIn(t, rootPath, "/usr/bin", "allowed")

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/usr"}, bogusNodeRootDev, true)
	anchors := resolveAnchors(t, n, rootPath)
	require.Len(t, anchors, 1)
	require.Equal(t, statDev(t, rootPath), anchors[0].id.dev, "the declared path is a plain rootfs directory")

	root := openRoot(t, rootPath)
	file, via, err := execHoldOpenCandidate(int(root.Fd()), statObjectOfPath(t, rootPath), anchors, "/usr/bin/allowed")
	if file != nil {
		file.Close()
	}
	require.Nil(t, file)
	require.Empty(t, via)
	require.ErrorContains(t, err, `but trusted mount "/usr" is on device`)
}

// TestExecHoldResolveTrustedAnchorsRefusesNodeRootDevice is the flagship pin
// for the one conjunct the container cannot forge: an anchor whose device is
// the NODE's root filesystem device is a host path whatever the pod spec called
// it, and is refused regardless of the declaration.
//
// The staging helper's two device assertions are what make this meaningful
// rather than vacuous: the fake rootfs is on its own tmpfs, so the trusted
// branch is genuinely entered, and the anchor is genuinely backed by the node
// root device the notifier is configured with.
func TestExecHoldResolveTrustedAnchorsRefusesNodeRootDevice(t *testing.T) {
	utils.RequireRoot(t)

	rootPath, anchorDev, candidate := stageTmpfsRootfsWithHostAnchor(t, "/home/coder")

	n := newExecHoldTrustTestNotifier(t, []string{filepath.Base(candidate)}, []string{"/home/coder"}, anchorDev, true)
	capture := captureLogs(t)
	anchors := resolveAnchors(t, n, rootPath)
	require.Empty(t, anchors, "an anchor on the node root device must never be handed to the marking path")
	require.Len(t, capture.matching(logrus.WarnLevel, "resolves to the node root device"), 1)

	root := openRoot(t, rootPath)
	file, via, err := execHoldOpenCandidate(int(root.Fd()), statObjectOfPath(t, rootPath), anchors, candidate)
	if file != nil {
		file.Close()
	}
	require.Nil(t, file)
	require.Empty(t, via)
	require.ErrorContains(t, err, "refusing to mark")
}

// TestExecHoldResolveTrustedAnchorsAcceptsNodeRootAnchorWhenDeviceIsMisderived
// is a RESIDUAL PIN, in the same register as
// TestExecHoldOpenCandidateAcceptsNonRootDeviceMountAtTrustedPath: it asserts
// what the mechanism does NOT protect against.
//
// With a misderived node root device T and a genuinely node-root-backed anchor
// on device Y, the refusal evaluates Y == T, which is false, so the anchor IS
// accepted. That is the fail-open shape by definition, and NOTHING downstream
// in execHoldOpenCandidate can detect it -- which is exactly why the derivation
// must be self-checking (TestExecHoldDeriveNodeRootDeviceDecisionTable) and
// published (TestSetExecHoldTrustedCrossDeviceMountsLogsAcceptedListAtInfo,
// plus the live-fire `stat -c %d /` cross-check). Those three are the ENTIRE
// defense: a reader must not go looking for a fourth check, because the
// available ones are the rejected heuristic-classification option by the back
// door.
func TestExecHoldResolveTrustedAnchorsAcceptsNodeRootAnchorWhenDeviceIsMisderived(t *testing.T) {
	utils.RequireRoot(t)

	rootPath, anchorDev, _ := stageTmpfsRootfsWithHostAnchor(t, "/home/coder")

	// The misderivation: the notifier believes the node root device is the fake
	// rootfs's tmpfs, exactly as stat() of the agent container's own overlay
	// would have produced.
	misderived := statDev(t, rootPath)
	require.NotEqual(t, anchorDev, misderived)

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/home/coder"}, misderived, true)
	anchors := resolveAnchors(t, n, rootPath)

	require.Len(t, anchors, 1, "a misderived node root device silently accepts a node-root anchor; this is the accepted residual")
	require.Equal(t, anchorDev, anchors[0].id.dev)
}

// TestExecHoldResolveTrustedAnchorsFailsClosedWhenNodeRootDevUnknown: without a
// KNOWN node root device there is no host-pinned conjunct left, so every
// trusted exemption is refused. No per-enumeration Error: that Error belongs to
// the derivation's sync.Once, which runs once per process rather than once per
// container create.
func TestExecHoldResolveTrustedAnchorsFailsClosedWhenNodeRootDevUnknown(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := stageTrustedCrossDeviceMount(t, "/data", "bin/allowed")

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/data"}, 0, false)
	capture := captureLogs(t)
	anchors := resolveAnchors(t, n, rootPath)
	require.Empty(t, anchors)
	require.Empty(t, capture.matching(logrus.ErrorLevel, "node root device"),
		"the fail-closed Error belongs to the once-per-process derivation, not to each enumeration")

	root := openRoot(t, rootPath)
	file, via, err := execHoldOpenCandidate(int(root.Fd()), statObjectOfPath(t, rootPath), anchors, "/data/bin/allowed")
	if file != nil {
		file.Close()
	}
	require.Nil(t, file)
	require.Empty(t, via)
	require.ErrorContains(t, err, "refusing to mark")
}

// TestExecHoldResolveTrustedAnchorsRejectsSymlinkedDeclaredPath: without
// RESOLVE_NO_SYMLINKS a symlink at the declared path would let CONTAINER
// CONTENT choose which mount the operator's declaration selects. The failure is
// logged at Warn, not Debug: unlike "not present in this container", a
// structurally broken declaration is always misconfiguration and would
// otherwise be as silently inert as a dropped entry.
func TestExecHoldResolveTrustedAnchorsRejectsSymlinkedDeclaredPath(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := t.TempDir()
	stageTrustedCrossDeviceMountIn(t, rootPath, "/elsewhere", "bin/allowed")
	require.NoError(t, os.Symlink("/elsewhere", filepath.Join(rootPath, "data")))

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/data"}, statDev(t, "/"), true)
	capture := captureLogs(t)
	anchors := resolveAnchors(t, n, rootPath)

	require.Empty(t, anchors, "a symlinked declared path must not select the mount it points at")
	require.Len(t, capture.matching(logrus.WarnLevel, "could not be resolved"), 1)
	require.Empty(t, capture.matching(logrus.DebugLevel, "not present in this container"))
}

// TestExecHoldOpenCandidateRefusesSymlinkFromTrustedPrefixOntoAnotherMount is
// the other half of the selector asymmetry: the declared path is matched as a
// STRING while the candidate is independently resolved, so a symlink UNDER the
// trusted prefix that lands on a different cross-device mount matches the
// string but is refused on identity.
func TestExecHoldOpenCandidateRefusesSymlinkFromTrustedPrefixOntoAnotherMount(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := t.TempDir()
	stageTrustedCrossDeviceMountIn(t, rootPath, "/data", "bin/allowed")
	stageTrustedCrossDeviceMountIn(t, rootPath, "/other", "bin/allowed")
	require.NoError(t, os.Symlink("/other/bin/allowed", filepath.Join(rootPath, "data/link")))

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/data"}, statDev(t, "/"), true)
	anchors := resolveAnchors(t, n, rootPath)
	require.Len(t, anchors, 1)

	root := openRoot(t, rootPath)
	file, via, err := execHoldOpenCandidate(int(root.Fd()), statObjectOfPath(t, rootPath), anchors, "/data/link")
	if file != nil {
		file.Close()
	}
	require.Nil(t, file)
	require.Empty(t, via)
	require.ErrorContains(t, err, `but trusted mount "/data" is on device`)
}

// TestExecHoldOpenCandidateSameDeviceTrustedDeclarationIsRefusedClearly:
// same-device trusted mounts are deliberately unsupported (there is no
// host-pinned conjunct available for one), but the refusal must not send the
// operator chasing a bind mount they did not create.
func TestExecHoldOpenCandidateSameDeviceTrustedDeclarationIsRefusedClearly(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "elsewhere/bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rootPath, "elsewhere/bin/allowed"), []byte("#!/bin/sh\n"), 0o755))
	dataPath := filepath.Join(rootPath, "data")
	require.NoError(t, os.MkdirAll(dataPath, 0o755))
	// A bind mount from the rootfs's OWN device: same st_dev, different mount.
	if err := unix.Mount(filepath.Join(rootPath, "elsewhere"), dataPath, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("cannot stage a same-device bind mount: %s", err)
	}
	t.Cleanup(func() { unix.Unmount(dataPath, unix.MNT_DETACH) })

	rootID := statObjectOfPath(t, rootPath)
	requireMntIDs(t, rootID, statObjectOfPath(t, dataPath))
	require.Equal(t, rootID.dev, statDev(t, dataPath), "the declaration under test must be SAME-device")

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/data"}, bogusNodeRootDev, true)
	anchors := resolveAnchors(t, n, rootPath)
	require.Len(t, anchors, 1)

	root := openRoot(t, rootPath)
	file, via, err := execHoldOpenCandidate(int(root.Fd()), rootID, anchors, "/data/bin/allowed")
	if file != nil {
		file.Close()
	}
	require.Nil(t, file)
	require.Empty(t, via)
	require.ErrorContains(t, err, "a trusted cross-device declaration does not apply to a same-device mount")
}

// TestExecHoldOpenCandidateAcceptsNonRootDeviceMountAtTrustedPath pins the
// ACCEPTED RESIDUAL ATTACK, deliberately.
//
// A mount that is NOT on the node root device -- a hostPath onto a separate
// host filesystem, or a node-directory-backed PV on a data disk -- staged AT
// the declared path IS the anchor. The mount-identity retarget is therefore
// genuinely WAIVED there: trusted identity and candidate identity are the same
// adversary-selected mount, and the mark is installed on whatever inode it
// provides.
//
// This is the accepted contract. What bounds it is the cluster's pod-admission
// policy and StorageClass choice, the acknowledgment key, and the AND with the
// basename allowlist -- NOT anything in this function.
func TestExecHoldOpenCandidateAcceptsNonRootDeviceMountAtTrustedPath(t *testing.T) {
	utils.RequireRoot(t)

	// The tmpfs stands in for the hostile mount: staged AT the declared path,
	// on a device that is neither the rootfs's nor the node root's, so the
	// staging cannot make this test pass or fail for a topology reason.
	rootPath := stageTrustedCrossDeviceMount(t, "/home/coder", "bin/allowed")
	anchorDev := statDev(t, filepath.Join(rootPath, "home/coder"))
	require.NotEqual(t, statDev(t, rootPath), anchorDev)
	require.NotEqual(t, statDev(t, "/"), anchorDev)

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/home/coder"}, statDev(t, "/"), true)
	anchors := resolveAnchors(t, n, rootPath)
	require.Len(t, anchors, 1, "the node-root-device refusal does not cover a mount on any OTHER device")

	root := openRoot(t, rootPath)
	file, via, err := execHoldOpenCandidate(int(root.Fd()), statObjectOfPath(t, rootPath), anchors, "/home/coder/bin/allowed")
	require.NoError(t, err)
	require.NotNil(t, file)
	file.Close()
	require.Equal(t, "/home/coder", via)
}

// --- End-to-end marking through both internal mark sources.

// TestMarkExecHoldCandidatesInRootMarksTrustedCrossDeviceBinary drives the
// create-time enumeration end to end against a separate /usr/bin volume -- the
// "separate /usr" case execHoldOpenCandidate's own comment names.
//
// Note this necessarily demonstrates "/usr/bin", the MAXIMUM-BLAST-RADIUS
// declaration: the setter warns on it and the operator docs advise against it.
// It is used here because it is the only search-path shape the create-time
// enumeration can reach; do not copy it as the example configuration.
func TestMarkExecHoldCandidatesInRootMarksTrustedCrossDeviceBinary(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := t.TempDir()
	binPath := stageTrustedCrossDeviceMountIn(t, rootPath, "/usr/bin", "allowed")
	var binStat unix.Stat_t
	require.NoError(t, unix.Stat(binPath, &binStat))

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/usr/bin"}, statDev(t, "/"), true)
	require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd))

	marked := n.markExecHoldCandidatesInRoot(openRoot(t, rootPath), 0)
	require.Equal(t, []string{"/usr/bin/allowed"}, marked)
	require.Contains(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd), binStat.Ino)
	require.Equal(t, uint64(1), n.ExecHoldStats().TrustedCrossDeviceExceptions)
}

// TestExecHoldMarkExecedBinaryMarksTrustedCrossDeviceBinary is the live-fire
// reproduction: a binary on a PVC mounted at /home/coder, OUTSIDE
// execHoldSearchPaths, which the create-time enumeration never sees and which
// the st_dev control refused before this feature existed.
func TestExecHoldMarkExecedBinaryMarksTrustedCrossDeviceBinary(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := t.TempDir()
	binPath := stageTrustedCrossDeviceMountIn(t, rootPath, "/home/coder", ".local/bin/allowed")
	var binStat unix.Stat_t
	require.NoError(t, unix.Stat(binPath, &binStat))

	t.Run("trusted", func(t *testing.T) {
		n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/home/coder"}, statDev(t, "/"), true)

		require.True(t, n.execHoldMarkExecedBinary(1, openRoot(t, rootPath), "/home/coder/.local/bin/allowed"))
		require.Contains(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd), binStat.Ino)
		require.Equal(t, uint64(1), n.ExecHoldStats().TrustedCrossDeviceExceptions)
	})

	t.Run("negative twin without the declaration", func(t *testing.T) {
		n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, nil, statDev(t, "/"), true)

		require.False(t, n.execHoldMarkExecedBinary(1, openRoot(t, rootPath), "/home/coder/.local/bin/allowed"))
		require.Empty(t, fanotifyMarkedInodes(t, n.execHoldNotify.Fd))
		require.Zero(t, n.ExecHoldStats().TrustedCrossDeviceExceptions)
	})
}

// TestExecHoldResolveTrustedAnchorsResolvesOncePerEnumeration: the anchor fd is
// held open across a whole batch, so a container remounting mid-enumeration
// cannot present different anchors to different candidates.
func TestExecHoldResolveTrustedAnchorsResolvesOncePerEnumeration(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := t.TempDir()
	stageTrustedCrossDeviceMountIn(t, rootPath, "/usr/bin", "allowed")
	// A second candidate for the same allowlisted basename, on the same trusted
	// mount, so one enumeration really does consult the anchors twice.
	binDir := filepath.Join(rootPath, "usr/bin")
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "bin"), 0o755))
	if err := unix.Mount(binDir, filepath.Join(rootPath, "bin"), "", unix.MS_BIND, ""); err != nil {
		t.Skipf("cannot stage the second search path: %s", err)
	}
	t.Cleanup(func() { unix.Unmount(filepath.Join(rootPath, "bin"), unix.MNT_DETACH) })

	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/usr/bin"}, statDev(t, "/"), true)

	root := openRoot(t, rootPath)
	anchors := n.execHoldResolveTrustedAnchors(int(root.Fd()))
	require.Len(t, anchors, 1)
	before, err := execHoldStatObject(int(anchors[0].file.Fd()))
	require.NoError(t, err)

	// The container swaps the mount at the declared path mid-batch.
	require.NoError(t, unix.Unmount(binDir, unix.MNT_DETACH))
	mountTmpfs(t, binDir)

	after, err := execHoldStatObject(int(anchors[0].file.Fd()))
	require.NoError(t, err)
	require.Equal(t, before, after,
		"the held-open anchor must still describe the mount resolved at the start of the batch")
	execHoldCloseTrustedAnchors(anchors)
}

// TestMarkExecHoldPathLogsTrustedExceptionAtInfo: the per-exception line is
// deliberately at Info, unlike every other exec-hold mark log, because it
// records a security-relevant exception that must be auditable without
// fleet-wide debug logging.
func TestMarkExecHoldPathLogsTrustedExceptionAtInfo(t *testing.T) {
	utils.RequireRoot(t)

	rootPath := stageTrustedCrossDeviceMount(t, "/home/coder", "bin/allowed")
	n := newExecHoldTrustTestNotifier(t, []string{"allowed"}, []string{"/home/coder"}, statDev(t, "/"), true)

	root := openRoot(t, rootPath)
	anchors := n.execHoldResolveTrustedAnchors(int(root.Fd()))
	t.Cleanup(func() { execHoldCloseTrustedAnchors(anchors) })

	capture := captureLogs(t)
	m, err := n.markExecHoldPath(int(root.Fd()), statObjectOfPath(t, rootPath), anchors, 4242, "/home/coder/bin/allowed")
	require.NoError(t, err)
	t.Cleanup(func() { m.file.Close() })

	lines := capture.matching(logrus.InfoLevel, "via trusted cross-device mount")
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], `"/home/coder"`)
	require.Contains(t, lines[0], "mntns 4242")
	require.Equal(t, uint64(1), n.ExecHoldStats().TrustedCrossDeviceExceptions)
}
