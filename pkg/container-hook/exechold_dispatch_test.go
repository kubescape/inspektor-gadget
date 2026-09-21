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
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/s3rj1k/go-fanotify/fanotify"
	"github.com/stretchr/testify/require"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
)

// The dispatcher tests below drive the REAL dispatcher — its guard, its
// goroutines, its timeout race and its counters — through execHoldEventRef,
// which is the seam the read loop hands it a fanotify event through. They
// deliberately do not create a fanotify group: fanotify_init needs CAP_SYS_ADMIN
// in the INITIAL user namespace, so a group cannot be created either unprivileged
// or under `unshare -Umr`, and gating this behaviour on root would leave the
// concurrency that matters most untested in every unprivileged run.

// fakeCrediter stands in for uprobetracer's CreditIfAttached. It consumes the
// file on every path, as the real one documents.
type fakeCrediter struct {
	calls    atomic.Int64
	lastPid  atomic.Uint32
	credited bool
	err      error
	// block, when non-nil, holds the call until it is closed: this is how a
	// worker is made to outrun its own hard bound.
	block chan struct{}
	// entered is closed by the first call, so a test can wait for the worker to
	// actually be inside the credit call rather than sleep.
	entered chan struct{}
}

func (f *fakeCrediter) CreditIfAttached(containerPid uint32, file *os.File) (uint64, bool, error) {
	defer file.Close()
	f.lastPid.Store(containerPid)
	if f.calls.Add(1) == 1 && f.entered != nil {
		close(f.entered)
	}
	if f.block != nil {
		<-f.block
	}
	return 0, f.credited, f.err
}

// fakeAttacher stands in for the resolve+attach hand-off (see ResolveAttacher).
type fakeAttacher struct {
	calls atomic.Int64
	err   error
}

func (f *fakeAttacher) ResolveAndAttach(containerPid uint32, file *os.File) error {
	defer file.Close()
	f.calls.Add(1)
	return f.err
}

// testEvent is a fanotify permission event as the dispatcher sees one, with the
// two kernel-visible actions recorded instead of performed.
type testEvent struct {
	ref     execHoldEventRef
	allows  atomic.Int64
	unmarks atomic.Int64
	allowed chan struct{}
	dups    atomic.Int64
}

// newTestEvent builds an event for key, exec'd by pid, whose dup() hands out
// real independent files (of path) exactly as the read loop's dup does.
func newTestEvent(t *testing.T, key execHoldKey, pid uint32, path string) *testEvent {
	t.Helper()

	ev := &testEvent{allowed: make(chan struct{})}
	ev.ref = execHoldEventRef{
		key: key,
		pid: pid,
		dup: func() (*os.File, error) {
			ev.dups.Add(1)
			return os.Open(path)
		},
		unmark: func() { ev.unmarks.Add(1) },
		allow: func() {
			if ev.allows.Add(1) == 1 {
				close(ev.allowed)
			}
		},
	}
	return ev
}

// waitAllowed waits for the exec to be released, failing the test rather than
// hanging if it never is.
func (ev *testEvent) waitAllowed(t *testing.T, within time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	select {
	case <-ev.allowed:
		return time.Since(start)
	case <-time.After(within):
		t.Fatalf("the held exec was never allowed within %s", within)
		return 0
	}
}

// testBinary creates a file to stand in for the exec'd binary and returns its
// path and its (dev, ino) key.
func testBinary(t *testing.T) (string, execHoldKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "held")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	key, err := execHoldKeyOfFd(int(f.Fd()))
	require.NoError(t, err)
	return path, key
}

// newDispatchTestNotifier builds a notifier that can dispatch holds and whose
// container lookup resolves THIS process's mount namespace to containerPid, so
// execHoldContainerPid is exercised for real rather than stubbed.
func newDispatchTestNotifier(t *testing.T, containerPid int) *ContainerNotifier {
	t.Helper()

	mntnsID, err := containerutils.GetMntNs(os.Getpid())
	require.NoError(t, err)

	return &ContainerNotifier{
		containers: map[string]*watchedContainer{
			"test": {id: "test", pid: containerPid, mntnsID: mntnsID},
		},
	}
}

// withExecHoldBounds overrides the dispatcher's bounds for the duration of a
// test, the way the container timeout vars are overridden elsewhere in this
// package.
func withExecHoldBounds(t *testing.T, hardBound time.Duration, maxInFlight int64) {
	t.Helper()
	prevBound, prevMax := execHoldWorkerHardBound, execHoldMaxInFlight
	execHoldWorkerHardBound, execHoldMaxInFlight = hardBound, maxInFlight
	t.Cleanup(func() {
		execHoldWorkerHardBound, execHoldMaxInFlight = prevBound, prevMax
	})
}

// TestExecHoldGuardAllowsUnknownObject is the guard that keeps an unrecognised
// event from costing a process a whole timeout: an event for an object this
// dispatcher never recorded hold-state for is allowed on the spot, with no
// worker and no credit call. Its mark is deliberately left alone — this
// dispatcher does not own it.
func TestExecHoldGuardAllowsUnknownObject(t *testing.T) {
	path, key := testBinary(t)
	n := newDispatchTestNotifier(t, os.Getpid())
	crediter := &fakeCrediter{}
	n.SetExecHoldHooks(crediter, nil)

	ev := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.False(t, n.execHoldDispatchEvent(ev.ref), "no worker may be spawned for an object with no hold state")

	ev.waitAllowed(t, time.Second)
	require.EqualValues(t, 1, ev.allows.Load())
	require.EqualValues(t, 0, ev.unmarks.Load(), "a mark this dispatcher did not install must not be removed")
	require.EqualValues(t, 0, ev.dups.Load(), "the guard must decide before any fd work")
	require.EqualValues(t, 0, crediter.calls.Load(), "CreditIfAttached must not be reached")

	stats := n.ExecHoldStats()
	require.EqualValues(t, 1, stats.GuardMisses)
	require.EqualValues(t, 0, stats.Holds)
	require.EqualValues(t, 0, stats.InFlight)
}

// TestExecHoldCreditedResolvesWithoutAttaching covers the fast path: the tracer
// is already attached to this inode, so the hold resolves on the credit alone —
// mark removed, hold-state dropped, exec allowed, no resolve+attach.
func TestExecHoldCreditedResolvesWithoutAttaching(t *testing.T) {
	path, key := testBinary(t)
	const containerPid = 4242

	n := newDispatchTestNotifier(t, containerPid)
	crediter := &fakeCrediter{credited: true}
	attacher := &fakeAttacher{}
	n.SetExecHoldHooks(crediter, attacher)
	n.execHoldRememberHold(key)

	ev := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.True(t, n.execHoldDispatchEvent(ev.ref))
	ev.waitAllowed(t, 5*time.Second)

	require.EqualValues(t, 1, crediter.calls.Load())
	require.EqualValues(t, containerPid, crediter.lastPid.Load(),
		"the credit must be made against the CONTAINER's pid, not the exec'ing one")
	require.EqualValues(t, 0, attacher.calls.Load(), "an already-attached inode must not be re-attached")
	require.EqualValues(t, 1, ev.unmarks.Load())
	require.False(t, n.execHoldHasHold(key), "hold state must be dropped with the mark")

	requireInFlightDrains(t, n)
	stats := n.ExecHoldStats()
	require.EqualValues(t, 1, stats.Holds)
	require.EqualValues(t, 1, stats.Credited)
	require.EqualValues(t, 0, stats.Timeouts)
}

// TestExecHoldSettleKeepsMarkWhileAnotherContainerOwnsIt is the security
// regression test for the shared-mark-across-containers fix: holds/marks are
// keyed globally per (dev, ino), but two or more containers can legitimately
// share the identical host inode for an allowlisted binary (an unmodified
// base-image layer overlayfs has not copied up). Settling ONE container's
// held exec must NOT strip the kernel mark or hold-state a DIFFERENT, still
// tracked container's own (simulated here via execHoldContainerMarks) mark on
// the SAME object still needs for its own first exec.
func TestExecHoldSettleKeepsMarkWhileAnotherContainerOwnsIt(t *testing.T) {
	path, key := testBinary(t)
	n := newDispatchTestNotifier(t, 4242)
	n.SetExecHoldHooks(&fakeCrediter{credited: true}, &fakeAttacher{})
	n.execHoldRememberHold(key)

	// A second, distinct container's retained mark for the IDENTICAL object.
	otherFile, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { otherFile.Close() })
	n.execHoldContainerMarks = map[uint64][]execHoldMarkedFile{
		9999: {{key: key, file: otherFile}},
	}

	ev := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.True(t, n.execHoldDispatchEvent(ev.ref))
	ev.waitAllowed(t, 5*time.Second)

	require.EqualValues(t, 0, ev.unmarks.Load(),
		"the kernel mark must stay installed while another tracked container still owns the object")
	require.True(t, n.execHoldHasHold(key),
		"hold-state must stay in place too, or a later exec of the SAME shared object would miss the F10 guard")
}

// TestExecHoldNotCreditedReachesResolveAttach covers the other branch: nothing
// is attached for this inode, so the dispatcher hands the file to the
// resolve+attach seam (TODO(US-07)) and only then releases the exec.
func TestExecHoldNotCreditedReachesResolveAttach(t *testing.T) {
	path, key := testBinary(t)
	n := newDispatchTestNotifier(t, os.Getpid())
	crediter := &fakeCrediter{credited: false}
	attacher := &fakeAttacher{}
	n.SetExecHoldHooks(crediter, attacher)
	n.execHoldRememberHold(key)

	ev := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.True(t, n.execHoldDispatchEvent(ev.ref))
	ev.waitAllowed(t, 5*time.Second)

	require.EqualValues(t, 1, attacher.calls.Load())
	require.EqualValues(t, 1, ev.unmarks.Load())
	require.False(t, n.execHoldHasHold(key))
	require.EqualValues(t, 1, n.ExecHoldStats().Attached)
}

// TestExecHoldCreditErrorFailsOpenAndCounts asserts the failure direction: a
// credit that errors releases the exec anyway and is counted, because the
// alternative — holding a process because we could not decide about it — is the
// one outcome this feature must never produce.
func TestExecHoldCreditErrorFailsOpenAndCounts(t *testing.T) {
	path, key := testBinary(t)
	n := newDispatchTestNotifier(t, os.Getpid())
	crediter := &fakeCrediter{err: errors.New("inode resolution failed")}
	attacher := &fakeAttacher{}
	n.SetExecHoldHooks(crediter, attacher)
	n.execHoldRememberHold(key)

	ev := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.True(t, n.execHoldDispatchEvent(ev.ref))
	ev.waitAllowed(t, 5*time.Second)

	require.EqualValues(t, 0, attacher.calls.Load(), "a failed credit must not fall through to an attach")
	require.EqualValues(t, 1, ev.unmarks.Load())
	require.False(t, n.execHoldHasHold(key))
	require.EqualValues(t, 1, n.ExecHoldStats().CreditFailed)
}

// TestExecHoldUnresolvedContainerFailsOpen asserts the same for an exec whose
// pid cannot be mapped to a tracked container: there is no container pid to
// credit against, so the exec is released instead of held.
func TestExecHoldUnresolvedContainerFailsOpen(t *testing.T) {
	path, key := testBinary(t)
	n := &ContainerNotifier{} // no tracked containers at all
	crediter := &fakeCrediter{}
	n.SetExecHoldHooks(crediter, nil)
	n.execHoldRememberHold(key)

	ev := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.True(t, n.execHoldDispatchEvent(ev.ref))
	ev.waitAllowed(t, 5*time.Second)

	require.EqualValues(t, 0, crediter.calls.Load())
	require.EqualValues(t, 1, n.ExecHoldStats().Unresolved)
}

// TestExecHoldInstallMarkOrdersStateBeforeMark is the lifecycle-ordering
// assertion: markExecHoldPath's state-then-mark sequence must record hold-state
// BEFORE fanotify_mark can produce an event, and must roll it back if the mark
// fails. The injected mark function observes the map at exactly the moment the
// kernel call would happen, which is the only way to assert the ORDER rather
// than just the end state.
//
// The injected closure reads n.execHold.holds directly rather than through
// execHoldHasHold: execHoldInstallMark now holds holdsMu across the ENTIRE
// call, including this closure (see its own comment, added to serialize
// install against execHoldSettle for the same key), so calling the
// lock-acquiring accessor from inside it would self-deadlock. The direct read
// is race-free here specifically because it runs on the SAME goroutine that
// already holds holdsMu -- no other goroutine can be touching the map at this
// exact moment.
func TestExecHoldInstallMarkOrdersStateBeforeMark(t *testing.T) {
	n := &ContainerNotifier{}
	key := execHoldKey{dev: 7, ino: 99}

	var observed bool
	require.NoError(t, n.execHoldInstallMark(key, func() error {
		observed = n.execHold.holds[key] > 0
		return nil
	}))
	require.True(t, observed, "hold state must already be recorded when the mark is installed")
	require.True(t, n.execHoldHasHold(key), "a successful mark keeps its hold state")

	// And the rollback: a mark that fails must leave nothing behind, or the
	// guard would report a hold for an object nothing can ever send an event for.
	failed := execHoldKey{dev: 7, ino: 100}
	markErr := errors.New("mark failed")
	err := n.execHoldInstallMark(failed, func() error {
		require.True(t, n.execHold.holds[failed] > 0)
		return markErr
	})
	require.ErrorIs(t, err, markErr)
	require.False(t, n.execHoldHasHold(failed), "a failed mark must roll its hold state back")
	require.True(t, n.execHoldHasHold(key), "rollback must not disturb another object's hold state")

	n.execHoldForgetHold(key)
	require.False(t, n.execHoldHasHold(key))
}

// TestMarkExecHoldPathRollsBackHoldStateOnMarkFailure drives the same rollback
// through the real markExecHoldPath, with a group fd that cannot be marked, so
// the wiring between the two is covered and not just the helper.
func TestMarkExecHoldPathRollsBackHoldStateOnMarkFailure(t *testing.T) {
	rootPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "usr/bin"), 0o755))
	binPath := filepath.Join(rootPath, "usr/bin/allowed")
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o755))

	// A pipe is not a fanotify group, so fanotify_mark on it always fails —
	// which is exactly the case the rollback exists for, with no privileges
	// needed to produce it.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { r.Close(); w.Close() })

	n := &ContainerNotifier{
		execHoldNotify:   &fanotify.NotifyFD{Fd: int(r.Fd()), File: r},
		execHoldBinaries: []string{"allowed"},
	}

	root := openRoot(t, rootPath)
	_, err = n.markExecHoldPath(int(root.Fd()), execHoldRootIdentity{dev: statDev(t, rootPath)}, 0, "/usr/bin/allowed")
	require.Error(t, err)

	n.execHold.holdsMu.Lock()
	defer n.execHold.holdsMu.Unlock()
	require.Empty(t, n.execHold.holds, "a mark that failed must leave no hold state behind")
}

// TestExecHoldTimeoutWinsRaceAndLateWorkerIsHarmless is the core safety
// property of the hold: a worker stuck past the hard bound must not keep a
// customer process frozen, and when it finally does return — long after its
// event was resolved — it must not touch the bookkeeping of a LATER hold on the
// same inode.
func TestExecHoldTimeoutWinsRaceAndLateWorkerIsHarmless(t *testing.T) {
	const hardBound = 150 * time.Millisecond
	withExecHoldBounds(t, hardBound, defaultExecHoldMaxInFlight)

	path, key := testBinary(t)
	n := newDispatchTestNotifier(t, os.Getpid())

	blocked := &fakeCrediter{block: make(chan struct{}), entered: make(chan struct{})}
	n.SetExecHoldHooks(blocked, nil)
	n.execHoldRememberHold(key)

	first := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.True(t, n.execHoldDispatchEvent(first.ref))

	// The timeout, not the worker, releases this exec.
	elapsed := first.waitAllowed(t, 5*time.Second)
	require.GreaterOrEqual(t, elapsed, hardBound, "the exec was released before the hard bound elapsed")
	require.Less(t, elapsed, 2*time.Second, "the exec was held far past the hard bound")
	require.EqualValues(t, 1, n.ExecHoldStats().Timeouts)
	require.EqualValues(t, 1, first.unmarks.Load())
	require.False(t, n.execHoldHasHold(key))

	select {
	case <-blocked.entered:
	default:
		t.Fatal("the worker never reached the credit call, so nothing was actually raced")
	}

	// A SECOND hold on the SAME inode: the binary was marked again (say by the
	// first-exec path) and exec'd again, while the first worker is still stuck.
	fast := &fakeCrediter{credited: true}
	n.SetExecHoldHooks(fast, nil)
	n.execHoldRememberHold(key)

	second := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.True(t, n.execHoldDispatchEvent(second.ref))
	second.waitAllowed(t, 5*time.Second)
	require.EqualValues(t, 1, second.unmarks.Load())
	require.False(t, n.execHoldHasHold(key))

	// A third mark, whose hold state the late worker must not touch when it
	// finally returns.
	n.execHoldRememberHold(key)
	close(blocked.block)
	requireInFlightDrains(t, n)

	require.True(t, n.execHoldHasHold(key),
		"a worker that outran its timeout must not drop hold state belonging to a later mark")
	require.EqualValues(t, 1, first.allows.Load(), "the late worker must not respond a second time")
	require.EqualValues(t, 1, first.unmarks.Load())
	require.EqualValues(t, 1, second.allows.Load())
	require.EqualValues(t, 1, second.unmarks.Load())
	require.EqualValues(t, 1, n.ExecHoldStats().Timeouts)
}

// TestExecHoldShedsBeyondInFlightLimit asserts the load-shedding shape: past the
// worker budget, further execs are allowed immediately rather than queued behind
// the ones already running, and their marks are left in place so the next exec
// gets another chance once the workers drain.
func TestExecHoldShedsBeyondInFlightLimit(t *testing.T) {
	withExecHoldBounds(t, 10*time.Second, 1)

	path, key := testBinary(t)
	n := newDispatchTestNotifier(t, os.Getpid())

	blocked := &fakeCrediter{block: make(chan struct{}), entered: make(chan struct{})}
	n.SetExecHoldHooks(blocked, nil)
	n.execHoldRememberHold(key)

	held := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.True(t, n.execHoldDispatchEvent(held.ref), "the first event is within the budget and must be held")
	<-blocked.entered

	// The budget is full now.
	shed := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.False(t, n.execHoldDispatchEvent(shed.ref), "no worker may be spawned past the in-flight limit")
	shed.waitAllowed(t, time.Second)
	require.EqualValues(t, 1, blocked.calls.Load(), "the shed event must not reach CreditIfAttached")
	require.EqualValues(t, 0, shed.unmarks.Load(), "shedding must leave the mark in place")
	require.True(t, n.execHoldHasHold(key), "shedding must leave hold state in place")

	stats := n.ExecHoldStats()
	require.EqualValues(t, 1, stats.Shed)
	require.EqualValues(t, 1, stats.Holds)
	require.EqualValues(t, 1, stats.InFlight)

	// Draining restores normal holding: the budget is self-resetting.
	close(blocked.block)
	requireInFlightDrains(t, n)
	held.waitAllowed(t, 5*time.Second)
}

// TestExecHoldWatchdogClosesGroupOnStalledLoop asserts the liveness half: a read
// loop that stops making progress — not one slow worker, the loop itself —
// closes the group's *os.File. Closing the group fd is what makes the kernel
// release every outstanding permission event, so this is the whole recovery.
func TestExecHoldWatchdogClosesGroupOnStalledLoop(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })

	n := &ContainerNotifier{execHoldNotify: &fanotify.NotifyFD{Fd: int(r.Fd()), File: r}}

	now := time.Now()

	// Idle (blocked waiting for the next event) is not a stall.
	require.False(t, n.execHoldWatchdogCheck(now))

	// Inside an iteration, but not for long enough.
	n.execHold.busySince.Store(now.Add(-execHoldLoopStallBound / 2).UnixNano())
	require.False(t, n.execHoldWatchdogCheck(now))
	require.EqualValues(t, 0, n.ExecHoldStats().WatchdogTrips)

	// Wedged.
	n.execHold.busySince.Store(now.Add(-2 * execHoldLoopStallBound).UnixNano())
	require.True(t, n.execHoldWatchdogCheck(now))
	require.EqualValues(t, 1, n.ExecHoldStats().WatchdogTrips)
	require.ErrorIs(t, r.Close(), os.ErrClosed, "the watchdog must have closed the group's File")

	// One-way: it never re-arms, and never closes anything twice.
	require.True(t, n.execHoldWatchdogCheck(now))
	require.EqualValues(t, 1, n.ExecHoldStats().WatchdogTrips)
}

// requireInFlightDrains waits for every hold worker to finish, so a test can
// assert on state a late worker might still be about to touch.
func requireInFlightDrains(t *testing.T, n *ContainerNotifier) {
	t.Helper()
	require.Eventually(t, func() bool {
		return n.execHold.inFlight.Load() == 0
	}, 5*time.Second, 5*time.Millisecond, "hold workers did not drain")
}

// TestExecHoldKeyOfFdIdentifiesObject covers the fact the guard is built on:
// two paths to the same object produce the same key, a different object does
// not.
func TestExecHoldKeyOfFdIdentifiesObject(t *testing.T) {
	path, key := testBinary(t)

	again, err := os.Open(path)
	require.NoError(t, err)
	defer again.Close()
	sameKey, err := execHoldKeyOfFd(int(again.Fd()))
	require.NoError(t, err)
	require.Equal(t, key, sameKey)

	other := filepath.Join(filepath.Dir(path), "other")
	require.NoError(t, os.WriteFile(other, []byte("x"), 0o755))
	f, err := os.Open(other)
	require.NoError(t, err)
	defer f.Close()
	otherKey, err := execHoldKeyOfFd(int(f.Fd()))
	require.NoError(t, err)
	require.NotEqual(t, key, otherKey)

	_, err = execHoldKeyOfFd(-1)
	require.Error(t, err)
}

// TestExecHoldWithoutHooksAllowsImmediately asserts the default: until a
// crediter is wired in there is nothing to decide, so a hold would be pure
// latency and the exec is released at once.
func TestExecHoldWithoutHooksAllowsImmediately(t *testing.T) {
	path, key := testBinary(t)
	n := newDispatchTestNotifier(t, os.Getpid())
	n.execHoldRememberHold(key)

	ev := newTestEvent(t, key, uint32(os.Getpid()), path)
	require.False(t, n.execHoldDispatchEvent(ev.ref))
	ev.waitAllowed(t, time.Second)
	require.EqualValues(t, 0, ev.unmarks.Load())
	require.True(t, n.execHoldHasHold(key))
}

// TestExecHoldNoopResolveAttacherConsumesFile pins the contract the real
// resolve+attach implementation (TODO(US-07)) has to honour: the file is
// consumed, exactly as CreditIfAttached consumes its own.
func TestExecHoldNoopResolveAttacherConsumesFile(t *testing.T) {
	path, _ := testBinary(t)
	f, err := os.Open(path)
	require.NoError(t, err)

	require.NoError(t, execHoldNoopResolveAttacher{}.ResolveAndAttach(1, f))
	require.ErrorIs(t, f.Close(), os.ErrClosed, "ResolveAndAttach must consume the file")
}
