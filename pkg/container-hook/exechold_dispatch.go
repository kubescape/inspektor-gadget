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
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
)

// This file holds the exec-hold DISPATCHER: what happens for each
// FAN_OPEN_EXEC_PERM event the exec-hold group delivers. Installing the marks
// that produce those events is exechold.go's job.
//
// Every path here fails OPEN. A held exec is a customer process frozen mid
// execve, so every uncertainty — an unrecognised event, a stalled worker, a
// wedged read loop — resolves to FAN_ALLOW rather than to a longer hold.

const (
	// defaultExecHoldWorkerHardBound caps how long ONE held exec waits for the
	// credit/attach decision before it is allowed anyway. It is the same
	// min(work-done, hard-bound) shape as addContainerCallbackHardBound, applied
	// to a different gate, and it is deliberately NOT that constant: the
	// create→start gate protects runc's single fanotify goroutine, while this one
	// protects a blocked execve. The resource behind the bound is the exec_args
	// BPF map (512 entries, see installEbpf) — every held exec occupies one entry
	// for the whole hold — plus contention on uprobetracer's t.mu, which the
	// credit fast path takes. A couple of seconds of one-off pause on the first
	// exec of an instrumented binary buys the attach; more than that is a user
	// visible stall for work that can just as well happen out of band.
	defaultExecHoldWorkerHardBound = 2 * time.Second

	// defaultExecHoldMaxInFlight caps concurrent hold workers. Beyond it, events
	// are allowed immediately instead of queued: the same "shed rather than
	// queue" philosophy as addContainerCallbackTripThreshold, sized for this
	// gate's own resource. Each in-flight hold pins one exec_args entry out of
	// 512 for up to execHoldWorkerHardBound, so 32 leaves the ordinary execve
	// traffic of a busy node its headroom while still letting a pod burst hold
	// every binary it means to instrument. Self-resetting: as workers drain,
	// holding resumes.
	defaultExecHoldMaxInFlight = 32

	// defaultExecHoldLoopStallBound is how long the read loop may spend inside a
	// SINGLE iteration before the watchdog declares it wedged. It bounds the loop
	// itself, not the holds it starts: dispatching an event is fstat + dup +
	// two goroutines, so any iteration outlasting this is stuck in a place it
	// was never expected to block, and while it is stuck no OTHER held exec can
	// even be read from the group. Idle time waiting for the next event is not
	// counted and never trips the watchdog.
	defaultExecHoldLoopStallBound = 5 * time.Second

	// defaultExecHoldWatchdogInterval is how often the stall above is checked.
	defaultExecHoldWatchdogInterval = time.Second
)

// Overridable by tests only; production code never writes these.
var (
	execHoldWorkerHardBound        = defaultExecHoldWorkerHardBound
	execHoldMaxInFlight      int64 = defaultExecHoldMaxInFlight
	execHoldLoopStallBound         = defaultExecHoldLoopStallBound
	execHoldWatchdogInterval       = defaultExecHoldWatchdogInterval
)

// ExecHoldCrediter is the already-attached fast path the dispatcher consults
// before it holds an exec for a real attach. It is satisfied by
// *uprobetracer.Tracer[Event].CreditIfAttached; declaring it here as an
// interface keeps container-hook free of a uprobetracer import and makes the
// dispatcher's concurrency testable without a kernel.
//
// FILE OWNERSHIP: the implementation CONSUMES file and closes it on every
// return path, including errors, exactly as CreditIfAttached documents.
type ExecHoldCrediter interface {
	CreditIfAttached(containerPid uint32, file *os.File) (uint64, bool, error)
}

// ResolveAttacher is the hand-off point for the "not attached yet" branch: the
// full resolve + uprobe attach for a binary whose exec is being held.
//
// TODO(US-07): nothing in this repo implements it yet. The real implementation
// is the gotls resolve+attach path plus the fork-side uprobe attach entrypoint,
// both separate stories; until they land, SetExecHoldHooks leaves the default
// execHoldNoopResolveAttacher in place, so the dispatcher's guard, concurrency,
// timeout and watchdog behaviour below is complete and exercised today and
// wiring the real call is a one-line change at that call site.
//
// FILE OWNERSHIP: implementations CONSUME file and must close it on every
// return path, matching ExecHoldCrediter. The exec stays held until this
// returns, so an implementation must do its own I/O bounding; the dispatcher
// only guarantees the exec is released at execHoldWorkerHardBound whether or
// not this has returned.
type ResolveAttacher interface {
	ResolveAndAttach(containerPid uint32, file *os.File) error
}

// execHoldNoopResolveAttacher is the default: it consumes the file and reports
// success without attaching anything. See ResolveAttacher's TODO(US-07).
type execHoldNoopResolveAttacher struct{}

func (execHoldNoopResolveAttacher) ResolveAndAttach(containerPid uint32, file *os.File) error {
	return file.Close()
}

// execHoldHooks bundles the two collaborators so they can be published
// atomically, which matters because they are set from the embedder's goroutine
// while the read loop is already running.
type execHoldHooks struct {
	Crediter ExecHoldCrediter
	Attacher ResolveAttacher
}

// execHoldKey identifies a marked object by the (device, inode) pair the
// container's overlay filesystem reports. It is what an event's fd can be
// compared against without any lock or lookup, and what hold-state is keyed on.
type execHoldKey struct {
	dev uint64
	ino uint64
}

func (k execHoldKey) String() string { return fmt.Sprintf("dev=%d ino=%d", k.dev, k.ino) }

// execHoldKeyOfFd returns the key of whatever fd refers to.
func execHoldKeyOfFd(fd int) (execHoldKey, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return execHoldKey{}, fmt.Errorf("fstat for exec-hold key: %w", err)
	}
	return execHoldKey{dev: uint64(stat.Dev), ino: stat.Ino}, nil
}

// execHoldDispatch is the dispatcher's own state. It lives on the notifier but
// is owned exclusively by this file: exechold.go reaches it only through
// execHoldRememberHold/execHoldForgetHold, which is the hook markExecHoldPath
// calls so that recording hold-state and installing the mark stay in the same
// code path, in that order.
type execHoldDispatch struct {
	// holds is the set of objects this dispatcher has a mark installed for. An
	// event whose key is absent is not ours and is allowed immediately.
	holds   map[execHoldKey]struct{}
	holdsMu sync.Mutex

	hooks atomic.Pointer[execHoldHooks]

	// inFlight counts hold workers running right now; it is the shed decision.
	inFlight atomic.Int64

	// busySince is the unix-nanos timestamp at which the read loop entered its
	// current iteration, or 0 when it is idle waiting for the next event. It is
	// the only thing the watchdog looks at.
	busySince atomic.Int64
	// watchdogTripped latches: tripping is a one-way condition for this
	// dispatcher's lifetime, since it closes the group.
	watchdogTripped atomic.Bool

	holdsStarted  atomic.Uint64
	credited      atomic.Uint64
	attached      atomic.Uint64
	attachFailed  atomic.Uint64
	creditFailed  atomic.Uint64
	unresolved    atomic.Uint64
	timeouts      atomic.Uint64
	shed          atomic.Uint64
	guardMisses   atomic.Uint64
	watchdogTrips atomic.Uint64
}

// ExecHoldStats is a point-in-time view of the exec-hold dispatcher.
//
// TODO(US-08): these are plain counters read through this snapshot; registering
// them as real metrics (execholdattach_credit_failed_total and friends) is a
// separate story. The counters and a way to read them exist now so that story
// is a registration change, not an instrumentation change.
type ExecHoldStats struct {
	// InFlight is the number of hold workers running right now.
	InFlight int64
	// Holds counts events that were actually held (a worker was spawned).
	Holds uint64
	// Credited counts holds resolved by the already-attached fast path.
	Credited uint64
	// Attached and AttachFailed count holds that reached ResolveAndAttach.
	Attached     uint64
	AttachFailed uint64
	// CreditFailed counts CreditIfAttached errors — the
	// execholdattach_credit_failed_total counter.
	CreditFailed uint64
	// Unresolved counts holds whose exec'ing pid could not be mapped to a
	// tracked container, so there was no container pid to credit against.
	Unresolved uint64
	// Timeouts counts holds released by execHoldWorkerHardBound rather than by
	// their worker finishing.
	Timeouts uint64
	// Shed counts events allowed immediately because execHoldMaxInFlight workers
	// were already running.
	Shed uint64
	// GuardMisses counts events for objects this dispatcher holds no state for.
	GuardMisses uint64
	// WatchdogTrips counts read-loop stalls that closed the group. It is 0 or 1:
	// tripping is one-way.
	WatchdogTrips uint64
}

// ExecHoldStats returns a snapshot. It takes no lock and never blocks a hold.
func (n *ContainerNotifier) ExecHoldStats() ExecHoldStats {
	return ExecHoldStats{
		InFlight:      n.execHold.inFlight.Load(),
		Holds:         n.execHold.holdsStarted.Load(),
		Credited:      n.execHold.credited.Load(),
		Attached:      n.execHold.attached.Load(),
		AttachFailed:  n.execHold.attachFailed.Load(),
		CreditFailed:  n.execHold.creditFailed.Load(),
		Unresolved:    n.execHold.unresolved.Load(),
		Timeouts:      n.execHold.timeouts.Load(),
		Shed:          n.execHold.shed.Load(),
		GuardMisses:   n.execHold.guardMisses.Load(),
		WatchdogTrips: n.execHold.watchdogTrips.Load(),
	}
}

// SetExecHoldHooks wires the uprobe tracer into the dispatcher. Until it is
// called, every held exec resolves immediately: with no crediter there is
// nothing to decide, so holding would be pure latency.
//
// Safe to call at any time from any goroutine, including while the read loop is
// running. A nil attacher keeps the no-op default (see ResolveAttacher).
func (n *ContainerNotifier) SetExecHoldHooks(crediter ExecHoldCrediter, attacher ResolveAttacher) {
	if attacher == nil {
		attacher = execHoldNoopResolveAttacher{}
	}
	n.execHold.hooks.Store(&execHoldHooks{Crediter: crediter, Attacher: attacher})
}

// execHoldRememberHold records that a mark is being installed for key. It is
// called by markExecHoldPath BEFORE fanotify_mark, so no event can arrive for
// an object the dispatcher has no state for; the returned rollback undoes it if
// the mark itself fails.
func (n *ContainerNotifier) execHoldRememberHold(key execHoldKey) (rollback func()) {
	n.execHold.holdsMu.Lock()
	defer n.execHold.holdsMu.Unlock()

	if n.execHold.holds == nil {
		n.execHold.holds = make(map[execHoldKey]struct{})
	}
	n.execHold.holds[key] = struct{}{}

	// The set is deliberately not reference counted. Two call sites racing to
	// mark the SAME object, one of them failing, can therefore drop the
	// survivor's hold-state, after which an event for it is allowed immediately
	// by the guard below. That is the fail-open direction, and the alternative —
	// a count that a resolved hold would have to reconcile with a mark the
	// kernel has already folded into one — buys nothing here.
	return func() {
		n.execHold.holdsMu.Lock()
		defer n.execHold.holdsMu.Unlock()
		delete(n.execHold.holds, key)
	}
}

// execHoldForgetHold drops hold-state for key, called when the mark it belongs
// to has been removed, so the guard stays an accurate picture of what this
// dispatcher marked.
func (n *ContainerNotifier) execHoldForgetHold(key execHoldKey) {
	n.execHold.holdsMu.Lock()
	defer n.execHold.holdsMu.Unlock()
	delete(n.execHold.holds, key)
}

// execHoldHasHold reports whether this dispatcher installed a mark for key.
func (n *ContainerNotifier) execHoldHasHold(key execHoldKey) bool {
	n.execHold.holdsMu.Lock()
	defer n.execHold.holdsMu.Unlock()
	_, ok := n.execHold.holds[key]
	return ok
}

// execHoldEventRef is the dispatcher's view of one permission event: the facts
// it decides on, and the two kernel-visible actions it can take. The read loop
// builds it from a fanotify event; nothing below this line knows what fanotify
// is, which is what makes the concurrency here testable without a group.
type execHoldEventRef struct {
	// key identifies the object being exec'd.
	key execHoldKey
	// pid is the process whose execve is blocked on this event.
	pid uint32
	// dup returns an independent open file for the exec'd binary. The caller
	// owns every file it returns, and the files outlive allow() on purpose: a
	// worker the timeout gave up on must never touch the event fd again.
	dup func() (*os.File, error)
	// unmark removes the mark this hold belongs to. Called only when a hold
	// RESOLVES, never on the immediate fail-open paths, which must leave the
	// mark in place so the next exec is still seen.
	unmark func()
	// allow issues FAN_ALLOW and releases the event. Called exactly once, on
	// every path, and always after unmark.
	allow func()
}

// execHoldHold is the per-event token. Its only job is to make resolution
// idempotent: the worker and its timeout both race to resolve the same event,
// exactly one of them wins, and the loser — typically a worker still blocked
// inside an attach the timeout already gave up on — becomes a no-op that cannot
// touch hold-state belonging to a LATER hold on the same object.
type execHoldHold struct {
	ref execHoldEventRef
	// hardBound is snapshotted when the hold is admitted rather than read by
	// the timeout goroutine, so one hold's bound cannot change under it.
	hardBound time.Duration
	once      sync.Once
	finished  chan struct{}
}

// execHoldSettle resolves a hold: mark removed, hold-state dropped, exec
// allowed. Idempotent by construction.
func (n *ContainerNotifier) execHoldSettle(h *execHoldHold, reason string) {
	h.once.Do(func() {
		h.ref.unmark()
		n.execHoldForgetHold(h.ref.key)
		h.ref.allow()
		log.Debugf("container-hook: exec-hold: released exec of %s (pid %d): %s", h.ref.key, h.ref.pid, reason)
	})
}

// execHoldDispatchEvent decides what happens to one event and reports whether a
// worker was spawned for it. Everything it can decide cheaply — and everything
// that fails open — is decided here, on the read loop, without a goroutine.
func (n *ContainerNotifier) execHoldDispatchEvent(ref execHoldEventRef) bool {
	// F10 guard, first and without a lookup into anything but our own map: an
	// event for an object we did not mark fails open right now rather than
	// blocking a process for a whole timeout for nothing.
	if !n.execHoldHasHold(ref.key) {
		n.execHold.guardMisses.Add(1)
		log.Debugf("container-hook: exec-hold: no hold state for %s (pid %d); allowing", ref.key, ref.pid)
		ref.allow()
		return false
	}

	hooks := n.execHold.hooks.Load()
	if hooks == nil || hooks.Crediter == nil {
		// Nothing to decide without a crediter, so holding would be pure latency.
		ref.allow()
		return false
	}

	// Already at the worker budget: shed instead of queueing. The mark stays, so
	// the next exec of this binary gets another chance once workers drain.
	if n.execHold.inFlight.Load() >= execHoldMaxInFlight {
		n.execHold.shed.Add(1)
		log.Warnf("container-hook: exec-hold: %d holds in flight (>= %d); allowing exec of %s immediately (shed=%d)",
			n.execHold.inFlight.Load(), execHoldMaxInFlight, ref.key, n.execHold.shed.Load())
		ref.allow()
		return false
	}

	// Both files are duplicated HERE, on the read loop, while the event fd is
	// known good. A worker that duplicated lazily could find the fd already
	// closed by its own timeout and reused by an unrelated open — the classic
	// late-worker fd reuse bug.
	creditFile, err := ref.dup()
	if err != nil {
		log.Errorf("container-hook: exec-hold: duplicating event fd for %s: %s", ref.key, err)
		ref.allow()
		return false
	}
	attachFile, err := ref.dup()
	if err != nil {
		log.Errorf("container-hook: exec-hold: duplicating event fd for %s: %s", ref.key, err)
		creditFile.Close()
		ref.allow()
		return false
	}

	h := &execHoldHold{ref: ref, hardBound: execHoldWorkerHardBound, finished: make(chan struct{})}
	n.execHold.inFlight.Add(1)
	n.execHold.holdsStarted.Add(1)

	go n.execHoldWork(h, hooks, creditFile, attachFile)
	// A SEPARATE goroutine, not a timeout inside the worker: the worker can be
	// blocked in a call Go cannot preempt, and the whole point of the bound is
	// that the exec is released even then.
	go n.execHoldTimeout(h)

	return true
}

// execHoldWork is the held exec's actual decision: credit if already attached,
// otherwise resolve and attach. It consumes both files on every path and
// settles the hold when it is done — which may be long after the timeout
// already settled it, in which case settling is a no-op.
func (n *ContainerNotifier) execHoldWork(h *execHoldHold, hooks *execHoldHooks, creditFile, attachFile *os.File) {
	// Decremented when the work REALLY finishes, not when the timeout fires: the
	// budget exists to bound concurrent work, and a worker the timeout gave up
	// on is still running and still costing.
	defer n.execHold.inFlight.Add(-1)
	defer close(h.finished)

	containerPid, ok := n.execHoldContainerPid(h.ref.pid)
	if !ok {
		n.execHold.unresolved.Add(1)
		creditFile.Close()
		attachFile.Close()
		n.execHoldSettle(h, "exec'ing pid does not belong to a tracked container")
		return
	}

	_, credited, err := hooks.Crediter.CreditIfAttached(containerPid, creditFile)
	switch {
	case err != nil:
		// Fail open: an exec we cannot decide about is an exec we allow.
		n.execHold.creditFailed.Add(1)
		attachFile.Close()
		log.Debugf("container-hook: exec-hold: crediting %s for container %d: %s (credit_failed=%d)",
			h.ref.key, containerPid, err, n.execHold.creditFailed.Load())
		n.execHoldSettle(h, "credit failed")
	case credited:
		// Already attached and now credited to this container: there is nothing
		// left to do, and in particular no resolve+attach.
		n.execHold.credited.Add(1)
		attachFile.Close()
		n.execHoldSettle(h, "already attached, credited")
	default:
		if err := hooks.Attacher.ResolveAndAttach(containerPid, attachFile); err != nil {
			n.execHold.attachFailed.Add(1)
			log.Debugf("container-hook: exec-hold: attaching to %s for container %d: %s", h.ref.key, containerPid, err)
		} else {
			n.execHold.attached.Add(1)
		}
		n.execHoldSettle(h, "resolve+attach done")
	}
}

// execHoldTimeout races the worker against the hard bound and settles whichever
// way the race goes. It never cancels the worker: Go cannot preempt a blocked
// call, so the worker runs to completion in the background and its late attempt
// to settle is absorbed by the token's once.
func (n *ContainerNotifier) execHoldTimeout(h *execHoldHold) {
	timer := time.NewTimer(h.hardBound)
	defer timer.Stop()

	select {
	case <-h.finished:
	case <-timer.C:
		n.execHold.timeouts.Add(1)
		log.Warnf("container-hook: exec-hold: hold of %s (pid %d) exceeded %s; allowing the exec (timeouts=%d, in-flight=%d)",
			h.ref.key, h.ref.pid, h.hardBound, n.execHold.timeouts.Load(), n.execHold.inFlight.Load())
		n.execHoldSettle(h, "hard bound exceeded")
	}
}

// execHoldContainerPid maps the pid whose execve is held to the pid of the
// container it runs in — the identity uprobetracer keys attachments on, which
// is the container's own pid and not the exec'ing one.
//
// The mount namespace is the only link between the two, exactly as it is for
// execHoldOnExec, and n.containers records it. It is populated only when exec
// event collection is enabled (see AddWatchContainerTermination), which is the
// configuration exec-hold runs in; without it every hold resolves through the
// unresolved path, i.e. fails open.
func (n *ContainerNotifier) execHoldContainerPid(execPid uint32) (uint32, bool) {
	mntnsID, err := containerutils.GetMntNs(int(execPid))
	if err != nil {
		log.Debugf("container-hook: exec-hold: mount namespace of held pid %d: %s", execPid, err)
		return 0, false
	}

	n.containersMu.Lock()
	defer n.containersMu.Unlock()

	for _, c := range n.containers {
		if c.mntnsID == 0 || c.mntnsID != mntnsID {
			continue
		}
		if c.pid < 0 || c.pid > math.MaxUint32 {
			return 0, false
		}
		return uint32(c.pid), true
	}
	return 0, false
}

// execHoldWatchdogCheck trips the liveness watchdog if the read loop has been
// inside one iteration since before now-execHoldLoopStallBound, and reports
// whether the watchdog is tripped.
//
// Tripping closes the group's *os.File — the File, never the raw fd, so the
// runtime's poller releases it too and every reader of it unblocks. Closing a
// fanotify group's fd is documented (fanotify(7)) to resolve every outstanding
// permission event as allowed, so nothing here has to walk the outstanding
// holds: the kernel releases every wedged exec on our behalf. It is one-way:
// once the group is closed it is never re-armed for this notifier.
func (n *ContainerNotifier) execHoldWatchdogCheck(now time.Time) bool {
	busy := n.execHold.busySince.Load()
	if busy == 0 {
		// Idle: blocked waiting for the next event, which is the normal state and
		// is not a stall.
		return false
	}
	if stalled := now.Sub(time.Unix(0, busy)); stalled < execHoldLoopStallBound {
		return false
	}
	if !n.execHold.watchdogTripped.CompareAndSwap(false, true) {
		return true
	}

	n.execHold.watchdogTrips.Add(1)
	log.Errorf("container-hook: exec-hold: read loop made no progress for %s; closing the fanotify group, which releases every held exec. Exec-hold is now DISABLED for this notifier (watchdog_trips=%d)",
		execHoldLoopStallBound, n.execHold.watchdogTrips.Load())

	if n.execHoldNotify != nil {
		n.execHoldNotify.File.Close()
	}
	return true
}

// watchExecHoldWatchdog runs execHoldWatchdogCheck until it trips or the
// notifier closes. It is a goroutine of its own precisely because it must stay
// live while the loop it watches is not.
func (n *ContainerNotifier) watchExecHoldWatchdog() {
	defer n.wg.Done()

	ticker := time.NewTicker(execHoldWatchdogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
			if n.closed.Load() {
				return
			}
			if n.execHoldWatchdogCheck(time.Now()) {
				return
			}
		}
	}
}
