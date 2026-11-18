// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package optcnode runs the option C exec engine (optcengine, product
// object) behind the shared node contract of fullruntime.NodeEnforcer:
// StartNode, Bind, BindingSession.Publish / Inspect / Remove, Ready,
// Degraded and StopNode, with fullruntime's own value types. Both nodes
// satisfy Enforcer; Bind and Publish mirror the product signatures (their
// session types differ, so they are not in the interface).
//
// A node starts only where admission (package admission, design 005 §8)
// admits the product object: an exactly pinned (kernel, object) pair by
// default, a qualified family only when opted in. Every other start is
// refused with ErrNotReady: an unknown kernel, no BPF LSM, a load or ksym
// failure, a start canary that did not see every hook. A started node's
// Ready fails (ErrNotReady, wrapping fullruntime.ErrSharedNodeNotReady) once
// the witness latches, once a task record, work area or mark could not be
// allocated, and when a kernel control re-read fails (ftrace off, a
// livepatch loaded); none of these clear until restart.
package optcnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/admission"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/optcengine"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Enforcer is the node part of fullruntime.NodeEnforcer's exported contract
// (ab57bdda6) that both engines implement with identical signatures:
// *fullruntime.NodeEnforcer satisfies it unchanged (compile-time assertion
// below). node-agent today calls no NodeEnforcer method (it drives the
// per-container fullruntime.Owner through its own igbackend.FullEngine), so
// the method set is NodeEnforcer's own, not a node-agent subset.
//
// Excluded NodeEnforcer methods, and why:
//   - Bind: returns the concrete *fullruntime.BindingSession. Both nodes have
//     Bind(ctx, SharedBindingConfig) with their own session type; both
//     sessions satisfy Binding.
//   - Start, Stop, Close (operators.GadgetContext lifecycle): the product
//     node is an operator hosted by a gadget context; the option C node is
//     not hosted (StartNode loads and attaches it; StopNode detaches).
//   - ReleaseAfterDetach, TeardownPendingWithdrawals: the product's
//     physical route slots and pending withdrawals; option C has neither
//     (Remove unbinds at once).
//
// Where option C has no equivalent of a product health model (capsules,
// facts, birth park, fail-closed rate windows, adoption), the method returns
// ErrNotSupported, never a healthy value.
type Enforcer interface {
	Ready(gc operators.GadgetContext) error
	Degraded(gc operators.GadgetContext) error
	BeforeStop(ctx context.Context) error
	StopNode(ctx context.Context) error
	KernelEventCounters() (fullruntime.KernelEventCounters, error)
	CapsuleHealth() (fullruntime.SharedCapsuleHealth, error)
	FactHealth() (fullruntime.SharedFactHealth, error)
	BirthParkHealth() (fullruntime.SharedBirthParkHealth, error)
	FailClosedHealth() (fullruntime.SharedFailClosedHealth, error)
	AdoptionReport() ([]fullruntime.SharedAdoptionStatus, map[string]uint64, error)
}

// Binding is the session part of the contract, satisfied by
// *fullruntime.BindingSession unchanged and by *BindingSession. Excluded
// BindingSession methods: Compile and PublishCompiled (the product's split
// of compiling a container-neutral shared object from committing it; option
// C compiles per binding inside Publish), PreparedID and ScopeCookie (the
// product's physical scope identifiers).
type Binding interface {
	Publish(ctx context.Context, policy fullruntime.SharedBindingPolicy) (fullruntime.SharedRouteState, error)
	Inspect() fullruntime.SharedBindingStatus
	Remove(ctx context.Context, expectedGeneration uint64) error
}

var (
	_ Enforcer = (*fullruntime.NodeEnforcer)(nil)
	_ Enforcer = (*Node)(nil)
	_ Binding  = (*fullruntime.BindingSession)(nil)
	_ Binding  = (*BindingSession)(nil)
)

// ErrNotSupported is what a contract method returns where the option C node
// has no equivalent of the product's model: never a fake healthy value.
var ErrNotSupported = errors.New("option C node: not supported")

// ErrNotReady wraps every refusal to start and every Ready failure. It
// wraps fullruntime.ErrSharedNodeNotReady, so callers of either node test
// one error.
var ErrNotReady = fmt.Errorf("option C node: %w", fullruntime.ErrSharedNodeNotReady)

// Config configures a node.
type Config struct {
	// Admission: the exact pins, and the families with the opt-in.
	Admission admission.Policy
	// MaxTasks is the per-binding tracked-task ceiling (R12; 0: none).
	// Not race-free: forks of a binding that pass the check concurrently
	// each count, so the count can exceed MaxTasks by the number of its
	// tasks forking at that moment (at most 2*MaxTasks-1 in all).
	MaxTasks uint32
	// BindDeadline (review C4) bounds the time from Bind to the init's
	// first exec, which captures the root anchor (0: DefaultBindDeadline).
	// A binding without an anchor is not Ready; past the deadline its
	// capture is closed for good. A container bound after its entrypoint
	// exec'd stays NotReady: bind at the runtime's exec.fifo point.
	BindDeadline time.Duration
	// OnEvent receives the engine's decision, fault and commit events
	// (nil: they are drained and dropped). It must not block.
	OnEvent func(optcengine.Detail)
	// Runtime is the container runtime whose init Bind proves (R3-C1).
	Runtime RuntimeConfig
	// Probe overrides the node facts and kernel controls (unit tests).
	Probe *Probe
}

// Probe is what the node reads from the host.
type Probe struct {
	Node     func() (admission.Node, error)
	LSMs     func() (string, error)
	Controls func() error
	Load     func(optcengine.Options) (*optcengine.Engine, error)
	// InitImage proves at Bind that the init has not started its
	// entrypoint (review N1, R3-C1: initProof). Nil refuses every Bind;
	// only a test passes an explicit bypass. The kernel checks the
	// outside-namespace part again when it captures the anchor.
	InitImage func(pid uint32, containerID string) error
}

// RuntimeConfig names the container runtime whose init a binding must
// prove to be (review R3-C1).
type RuntimeConfig struct {
	// StateRoot is the runtime's state directory root: the init of
	// container <id> waits on <StateRoot>/<id>/exec.fifo (runc's layout;
	// crun: its own state root). Default: DefaultRuntimeStateRoot.
	StateRoot string
	// Binaries are the runtime binaries (host paths) the init's image must
	// be a copy of, by content (runc's memfd clone included). Default:
	// DefaultRuntimeBinaries, those that exist.
	Binaries []string
}

// DefaultRuntimeStateRoot is runc's state root.
const DefaultRuntimeStateRoot = "/run/runc"

// DefaultRuntimeBinaries are the usual runc locations.
var DefaultRuntimeBinaries = []string{"/usr/bin/runc", "/usr/sbin/runc", "/usr/local/bin/runc", "/usr/local/sbin/runc"}

func hostProbe() *Probe {
	return &Probe{Node: hostNode, LSMs: func() (string, error) {
		b, err := os.ReadFile("/sys/kernel/security/lsm")
		return string(b), err
	}, Controls: kernelControls, Load: optcengine.Load}
}

// DefaultBindDeadline is Config.BindDeadline's default.
const DefaultBindDeadline = 60 * time.Second

// Node is a started option C node.
type Node struct {
	eng      *optcengine.Engine
	decision admission.Decision
	probe    *Probe
	done     chan struct{}

	mu       sync.Mutex
	stopped  bool
	sessions map[uint64]*BindingSession
	// controlErr latches the first kernel-control failure (review M1):
	// Ready stays failed until restart.
	controlErr error
	deadline   time.Duration
}

// StartNode admits, loads and attaches the product engine. It returns
// ErrNotReady (with the reason) wherever the node may not enforce.
func StartNode(ctx context.Context, c Config) (*Node, error) {
	p := c.Probe
	if p == nil {
		p = hostProbe()
		proof, err := newInitProof(c.Runtime)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotReady, err)
		}
		p.InitImage = proof.prove
	}
	lsms, err := p.LSMs()
	if err != nil {
		return nil, fmt.Errorf("%w: reading the active LSMs: %v", ErrNotReady, err)
	}
	if !contains(strings.Split(strings.TrimSpace(lsms), ","), "bpf") {
		return nil, fmt.Errorf("%w: BPF LSM is not active (lsm=%s)", ErrNotReady, strings.TrimSpace(lsms))
	}
	node, err := p.Node()
	if err != nil {
		return nil, fmt.Errorf("%w: node facts: %v", ErrNotReady, err)
	}
	d, err := admission.Admit(node, optcengine.ProductObject(), c.Admission)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotReady, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Load attaches every program and runs the start canary (a fork and an
	// exec must reach all four LSM programs and both tracepoints).
	eng, err := p.Load(optcengine.Options{Product: true, MaxTasks: c.MaxTasks})
	if err != nil {
		return nil, fmt.Errorf("%w: engine load: %v", ErrNotReady, err)
	}
	n := &Node{eng: eng, decision: d, probe: p, done: make(chan struct{}), sessions: map[uint64]*BindingSession{}, deadline: c.BindDeadline}
	if n.deadline == 0 {
		n.deadline = DefaultBindDeadline
	}
	go n.drain(c.OnEvent)
	return n, nil
}

func (n *Node) drain(on func(optcengine.Detail)) {
	defer close(n.done)
	for {
		ev, err := n.eng.ReadEvent(time.Now().Add(time.Second))
		if errors.Is(err, os.ErrClosed) {
			return
		}
		if err != nil {
			continue // a deadline, or one undecodable record
		}
		if on != nil {
			for _, d := range n.eng.Details(ev.PID) {
				on(d)
			}
		}
		n.eng.ResetDetails()
	}
}

// Admission is how the node was admitted.
func (n *Node) Admission() admission.Decision { return n.decision }

// Ready is nil while the node enforces as qualified.
func (n *Node) Ready(operators.GadgetContext) error {
	n.mu.Lock()
	stopped := n.stopped
	n.mu.Unlock()
	if stopped {
		return fmt.Errorf("%w: stopped", ErrNotReady)
	}
	var reasons []error
	w, err := n.eng.Witness()
	if err != nil {
		reasons = append(reasons, fmt.Errorf("witness: %w", err))
	} else {
		if !w.Armed {
			reasons = append(reasons, errors.New("witness not armed"))
		}
		if w.Latched {
			reasons = append(reasons, fmt.Errorf("witness latched (exec unmarked %d, fork unmarked %d, undecided %d, signal failures %d)", w.ExecUnmarked, w.ForkUnmarked, w.Undecided, w.SignalFail))
		}
		if w.MarkFail != 0 {
			reasons = append(reasons, fmt.Errorf("%d witness marks could not be allocated", w.MarkFail))
		}
	}
	if sf, err := n.eng.Raw(optcengine.CStorageFail); err != nil {
		reasons = append(reasons, err)
	} else if sf != 0 {
		reasons = append(reasons, fmt.Errorf("%d task records or work areas could not be allocated", sf))
	}
	n.mu.Lock()
	if n.controlErr == nil {
		n.controlErr = n.probe.Controls()
	}
	if n.controlErr != nil {
		reasons = append(reasons, fmt.Errorf("%w (latched)", n.controlErr))
	}
	n.mu.Unlock()
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrNotReady, errors.Join(reasons...))
}

// Degraded reports conditions that do not stop enforcement: tasks refused
// at a binding's ceiling (R12), lost events.
func (n *Node) Degraded(operators.GadgetContext) error {
	var errs []error
	if v, err := n.eng.Raw(optcengine.CCeiling); err != nil {
		errs = append(errs, err)
	} else if v != 0 {
		errs = append(errs, fmt.Errorf("%d task births met a binding's task ceiling", v))
	}
	if c, err := n.eng.Counters(); err != nil {
		errs = append(errs, err)
	} else if c.EventLost != 0 {
		errs = append(errs, fmt.Errorf("%d events lost", c.EventLost))
	}
	return errors.Join(errs...)
}

// BeforeStop joins nothing: the option C node runs no native command
// goroutines (the product joins its command transport here). StopNode does
// the teardown.
func (n *Node) BeforeStop(context.Context) error { return nil }

// KernelEventCounters is not supported: the engine counts failed ring
// reservations (Degraded reports them) but not submitted events, so a
// KernelEventCounters value would be partly invented.
func (n *Node) KernelEventCounters() (fullruntime.KernelEventCounters, error) {
	return fullruntime.KernelEventCounters{}, fmt.Errorf("%w: kernel event counters (no submitted count)", ErrNotSupported)
}

// CapsuleHealth is not supported: no exec capsules (product frame model).
func (n *Node) CapsuleHealth() (fullruntime.SharedCapsuleHealth, error) {
	return fullruntime.SharedCapsuleHealth{}, fmt.Errorf("%w: exec capsule health", ErrNotSupported)
}

// FactHealth is not supported: no product fact statistics.
func (n *Node) FactHealth() (fullruntime.SharedFactHealth, error) {
	return fullruntime.SharedFactHealth{}, fmt.Errorf("%w: fact health", ErrNotSupported)
}

// BirthParkHealth is not supported: no birth park (task storage instead).
func (n *Node) BirthParkHealth() (fullruntime.SharedBirthParkHealth, error) {
	return fullruntime.SharedBirthParkHealth{}, fmt.Errorf("%w: birth park health", ErrNotSupported)
}

// FailClosedHealth is not supported: no fail-closed rate windows (the
// witness latches Ready instead).
func (n *Node) FailClosedHealth() (fullruntime.SharedFailClosedHealth, error) {
	return fullruntime.SharedFailClosedHealth{}, fmt.Errorf("%w: fail-closed rate health", ErrNotSupported)
}

// AdoptionReport is not supported: no product adoption slots.
func (n *Node) AdoptionReport() ([]fullruntime.SharedAdoptionStatus, map[string]uint64, error) {
	return nil, nil, fmt.Errorf("%w: adoption report", ErrNotSupported)
}

// StopNode removes every binding and detaches the engine.
func (n *Node) StopNode(ctx context.Context) error {
	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		return nil
	}
	n.stopped = true
	sessions := n.sessions
	n.sessions = map[uint64]*BindingSession{}
	n.mu.Unlock()
	var errs []error
	for _, s := range sessions {
		errs = append(errs, s.remove())
	}
	errs = append(errs, n.eng.Close())
	select {
	case <-n.done:
	case <-ctx.Done():
		errs = append(errs, ctx.Err())
	}
	return errors.Join(errs...)
}

// BindingSession is one bound container.
type BindingSession struct {
	n     *Node
	cfg   fullruntime.SharedBindingConfig
	lease fullruntime.BindingLease

	mu      sync.Mutex
	gen     uint64
	class   uint32
	removed bool
	// Review C4: the init is registered at Bind; its anchor must be
	// captured before deadline.
	deadline time.Time
	timer    *time.Timer
	expired  bool
}

// Bind reserves a binding for the container's cgroup. The engine binds it
// at the first Publish, adopting InitHostPID as the seeded init (its start
// time is recorded at Bind; review R6, C4). Wiring contract: Bind AND the
// first Publish complete before the runtime releases the init (runc:
// exec.fifo); BindDeadline covers the create-to-start gap. Bind refuses an
// init that already runs its workload (ErrInitStarted, review N1).
func (n *Node) Bind(ctx context.Context, c fullruntime.SharedBindingConfig) (*BindingSession, error) {
	if c.CgroupID == 0 || c.InitHostPID == 0 {
		return nil, errors.New("binding needs a cgroup and an init host pid")
	}
	if c.ContainerID != "" && !fullruntime.ValidSharedContainerID(c.ContainerID) {
		return nil, fmt.Errorf("container id %q is not a containerd identifier", c.ContainerID)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.stopped {
		return nil, fmt.Errorf("%w: stopped", ErrNotReady)
	}
	if _, ok := n.sessions[c.CgroupID]; ok {
		return nil, fmt.Errorf("cgroup %d is already bound", c.CgroupID)
	}
	s := &BindingSession{n: n, cfg: c}
	if c.Acquire != nil {
		l, err := c.Acquire(ctx)
		if err != nil {
			return nil, fmt.Errorf("binding lease: %w", err)
		}
		s.lease = l
	}
	// Review C4: the init's identity and start time now; its execs are
	// counted from now on (before the proof, review R3: an exec racing the
	// proof is counted and closes capture).
	if err := n.eng.RegisterInit(c.CgroupID, c.InitHostPID); err != nil {
		if s.lease != nil {
			_ = s.lease.Close()
		}
		return nil, err
	}
	// Review N1, R3-C1: prove the init is the runtime's init, still
	// blocked on THIS container's exec.fifo; anything unproven refuses.
	proof := n.probe.InitImage
	if proof == nil {
		proof = func(uint32, string) error { return fmt.Errorf("%w: no init proof configured", ErrInitStarted) }
	}
	if err := proof(c.InitHostPID, c.ContainerID); err != nil {
		_ = n.eng.UnregisterInit(c.InitHostPID)
		if s.lease != nil {
			_ = s.lease.Close()
		}
		if !errors.Is(err, ErrInitStarted) {
			err = fmt.Errorf("%w: %v", ErrInitStarted, err)
		}
		return nil, err
	}
	s.deadline = time.Now().Add(n.deadline)
	s.timer = time.AfterFunc(n.deadline, s.closeCapture)
	n.sessions[c.CgroupID] = s
	return s, nil
}

// Publish makes policy the binding's current generation (atomic; never
// waits for execs in flight) and retires the previous one at once (R6).
// Only a fullpolicy source is accepted; a policy beyond the engine's limits
// is refused (optcengine.ErrUnsupportedPolicy), never truncated.
func (s *BindingSession) Publish(ctx context.Context, policy fullruntime.SharedBindingPolicy) (fullruntime.SharedRouteState, error) {
	if policy.Source == nil {
		return fullruntime.SharedRouteState{}, fmt.Errorf("%w: the option C node publishes fullpolicy sources only", optcengine.ErrUnsupportedPolicy)
	}
	if err := refuseArgv(policy.Source); err != nil {
		return fullruntime.SharedRouteState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.removed {
		return fullruntime.SharedRouteState{}, fullruntime.ErrSharedBindingWithdrawn
	}
	if s.lease != nil {
		if err := s.lease.Check(ctx); err != nil {
			return fullruntime.SharedRouteState{}, fmt.Errorf("binding lease: %w", err)
		}
	}
	ps := []fullpolicy.Policy{*policy.Source}
	cg := s.cfg.CgroupID
	var gen uint64
	var err error
	if s.gen == 0 {
		container := policy.Container
		if container == "" {
			container = s.cfg.ContainerID
		}
		if gen, err = s.n.eng.BindPolicies(cg, container, ps); err != nil {
			return fullruntime.SharedRouteState{}, err
		}
		if err = s.n.eng.AdoptInit(cg, s.cfg.InitHostPID); err != nil {
			return fullruntime.SharedRouteState{}, errors.Join(err, s.n.eng.Unbind(cg))
		}
	} else {
		if gen, err = s.n.eng.PublishPolicies(cg, ps); err != nil {
			return fullruntime.SharedRouteState{}, err
		}
	}
	prev := s.gen
	s.gen = gen // current from here on, even if retiring prev fails (review M8)
	s.class = 1
	if policy.Source.Mode == fullpolicy.Enforce {
		s.class = 2
	}
	state := fullruntime.SharedRouteState{Cgroup: cg, Generation: gen, Class: s.class}
	if prev != 0 {
		if err := s.n.eng.Retire(cg, prev); err != nil {
			return state, fmt.Errorf("generation %d is current; retiring %d failed: %w", gen, prev, err)
		}
	}
	return state, nil
}

// refuseArgv refuses argv contains/prefix predicates, as the product does:
// the engine acquires no authoritative argv fact, so such a rule could only
// ever be UNKNOWN (an evaluation error in every enforced exec it reaches).
// StdinIsPipe is acquired (the product's full_stdin_pipe).
func refuseArgv(p *fullpolicy.Policy) error {
	check := func(rule string, t fullpolicy.Target) error {
		if t.Argv != nil && (len(t.Argv.Contains) != 0 || len(t.Argv.Prefix) != 0) {
			return fmt.Errorf("%w: policy %s rule %s: argv predicates are refused (no authoritative argv fact)", optcengine.ErrUnsupportedPolicy, p.ID, rule)
		}
		return nil
	}
	for _, r := range p.Rules {
		if err := check(r.Name, r.Target); err != nil {
			return err
		}
		for _, ex := range r.Except {
			if err := check(r.Name, ex.Target); err != nil {
				return err
			}
		}
	}
	return nil
}

// closeCapture runs at the bind deadline: without an anchor by then, the
// capture is closed for good (the binding stays NotReady).
func (s *BindingSession) closeCapture() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.removed {
		return
	}
	if _, anchored, err := s.n.eng.Anchor(s.cfg.CgroupID); err == nil && anchored {
		return
	}
	_ = s.n.eng.CloseInit(s.cfg.InitHostPID)
	// A capture racing the close: anchored now means it came first.
	if _, anchored, err := s.n.eng.Anchor(s.cfg.CgroupID); err == nil && anchored {
		return
	}
	s.expired = true
}

// AnchorDeadline is when the binding's root anchor capture closes.
func (s *BindingSession) AnchorDeadline() time.Time { return s.deadline }

// Inspect reports the binding. Ready requires a published policy, a ready
// node and a captured root anchor (review C4): a binding whose init exec'd
// before its first policy, or whose deadline passed, never becomes Ready.
func (s *BindingSession) Inspect() fullruntime.SharedBindingStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, anchored, err := s.n.eng.Anchor(s.cfg.CgroupID)
	anchored = anchored && err == nil
	return fullruntime.SharedBindingStatus{
		CgroupID: s.cfg.CgroupID, Generation: s.gen, Removed: s.removed,
		Ready:          !s.removed && s.gen != 0 && anchored && s.n.Ready(nil) == nil,
		RootAuthorized: anchored,
		RoutePublished: s.gen != 0,
	}
}

// Remove unbinds the container. expectedGeneration (0: any) must be the
// current generation.
func (s *BindingSession) Remove(_ context.Context, expectedGeneration uint64) error {
	s.mu.Lock()
	if expectedGeneration != 0 && expectedGeneration != s.gen {
		g := s.gen
		s.mu.Unlock()
		return fmt.Errorf("generation %d is not current (%d)", expectedGeneration, g)
	}
	s.mu.Unlock()
	s.n.mu.Lock()
	delete(s.n.sessions, s.cfg.CgroupID)
	s.n.mu.Unlock()
	return s.remove()
}

func (s *BindingSession) remove() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.removed {
		return nil
	}
	s.removed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	errs := []error{s.n.eng.Unbind(s.cfg.CgroupID), s.n.eng.UnregisterInit(s.cfg.InitHostPID)}
	if s.lease != nil {
		errs = append(errs, s.lease.Close())
	}
	return errors.Join(errs...)
}

// ErrInitStarted is Bind's refusal of an init it cannot prove to be the
// runtime's init before its entrypoint (a late bind, or no proof).
var ErrInitStarted = errors.New("the binding's init is not proven to be the runtime's, before its entrypoint (late bind)")

// initProof (review R3-C1, option A) proves at Bind that the init is the
// container runtime's init, blocked on THIS container's exec.fifo:
//  1. <StateRoot>/<container id>/exec.fifo is a fifo, and the init holds an
//     fd to it: same path (readlink) and same st_dev and st_ino;
//  2. the init is blocked in open(2) or openat(2) (/proc/<pid>/syscall);
//  3. the init's image is a copy of a configured runtime binary (sha256 of
//     /proc/<pid>/exe; runc's memfd clone has the same content);
//  4. the image is not on a mount of the init's own namespace (N1).
//
// The state directory is the runtime's, on the host (root-owned, outside
// every container's mounts): a workload cannot hold an fd to its fifo. A
// workload that execs a memfd copy of the runtime binary (3, 4 pass) is
// still not blocked on that fifo (1).
type initProof struct {
	stateRoot string
	hashes    map[string]bool
	// Mutant knobs (tests only): skip one part of the proof.
	skipFifo, skipHash bool
}

func newInitProof(rc RuntimeConfig) (*initProof, error) {
	p := &initProof{stateRoot: rc.StateRoot, hashes: map[string]bool{}}
	if p.stateRoot == "" {
		p.stateRoot = DefaultRuntimeStateRoot
	}
	bins := rc.Binaries
	if len(bins) == 0 {
		bins = DefaultRuntimeBinaries
	}
	for _, b := range bins {
		sum, err := fileSHA256(b)
		if err != nil {
			if len(rc.Binaries) != 0 {
				return nil, fmt.Errorf("runtime binary %s: %w", b, err)
			}
			continue // a default location that does not exist
		}
		p.hashes[sum] = true
	}
	// No binary: every Bind is refused (fail closed), the node still starts.
	return p, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (p *initProof) prove(pid uint32, containerID string) error {
	if containerID == "" || !fullruntime.ValidSharedContainerID(containerID) {
		return fmt.Errorf("%w: no valid container id to find its exec.fifo", ErrInitStarted)
	}
	fifo := filepath.Join(p.stateRoot, containerID, "exec.fifo")
	if !p.skipFifo {
		var ft unix.Stat_t
		if err := unix.Lstat(fifo, &ft); err != nil || ft.Mode&unix.S_IFMT != unix.S_IFIFO {
			return fmt.Errorf("%w: %s is not the container's exec.fifo (%v)", ErrInitStarted, fifo, err)
		}
		dir := fmt.Sprintf("/proc/%d/fd", pid)
		ents, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("%w: init %d fds: %v", ErrInitStarted, pid, err)
		}
		held := false
		for _, e := range ents {
			var st unix.Stat_t
			target, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil || target != fifo || unix.Stat(filepath.Join(dir, e.Name()), &st) != nil {
				continue
			}
			if st.Dev == ft.Dev && st.Ino == ft.Ino {
				held = true
				break
			}
		}
		if !held {
			return fmt.Errorf("%w: init %d holds no fd to %s", ErrInitStarted, pid, fifo)
		}
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/syscall", pid))
		f := strings.Fields(string(b))
		if err != nil || len(f) == 0 || (f[0] != fmt.Sprint(unix.SYS_OPEN) && f[0] != fmt.Sprint(unix.SYS_OPENAT)) {
			return fmt.Errorf("%w: init %d is not blocked in open (syscall %q, %v)", ErrInitStarted, pid, strings.TrimSpace(string(b)), err)
		}
	}
	if !p.skipHash {
		sum, err := fileSHA256(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || !p.hashes[sum] {
			return fmt.Errorf("%w: init %d image (sha256 %.16s, %v) is not a configured runtime binary", ErrInitStarted, pid, sum, err)
		}
	}
	return initRunsRuntimeImage(pid)
}

// initRunsRuntimeImage (review N1): the init's executable must NOT be on a
// mount of the init's own mount namespace. Until its entrypoint exec a
// container init runs the runtime's image (the host runc or crun binary, or
// runc's sealed memfd clone), from outside the container's mounts; after it,
// a file of the container's mounts. The mount id of /proc/<pid>/exe
// (statx) is looked up in the init's /proc/<pid>/mountinfo.
//
// Residual: a workload that already put its executable on a foreign mount
// (PR_SET_MM_EXE_FILE, which needs CAP_SYS_RESOURCE, or an exec of a memfd)
// before a late Bind passes this check and the kernel's; the wiring contract
// (Bind and the first Publish before runc releases exec.fifo) excludes a
// late bind. A runtime whose init runs from inside the container's mounts
// fails closed (Bind refused).
func initRunsRuntimeImage(pid uint32) error {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, fmt.Sprintf("/proc/%d/exe", pid), 0, unix.STATX_MNT_ID, &st); err != nil {
		return fmt.Errorf("init %d executable: %w", pid, err)
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return fmt.Errorf("init %d executable: no mount id (fail closed)", pid)
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return fmt.Errorf("init %d mounts: %w", pid, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == fmt.Sprint(st.Mnt_id) {
			return fmt.Errorf("%w: init %d executable is on its own mount %d", ErrInitStarted, pid, st.Mnt_id)
		}
	}
	return nil
}

// hostNode reads the node facts admission decides on.
func hostNode() (admission.Node, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return admission.Node{}, err
	}
	raw, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		return admission.Node{}, fmt.Errorf("kernel BTF: %w", err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		return admission.Node{}, fmt.Errorf("kernel BTF: %w", err)
	}
	sum := sha256.Sum256(raw)
	n := admission.Node{Release: unix.ByteSliceToString(u.Release[:]), BTFSHA256: hex.EncodeToString(sum[:]), Kernel: spec}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(l, "=")
			switch v = strings.Trim(v, `"`); {
			case !ok:
			case k == "ID":
				n.OSID = v
			case k == "VERSION_ID":
				n.OSVersionID = v
			}
		}
	}
	return n, nil
}

// kernelControls re-reads the controls that silence BPF LSM programs or
// replace kernel code under them: ftrace off, a livepatch loaded.
func kernelControls() error {
	var errs []error
	if b, err := os.ReadFile("/proc/sys/kernel/ftrace_enabled"); err == nil && strings.TrimSpace(string(b)) != "1" {
		errs = append(errs, errors.New("kernel.ftrace_enabled is off"))
	}
	if es, err := os.ReadDir("/sys/kernel/livepatch"); err == nil && len(es) != 0 {
		errs = append(errs, fmt.Errorf("%d livepatches loaded", len(es)))
	}
	return errors.Join(errs...)
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if strings.TrimSpace(v) == s {
			return true
		}
	}
	return false
}
