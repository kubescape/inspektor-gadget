// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package selfqual

import (
	"time"
)

// Harness exposes the probe plumbing (stage, cgroups, fixtures, event
// collection) WITHOUT any of the admission suite's checks. The semantic
// oracle is written against it with its own hand-written expectations, so a
// wrong expectation in the suite's model cannot hide in the oracle.
type Harness struct {
	s *session
}

// TokenResult is what user space saw for one token.
type TokenResult struct {
	Token string
	Code  int
	PID   uint32
	Ran   bool // the exec target image reported from this pid
}

// Observation is one probe root's run: user-space results, kernel events and
// counter deltas (gauges are absolute).
type Observation struct {
	Root     uint32
	RootRan  bool // the root's own image reported (G003: a root that execs itself)
	Results  []TokenResult
	Storm    []StormAttempt
	Events   []Event
	Delta    Counters
	Quiesced bool
}

// StormAttempt is one exec of a storm worker.
type StormAttempt struct {
	Worker int
	File   string
	PID    uint32
	Code   int
}

func NewHarness(eng Engine, opts Options) (*Harness, error) {
	s, err := newSession(eng, opts)
	if err != nil {
		return nil, err
	}
	return &Harness{s: s}, nil
}

func (h *Harness) Close() error { return h.s.close() }

func (h *Harness) cg(mode Mode) *cgroupRef {
	if mode == ModeStrict {
		return h.s.strict
	}
	return h.s.audit
}

// CgroupID and CgroupPath name the probe cgroup bound in mode; AltPath is a
// cgroup that is never bound.
func (h *Harness) CgroupID(mode Mode) uint64   { return h.cg(mode).id }
func (h *Harness) CgroupPath(mode Mode) string { return h.cg(mode).path }
func (h *Harness) AltPath() string             { return h.s.alt.path }
func (h *Harness) Generation(mode Mode) uint64 { return h.cg(mode).gen }
func (h *Harness) HasBinfmtMisc() bool         { return h.s.st.binfmt }

// File returns a fixture's kernel identity.
func (h *Harness) File(name string) FileID { return h.s.st.files[name] }

// BaseAllow is the allow-list both probe cgroups start with.
func BaseAllow() []string { return append([]string(nil), baseAllow...) }

// Publish switches the mode's cgroup to a generation allowing exactly names.
func (h *Harness) Publish(mode Mode, names ...string) (uint64, error) {
	return h.s.publish(h.cg(mode), names)
}

func (h *Harness) Retire(mode Mode, gen uint64) error { return h.s.eng.Retire(h.cg(mode).id, gen) }

func (h *Harness) InjectFault(mode Mode, on bool) error {
	return h.s.eng.InjectFault(h.cg(mode).id, on)
}

func (h *Harness) observe(r *stepResult) Observation {
	o := Observation{Root: r.root, RootRan: r.out.Ran[r.root], Events: r.events, Delta: r.delta, Quiesced: r.quiesced}
	for _, res := range r.out.Results {
		o.Results = append(o.Results, TokenResult{Token: res.Token, Code: res.Code, PID: res.PID, Ran: r.out.Ran[res.PID]})
	}
	for _, l := range r.out.Storm {
		o.Storm = append(o.Storm, StormAttempt(l))
	}
	return o
}

// Where is where a probe root runs.
type Where struct {
	Mode    Mode // the bound cgroup of this mode, or
	Outside bool // outside every probe cgroup, or
	Alt     bool // in the never-bound cgroup
	Adopt   bool // have the engine track the root
	During  func() error
	Timeout time.Duration
}

// Run runs tokens in one probe root.
func (h *Harness) Run(w Where, tokens ...string) (Observation, error) {
	sp := stepSpec{adopt: w.Adopt, tokens: tokens, timeout: w.Timeout}
	switch {
	case w.Outside:
	case w.Alt:
		sp.cg = h.s.alt
	default:
		sp.cg = h.cg(w.Mode)
	}
	if w.During != nil {
		sp.during = func(uint32) error { return w.During() }
	}
	r, err := h.s.step(sp)
	if err != nil {
		return Observation{}, err
	}
	return h.observe(r), nil
}

// RunHeld runs tokens in an adopted root; the first exec of sh_hold is parked
// between its script pass and its interpreter pass while parked runs. If kill
// is set the parked task is SIGKILLed before it is released.
func (h *Harness) RunHeld(mode Mode, kill bool, parked func(pid uint32) error, tokens ...string) (Observation, error) {
	r, err := h.s.held(h.cg(mode), tokens, func(e heldExec) error {
		if kill {
			if err := killParked(e.PID, h.s.opts.probeTimeout()); err != nil {
				return err
			}
		}
		if parked != nil {
			return parked(e.PID)
		}
		return nil
	})
	if err != nil {
		return Observation{}, err
	}
	return h.observe(r), nil
}

// Counters reads the engine's counters.
func (h *Harness) Counters() (Counters, error) { return h.s.eng.Counters() }

// Path is a fixture's absolute path in the stage's mount namespace (E1).
func (h *Harness) Path(name string) string { return h.s.st.dir + "/" + name }

// HostPath is a fixture's path as the agent reaches it (/proc/<stage>/root).
func (h *Harness) HostPath(name string) string { return h.s.st.hostPath(name) }

// StagePID is the stage's pid (its mount namespace holds the fixtures).
func (h *Harness) StagePID() int { return h.s.st.pid }

// SetGeneration records a generation published to the mode's cgroup outside
// Publish (E1: engine-specific policy sets).
func (h *Harness) SetGeneration(mode Mode, gen uint64) { h.cg(mode).gen = gen }

// RunAsInit adopts the probe root as the mode's seeded init and runs tokens
// (E1: a second init must not move the anchor).
func (h *Harness) RunAsInit(mode Mode, tokens ...string) (Observation, error) {
	r, err := h.s.step(stepSpec{cg: h.cg(mode), adopt: true, adoptInit: true, tokens: tokens})
	if err != nil {
		return Observation{}, err
	}
	return h.observe(r), nil
}

// RunInit adopts a probe root as the mode's seeded init and has it exec the
// allowed fixture (E1: the root anchor's source).
func (h *Harness) RunInit(mode Mode) error { return h.s.initExec(h.cg(mode)) }

// RunHeldOn is RunHeld with the park on another fixture's exec open (E1: a
// PT_INTERP park).
func (h *Harness) RunHeldOn(mode Mode, file string, parked func(pid uint32) error, tokens ...string) (Observation, error) {
	r, err := h.s.heldOn(file, h.cg(mode), tokens, func(e heldExec) error {
		if parked != nil {
			return parked(e.PID)
		}
		return nil
	})
	if err != nil {
		return Observation{}, err
	}
	return h.observe(r), nil
}
