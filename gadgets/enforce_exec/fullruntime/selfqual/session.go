// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package selfqual

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const cgroupRoot = "/sys/fs/cgroup"

type cgroupRef struct {
	name string
	path string
	id   uint64
	mode Mode // 0: not bound
	gen  uint64
}

type genPolicy struct {
	cgroup uint64
	mode   Mode
	allow  map[FileID]bool
}

// session is one qualification run's state: the engine under test, the
// stage, the throwaway cgroups and everything published to them.
type session struct {
	eng  Engine
	st   *stage
	opts Options

	root          string
	strict, audit *cgroupRef
	alt           *cgroupRef // never bound
	policies      map[uint64]genPolicy

	evMu   sync.Mutex
	events []Event
	evErr  error
	evStop chan struct{}
	evDone chan struct{}
}

// baseAllow is the allow-list every probe starts from. Everything else on the
// fixture tmpfs (deny, sh_denied, garbage_denied) and everything off it is
// denied.
var baseAllow = []string{
	"allow", "hold_interp", "sh_ok", "sh_deny_interp", "sh_nointerp", "sh_dirinterp", "sh_hold",
	"garbage", "noperm", "c1", "c2", "c3", "c4", "c5", "l1", "l2", "l3", "l4", "l5", "l6", "bm_file",
}

func makeCgroup(parent, name string) (*cgroupRef, error) {
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	var s unix.Stat_t
	if err := unix.Stat(path, &s); err != nil {
		return nil, err
	}
	return &cgroupRef{name: name, path: path, id: s.Ino}, nil
}

func newSession(eng Engine, opts Options) (s *session, err error) {
	s = &session{eng: eng, opts: opts, policies: map[uint64]genPolicy{}, evStop: make(chan struct{}), evDone: make(chan struct{})}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	var rnd [8]byte
	if _, err = rand.Read(rnd[:]); err != nil {
		return s, err
	}
	// The cgroups are root-owned and outside every container's cgroup
	// namespace: a workload cannot move a task into them.
	s.root = filepath.Join(cgroupRoot, "ee-selfqual-"+hex.EncodeToString(rnd[:]))
	if err = os.Mkdir(s.root, 0o700); err != nil {
		return s, fmt.Errorf("probe cgroup: %w", err)
	}
	if s.strict, err = makeCgroup(s.root, "strict"); err != nil {
		return s, fmt.Errorf("probe cgroup: %w", err)
	}
	if s.audit, err = makeCgroup(s.root, "audit"); err != nil {
		return s, fmt.Errorf("probe cgroup: %w", err)
	}
	if s.alt, err = makeCgroup(s.root, "alt"); err != nil {
		return s, fmt.Errorf("probe cgroup: %w", err)
	}
	if s.st, err = startStage(opts.helperImage()); err != nil {
		return s, err
	}
	go s.collectEvents()
	s.strict.mode, s.audit.mode = ModeStrict, ModeAudit
	for _, cg := range []*cgroupRef{s.strict, s.audit} {
		p, allow := s.policy(cg.mode, baseAllow)
		gen, err := eng.Bind(cg.id, p)
		if err != nil {
			cg.mode = 0
			return s, fmt.Errorf("bind %s probe cgroup: %w", cg.name, err)
		}
		cg.gen = gen
		s.policies[gen] = genPolicy{cgroup: cg.id, mode: p.Mode, allow: allow}
	}
	if opts.InitExec {
		for _, cg := range []*cgroupRef{s.strict, s.audit} {
			if err := s.initExec(cg); err != nil {
				return s, err
			}
		}
	}
	return s, nil
}

// initExec adopts a probe root as the binding's seeded init and has it exec
// the allowed fixture (its first exec).
func (s *session) initExec(cg *cgroupRef) error {
	r, err := s.step(stepSpec{cg: cg, adopt: true, adoptInit: true, tokens: []string{"self+exec:allow"}})
	if err != nil {
		return fmt.Errorf("init exec in %s: %w", cg.name, err)
	}
	// A successful self exec replaces the root: no result line, the image
	// reports from the root's pid.
	if len(r.out.Results) != 0 || !r.out.Ran[r.root] {
		return fmt.Errorf("init exec in %s: %+v", cg.name, r.out)
	}
	return nil
}

func (s *session) policy(mode Mode, names []string) (Policy, map[FileID]bool) {
	p := Policy{Mode: mode}
	allow := map[FileID]bool{}
	for _, name := range names {
		id, ok := s.st.files[name]
		if !ok {
			continue // bm_file without binfmt_misc
		}
		p.Allow = append(p.Allow, id)
		p.Paths = append(p.Paths, s.st.dir+"/"+name)
		allow[id] = true
	}
	return p, allow
}

// publish switches cg to a new generation that allows exactly names.
func (s *session) publish(cg *cgroupRef, names []string) (uint64, error) {
	p, allow := s.policy(cg.mode, names)
	gen, err := s.eng.Publish(cg.id, p)
	if err != nil {
		return 0, err
	}
	s.policies[gen] = genPolicy{cgroup: cg.id, mode: p.Mode, allow: allow}
	cg.gen = gen
	return gen, nil
}

func (s *session) collectEvents() {
	defer close(s.evDone)
	for {
		select {
		case <-s.evStop:
			return
		default:
		}
		ev, err := s.eng.ReadEvent(time.Now().Add(10 * time.Millisecond))
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		s.evMu.Lock()
		if err != nil {
			s.evErr = err
			s.evMu.Unlock()
			return
		}
		s.events = append(s.events, ev)
		s.evMu.Unlock()
	}
}

func (s *session) eventCount() int {
	s.evMu.Lock()
	defer s.evMu.Unlock()
	return len(s.events)
}

func (s *session) takeEvents() ([]Event, error) {
	s.evMu.Lock()
	defer s.evMu.Unlock()
	ev := s.events
	s.events = nil
	return ev, s.evErr
}

func (s *session) probeCgroup(id uint64) bool {
	return id == s.strict.id || id == s.audit.id
}

// close tears everything down. A teardown failure is a qualification failure:
// the caller treats the returned error as fatal.
func (s *session) close() error {
	var errs []error
	if s.st != nil {
		if err := s.st.stop(); err != nil {
			errs = append(errs, fmt.Errorf("stop probe stage: %w", err))
		}
	}
	select {
	case <-s.evStop:
	default:
		close(s.evStop)
		if s.st != nil {
			<-s.evDone
		}
	}
	for _, cg := range []*cgroupRef{s.strict, s.audit} {
		if cg == nil || cg.mode == 0 {
			continue
		}
		if err := s.eng.Unbind(cg.id); err != nil {
			errs = append(errs, fmt.Errorf("unbind %s probe cgroup: %w", cg.name, err))
		}
	}
	for _, cg := range []*cgroupRef{s.strict, s.audit, s.alt} {
		if cg == nil {
			continue
		}
		if err := removeCgroup(cg.path); err != nil {
			errs = append(errs, err)
		}
	}
	if s.root != "" {
		if err := removeCgroup(s.root); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func removeCgroup(path string) error {
	var err error
	for i := 0; i < 200; i++ {
		if err = unix.Rmdir(path); err == nil || errors.Is(err, unix.ENOENT) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("remove probe cgroup %s: %w", path, err)
}

// inCgroup reports whether pid is in cg, as the agent reads it.
func inCgroup(pid uint32, cg *cgroupRef) (bool, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false, err
	}
	want := strings.TrimPrefix(cg.path, cgroupRoot)
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return rest == want, nil
		}
	}
	return false, nil
}

type stepSpec struct {
	cg    *cgroupRef // nil: the probe root stays outside every probe cgroup
	adopt bool
	// adoptInit adopts the root as the binding's seeded init (InitAdopter).
	adoptInit bool
	tokens    []string
	during    func(root uint32) error
	timeout   time.Duration
}

type stepResult struct {
	spec     stepSpec
	root     uint32
	out      stageOutput
	events   []Event
	before   Counters
	after    Counters
	delta    Counters
	quiesced bool
}

func expectedEvents(d Counters) int {
	return int(d.Decisions + d.FaultDeny + d.UnknownExec + d.UnknownFork + d.ExecOK + d.ExecFail + d.ExecAbort)
}

// step runs one probe root through its tokens and returns what user space
// saw (codes, images that ran) and what the kernel recorded (events, counter
// deltas) once the engine is quiet again.
func (s *session) step(sp stepSpec) (*stepResult, error) {
	if sp.timeout == 0 {
		sp.timeout = s.opts.probeTimeout()
	}
	r := &stepResult{spec: sp}
	if _, err := s.takeEvents(); err != nil {
		return nil, fmt.Errorf("engine events: %w", err)
	}
	var err error
	if r.before, err = s.eng.Counters(); err != nil {
		return nil, err
	}
	dir := "-"
	if sp.cg != nil {
		dir = sp.cg.path
	}
	if r.root, err = s.st.spawn(dir, sp.tokens); err != nil {
		return nil, err
	}
	if sp.cg != nil {
		in, err := inCgroup(r.root, sp.cg)
		if err != nil || !in {
			return nil, fmt.Errorf("probe root %d is not in %s (%v)", r.root, sp.cg.path, err)
		}
	}
	if sp.adopt {
		if sp.cg == nil {
			return nil, errors.New("adopt without a cgroup")
		}
		if sp.adoptInit {
			ia, ok := s.eng.(InitAdopter)
			if !ok {
				return nil, errors.New("engine cannot adopt a seeded init")
			}
			if err := ia.AdoptInit(sp.cg.id, r.root); err != nil {
				return nil, fmt.Errorf("adopt probe root as init: %w", err)
			}
		} else if err := s.eng.Adopt(sp.cg.id, r.root); err != nil {
			return nil, fmt.Errorf("adopt probe root: %w", err)
		}
	}
	if err := s.st.release(); err != nil {
		return nil, err
	}
	var duringErr error
	if sp.during != nil {
		duringErr = sp.during(r.root)
	}
	if r.out, err = s.st.collect(sp.timeout); err != nil {
		return nil, errors.Join(duringErr, err)
	}
	if duringErr != nil {
		return nil, duringErr
	}
	// Quiescence: gauges back to where they were and every event the
	// counters promise has been read.
	deadline := time.Now().Add(s.opts.quiesceTimeout())
	for {
		if r.after, err = s.eng.Counters(); err != nil {
			return nil, err
		}
		r.delta = r.after.Sub(r.before)
		if s.opts.Shared {
			r.quiesced = true
			time.Sleep(20 * time.Millisecond)
			break
		}
		if r.after.Pending == r.before.Pending && r.after.Live == r.before.Live && s.eventCount() >= expectedEvents(r.delta) {
			r.quiesced = true
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if r.events, err = s.takeEvents(); err != nil {
		return nil, fmt.Errorf("engine events: %w", err)
	}
	if s.opts.Shared {
		own := r.events[:0]
		for _, ev := range r.events {
			if s.probeCgroup(ev.Cgroup) {
				own = append(own, ev)
			}
		}
		r.events = own
	}
	return r, nil
}

// ranCheck is how strictly the images user space saw running must match the
// completed execs the engine recorded.
type ranCheck int

const (
	ranExact  ranCheck = iota // the same set
	ranSubset                 // every image that reported has a completed exec (a task may be killed before it reports)
	ranSkip                   // not comparable (silent targets, tasks outside the engine)
)

type execKey struct {
	tid uint32
	id  uint64
}

type execGroup struct {
	pid       uint32
	gen       uint64
	passes    int
	blocked   bool
	outcome   uint32
	ret       int32
	decisions []Event
	fault     uint32
}

// invariants checks everything that must hold for ANY probe, deterministic or
// racy: the kernel's records agree with the published policy, with each
// other, with the counters and with what user space saw.
func (s *session) invariants(r *stepResult, ran ranCheck) []string {
	var bad []string
	fail := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	d := r.delta
	if !s.opts.Shared {
		if !r.quiesced {
			fail("engine did not quiesce: pending %d (was %d), live %d (was %d), %d events of %d", r.after.Pending, r.before.Pending, r.after.Live, r.before.Live, len(r.events), expectedEvents(d))
		}
		if d.StalePending != 0 || d.EventLost != 0 || d.StorageFail != 0 {
			fail("engine faults: stale pending %d, events lost %d, storage failures %d", d.StalePending, d.EventLost, d.StorageFail)
		}
		if d.Execs != d.ExecOK+d.ExecFail+d.ExecAbort {
			fail("%d execs decided but %d settled (ok %d, fail %d, abort %d)", d.Execs, d.ExecOK+d.ExecFail+d.ExecAbort, d.ExecOK, d.ExecFail, d.ExecAbort)
		}
		if d.Exits != d.Births+d.Adopted {
			fail("%d tracked tasks exited, %d were born and %d adopted", d.Exits, d.Births, d.Adopted)
		}
	}
	var decisions, allow, deny, would, faults, ok, failed, abort uint64
	groups := map[execKey]*execGroup{}
	var order []*execGroup
	group := func(ev Event) *execGroup {
		k := execKey{ev.TID, ev.ExecID}
		g := groups[k]
		if g == nil {
			g = &execGroup{pid: ev.PID, gen: ev.Gen}
			groups[k] = g
			order = append(order, g)
		}
		return g
	}
	var okOutcomes []Event
	for _, ev := range r.events {
		if !s.probeCgroup(ev.Cgroup) {
			fail("event from cgroup %d, not a probe cgroup: %+v", ev.Cgroup, ev)
			continue
		}
		switch ev.Kind {
		case EventDecision:
			decisions++
			pol, known := s.policies[ev.Gen]
			if !known || pol.cgroup != ev.Cgroup {
				fail("decision under generation %d, never published to cgroup %d", ev.Gen, ev.Cgroup)
				continue
			}
			wantDeny := !pol.allow[ev.File]
			if ev.Mode != pol.mode || ev.Deny != wantDeny || ev.Blocked != (wantDeny && pol.mode == ModeStrict) {
				fail("decision contradicts generation %d (%s, file allowed=%v): %+v", ev.Gen, pol.mode, !wantDeny, ev)
			}
			switch {
			case !ev.Deny:
				allow++
			case ev.Mode == ModeStrict:
				deny++
			default:
				would++
			}
			g := group(ev)
			if g.outcome != 0 || g.blocked {
				fail("decision after the exec was blocked or settled: %+v", ev)
			}
			if int(ev.Pass) != g.passes || ev.Gen != g.gen {
				fail("exec %d/%d: pass %d under generation %d, expected pass %d under generation %d", ev.TID, ev.ExecID, ev.Pass, ev.Gen, g.passes, g.gen)
			}
			g.passes++
			g.blocked = ev.Blocked
			g.decisions = append(g.decisions, ev)
		case EventFault:
			faults++
			if !ev.Blocked {
				fail("fault did not block: %+v", ev)
			}
			if ev.ExecID != 0 {
				g := group(ev)
				g.blocked = true
				g.fault = ev.Fault
			}
		case EventOutcome:
			switch ev.Outcome {
			case OutcomeOK:
				ok++
				okOutcomes = append(okOutcomes, ev)
				continue
			case OutcomeFail:
				failed++
			case OutcomeAbort:
				abort++
			default:
				fail("unknown outcome: %+v", ev)
				continue
			}
			g := groups[execKey{ev.TID, ev.ExecID}]
			if g == nil || g.outcome != 0 {
				fail("outcome without one open exec: %+v", ev)
				continue
			}
			g.outcome, g.ret = ev.Outcome, ev.Ret
		default:
			fail("unknown event: %+v", ev)
		}
	}
	// A completed exec settles as the thread-group leader, whatever thread
	// decided it: match it to the open exec of the same process.
	ranBPF := map[uint32]bool{}
	for _, ev := range okOutcomes {
		ranBPF[ev.PID] = true
		g := groups[execKey{ev.TID, ev.ExecID}]
		if g == nil || g.outcome != 0 || g.pid != ev.PID {
			g = nil
			for _, c := range order {
				if c.pid == ev.PID && c.outcome == 0 && len(c.decisions) > 0 && c.decisions[0].ExecID == ev.ExecID {
					g = c
					break
				}
			}
		}
		if g == nil {
			fail("completed exec without an open decision: %+v", ev)
			continue
		}
		g.outcome = OutcomeOK
	}
	for _, g := range order {
		switch {
		case g.outcome == 0:
			fail("exec of pid %d never settled (leaked pending record)", g.pid)
		case g.blocked && g.outcome == OutcomeOK:
			fail("BLOCKED EXEC COMPLETED: pid %d", g.pid)
		case g.blocked && g.outcome == OutcomeFail && g.ret != -int32(unix.EPERM):
			fail("blocked exec of pid %d failed with %d, not -EPERM", g.pid, g.ret)
		}
	}
	if !s.opts.Shared {
		if decisions != d.Decisions || allow != d.Allow || deny != d.Deny || would != d.WouldDeny {
			fail("decision events (%d: allow %d, deny %d, would-deny %d) disagree with counters (%d: %d, %d, %d)", decisions, allow, deny, would, d.Decisions, d.Allow, d.Deny, d.WouldDeny)
		}
		if faults != d.FaultDeny+d.UnknownExec+d.UnknownFork {
			fail("%d fault events, counters say %d", faults, d.FaultDeny+d.UnknownExec+d.UnknownFork)
		}
		if ok != d.ExecOK || failed != d.ExecFail || abort != d.ExecAbort {
			fail("outcome events (ok %d, fail %d, abort %d) disagree with counters (%d, %d, %d)", ok, failed, abort, d.ExecOK, d.ExecFail, d.ExecAbort)
		}
	}
	// User space and kernel must name the same set of images that ran.
	if ran == ranExact || ran == ranSubset {
		for pid := range r.out.Ran {
			if !ranBPF[pid] {
				fail("pid %d ran its image but the engine recorded no completed exec", pid)
			}
		}
	}
	if ran == ranExact {
		for pid := range ranBPF {
			if !r.out.Ran[pid] {
				fail("engine recorded a completed exec for pid %d but its image never reported", pid)
			}
		}
	}
	return bad
}
