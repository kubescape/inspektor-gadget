// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package selfqual

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Probe is one admission probe. It runs once per mode against the probe
// cgroup bound in that mode.
type Probe struct {
	Name string
	// Proves is the semantics the probe demonstrates; Guards is the
	// fail-open it would catch.
	Proves, Guards string
	// Canary marks the probes cheap enough to repeat after admission.
	Canary bool
	run    func(s *session, cg *cgroupRef) ([]string, error)
}

// errNotApplicable: the kernel cannot produce this exec path at all.
var errNotApplicable = errors.New("not applicable")

// seq runs deterministic tokens in one adopted probe root and checks them
// against the invariants and the model.
func (s *session) seq(cg *cgroupRef, tokens ...string) ([]string, error) {
	r, err := s.step(stepSpec{cg: cg, adopt: true, tokens: tokens})
	if err != nil {
		return nil, err
	}
	return append(s.invariants(r, ranExact), s.exact(r)...), nil
}

func pairs(creators, variants, files []string) []string {
	var out []string
	for _, c := range creators {
		for _, v := range variants {
			for _, f := range files {
				out = append(out, c+"+"+v+":"+f)
			}
		}
	}
	return out
}

func probeBasic(s *session, cg *cgroupRef) ([]string, error) {
	return s.seq(cg, "fork+exec:allow", "fork+exec:deny", "fork+exec:allow")
}

func probeCreators(s *session, cg *cgroupRef) ([]string, error) {
	return s.seq(cg, pairs([]string{"vfork", "clonevm", "spawn"}, []string{"exec"}, []string{"allow", "deny"})...)
}

func probeFdExec(s *session, cg *cgroupRef) ([]string, error) {
	tokens := pairs([]string{"fork"}, []string{"at_empty", "fexecve", "fdpath", "dirfd"}, []string{"allow", "deny", "sh_ok"})
	tokens = append(tokens, "fork+memfd:allow", "vfork+memfd:allow")
	return s.seq(cg, tokens...)
}

func probeScripts(s *session, cg *cgroupRef) ([]string, error) {
	return s.seq(cg, "fork+exec:sh_ok", "fork+exec:sh_deny_interp", "fork+exec:sh_denied", "vfork+exec:sh_deny_interp")
}

func probeExecFailures(s *session, cg *cgroupRef) ([]string, error) {
	return s.seq(cg,
		"fork+exec:missing", "fork+exec:noperm", // fail before the decision hook
		"fork+exec:sh_nointerp", "fork+exec:sh_dirinterp", "fork+exec:garbage", // fail after an allow
		"fork+exec:garbage_denied", // Strict: the deny is the failure; Audit: fails after a would-deny
		"vfork+exec:garbage", "fork+at_empty:garbage",
		"fork+exec:allow", // and the engine still decides afterwards
	)
}

func probeRecursion(s *session, cg *cgroupRef) ([]string, error) {
	return s.seq(cg, "fork+exec:c1", "fork+exec:l1", "fork+exec:allow")
}

func probeBinfmtMisc(s *session, cg *cgroupRef) ([]string, error) {
	if !s.st.binfmt {
		return nil, errNotApplicable
	}
	return s.seq(cg, "fork+exec:bm_file", "fork+at_empty:bm_file")
}

func probeThreads(s *session, cg *cgroupRef) ([]string, error) {
	return s.seq(cg, "thread+exec:allow", "thread+exec:deny", "thread+exec:sh_ok", "thread+at_empty:deny", "thread+exec:garbage")
}

// probeInheritance: lineage, not the current cgroup, carries the binding. A
// child cloned into another cgroup, bound or not, stays under its policy.
func probeInheritance(s *session, cg *cgroupRef) ([]string, error) {
	same, alt := "into@"+cg.path, "into@"+s.alt.path
	return s.seq(cg, same+"+exec:allow", same+"+exec:deny", alt+"+exec:allow", alt+"+exec:deny", alt+"+at_empty:deny")
}

// probeUnknownTask: a task in a bound cgroup that the engine never tracked is
// unknown. Nothing it creates may run, in every mode.
func probeUnknownTask(s *session, cg *cgroupRef) ([]string, error) {
	var bad []string
	fail := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	r, err := s.step(stepSpec{cg: cg, tokens: []string{"fork+exec:allow", "vfork+exec:allow", "self+exec:allow"}})
	if err != nil {
		return nil, err
	}
	bad = append(bad, s.invariants(r, ranExact)...)
	want := []int{300 + int(unix.EPERM), 300 + int(unix.EPERM), int(unix.EPERM)}
	if len(r.out.Results) != len(want) {
		fail("%d results, want %d", len(r.out.Results), len(want))
	}
	for i, res := range r.out.Results {
		if i < len(want) && res.Code != want[i] {
			fail("%s by an unknown task: code %d, want %d", res.Token, res.Code, want[i])
		}
	}
	if len(r.out.Ran) != 0 {
		fail("an unknown task ran %d images", len(r.out.Ran))
	}
	d := r.delta
	if !s.opts.Shared && (d.UnknownFork != 2 || d.UnknownExec != 1 || d.Births != 0 || d.Adopted != 0 || d.Decisions != 0 || d.Execs != 0) {
		fail("unknown task counters: %+v", d)
	}
	faults := 0
	for _, ev := range r.events {
		if ev.Kind == EventFault && ev.Fault == FaultUnknownTask && ev.Blocked && ev.Cgroup == cg.id && ev.PID == r.root {
			faults++
		}
	}
	if faults != 3 || len(r.events) != 3 {
		fail("unknown task: %d unknown-task faults in %d events, want 3 of 3", faults, len(r.events))
	}
	// A process outside every probe cgroup clones a child straight into the
	// bound cgroup: that child is unknown too.
	r, err = s.step(stepSpec{tokens: []string{"into@" + cg.path + "+exec:allow"}})
	if err != nil {
		return nil, err
	}
	bad = append(bad, s.invariants(r, ranExact)...)
	if len(r.out.Results) != 1 || r.out.Results[0].Code != int(unix.EPERM) || len(r.out.Ran) != 0 {
		fail("child cloned into the bound cgroup by an untracked parent: %+v", r.out.Results)
	}
	if !s.opts.Shared && (r.delta.UnknownExec != 1 || r.delta.Decisions != 0) {
		fail("cloned-in unknown child counters: %+v", r.delta)
	}
	return bad, nil
}

// probeUnbound: the engine must not touch, count or report tasks that are in
// no bound cgroup and have no bound lineage.
func probeUnbound(s *session, cg *cgroupRef) ([]string, error) {
	var bad []string
	for _, where := range []*cgroupRef{nil, s.alt} {
		r, err := s.step(stepSpec{cg: where, tokens: []string{"fork+exec:deny", "fork+exec:allow", "fork+memfd:allow", "thread+exec:deny"}})
		if err != nil {
			return nil, err
		}
		bad = append(bad, s.invariants(r, ranSkip)...)
		for _, res := range r.out.Results {
			if res.Code != 0 || !r.out.Ran[res.PID] {
				bad = append(bad, fmt.Sprintf("unbound task: %s code %d ran=%v", res.Token, res.Code, r.out.Ran[res.PID]))
			}
		}
		if len(r.out.Results) != 4 || len(r.events) != 0 || (!s.opts.Shared && r.delta != (Counters{Pending: r.before.Pending, Live: r.before.Live})) {
			bad = append(bad, fmt.Sprintf("unbound task was observed: %d results, %d events, counters %+v", len(r.out.Results), len(r.events), r.delta))
		}
	}
	return bad, nil
}

// probeInjectedFault: a fault before classification denies in every mode.
func probeInjectedFault(s *session, cg *cgroupRef) (bad []string, err error) {
	fail := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	if err := s.eng.InjectFault(cg.id, true); err != nil {
		return nil, err
	}
	r, err := s.step(stepSpec{cg: cg, adopt: true, tokens: []string{"fork+exec:allow", "fork+exec:deny", "fork+exec:sh_ok"}})
	if offErr := s.eng.InjectFault(cg.id, false); offErr != nil {
		return nil, offErr
	}
	if err != nil {
		return nil, err
	}
	bad = append(bad, s.invariants(r, ranExact)...)
	for _, res := range r.out.Results {
		if res.Code != int(unix.EPERM) {
			fail("%s under a pre-classification fault: code %d, want EPERM in %s", res.Token, res.Code, cg.mode)
		}
	}
	if len(r.out.Results) != 3 || len(r.out.Ran) != 0 {
		fail("pre-classification fault: %d results, %d images ran", len(r.out.Results), len(r.out.Ran))
	}
	d := r.delta
	if !s.opts.Shared && (d.FaultDeny != 3 || d.Decisions != 0 || d.Execs != 3 || d.ExecFail != 3) {
		fail("pre-classification fault counters: %+v", d)
	}
	for _, ev := range r.events {
		if ev.Kind == EventFault && ev.Fault != FaultInjected {
			fail("unexpected fault %+v", ev)
		}
	}
	// The fault is gone: the engine classifies again.
	after, err := s.seq(cg, "fork+exec:allow", "fork+exec:deny")
	return append(bad, after...), err
}

// probeExecveCheck: AT_EXECVE_CHECK runs nothing and leaves no record; a real
// exec of the same file afterwards is decided normally.
func probeExecveCheck(s *session, cg *cgroupRef) ([]string, error) {
	return s.seq(cg, "fork+check:allow", "fork+check:deny", "fork+exec:deny", "fork+exec:allow")
}

// held runs one exec of sh_hold in an adopted probe root, parks it between
// its two binfmt passes and calls while parked.
func (s *session) held(cg *cgroupRef, tokens []string, parked func(h heldExec) error) (*stepResult, error) {
	return s.heldOn("hold_interp", cg, tokens, parked)
}

// heldOn parks the first exec that opens the fixture file for execution.
func (s *session) heldOn(file string, cg *cgroupRef, tokens []string, parked func(h heldExec) error) (*stepResult, error) {
	hold, err := newHolder(s.st.hostPath(file))
	if err != nil {
		return nil, err
	}
	defer hold.close()
	return s.step(stepSpec{cg: cg, adopt: true, tokens: tokens, during: func(uint32) error {
		h, err := hold.wait(s.opts.probeTimeout())
		if err != nil {
			return err
		}
		// The exec is parked after its first decision: one pending record.
		if !s.opts.Shared && !s.opts.NoPendingGauge {
			c, err := s.eng.Counters()
			if err != nil {
				hold.allow(h)
				return err
			}
			if c.Pending != 1 {
				hold.allow(h)
				return fmt.Errorf("parked exec: %d pending records, want 1", c.Pending)
			}
		}
		err = parked(h)
		// Release the parked exec; every later exec of the interpreter in
		// this step passes straight through.
		hold.allow(h)
		hold.passThrough()
		return err
	}})
}

// probeExitMidExec: a task killed between its decision and its outcome leaves
// no pending record.
func probeExitMidExec(s *session, cg *cgroupRef) (bad []string, err error) {
	var victim uint32
	r, err := s.held(cg, []string{"fork+exec:sh_hold", "fork+exec:allow"}, func(h heldExec) error {
		victim = h.PID
		return killParked(h.PID, s.opts.probeTimeout())
	})
	if err != nil {
		return nil, err
	}
	bad = append(bad, s.invariants(r, ranExact)...)
	fail := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	if len(r.out.Results) != 2 || r.out.Results[0].Code != 1000+int(unix.SIGKILL) || r.out.Results[0].PID != victim || r.out.Results[1].Code != 0 {
		fail("kill mid-exec: results %+v, victim %d", r.out.Results, victim)
	}
	// The killed exec settles exactly once. Which hook settles it is the
	// kernel's choice: the failed execve's syscall exit runs before the
	// fatal signal is delivered on every kernel tested, and task exit is the
	// backstop if it ever does not.
	d := r.delta
	if !s.opts.Shared && (d.ExecFail+d.ExecAbort != 1 || d.Execs != 2 || d.ExecOK != 1 || d.Decisions != 2) {
		fail("kill mid-exec counters: %+v", d)
	}
	return bad, nil
}

// probeFrozenGeneration: an exec parked between passes while the generation
// switches finishes under the generation it started with; the next exec runs
// under the new one.
func probeFrozenGeneration(s *session, cg *cgroupRef) (bad []string, err error) {
	fail := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	old := cg.gen
	var next uint64
	var without []string
	for _, name := range baseAllow {
		if name != "hold_interp" {
			without = append(without, name)
		}
	}
	r, err := s.held(cg, []string{"fork+exec:sh_hold", "fork+exec:sh_hold"}, func(h heldExec) error {
		var err error
		next, err = s.publish(cg, without)
		return err
	})
	if err != nil {
		return nil, err
	}
	bad = append(bad, s.invariants(r, ranExact)...)
	if len(r.out.Results) != 2 {
		fail("frozen generation: results %+v", r.out.Results)
		return bad, nil
	}
	first, second := r.out.Results[0], r.out.Results[1]
	wantSecond := 0
	if cg.mode == ModeStrict {
		wantSecond = int(unix.EPERM)
	}
	if first.Code != 0 || second.Code != wantSecond {
		fail("frozen generation: parked exec code %d (want 0), next exec code %d (want %d)", first.Code, second.Code, wantSecond)
	}
	for _, ev := range r.events {
		if ev.Kind != EventDecision {
			continue
		}
		switch ev.PID {
		case first.PID:
			if ev.Gen != old || ev.Deny {
				fail("parked exec decided under generation %d deny=%v, want %d allow: %+v", ev.Gen, ev.Deny, old, ev)
			}
		case second.PID:
			if ev.Gen != next {
				fail("next exec decided under generation %d, want %d", ev.Gen, next)
			}
			if ev.Pass == 1 && !ev.Deny {
				fail("next exec's interpreter was allowed under generation %d", next)
			}
		}
	}
	if _, err := s.publish(cg, baseAllow); err != nil {
		return bad, err
	}
	return bad, errors.Join(s.eng.Retire(cg.id, old), s.eng.Retire(cg.id, next))
}

// probeRetiredGeneration: an exec whose generation disappears between passes
// cannot be classified. It is denied in every mode.
func probeRetiredGeneration(s *session, cg *cgroupRef) (bad []string, err error) {
	fail := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	old := cg.gen
	r, err := s.held(cg, []string{"fork+exec:sh_hold", "fork+exec:sh_hold"}, func(h heldExec) error {
		if _, err := s.publish(cg, baseAllow); err != nil {
			return err
		}
		return s.eng.Retire(cg.id, old)
	})
	if err != nil {
		return nil, err
	}
	bad = append(bad, s.invariants(r, ranExact)...)
	if len(r.out.Results) != 2 || r.out.Results[0].Code != int(unix.EPERM) || r.out.Results[1].Code != 0 {
		fail("retired generation: results %+v, want EPERM then 0 in %s", r.out.Results, cg.mode)
	}
	d := r.delta
	if !s.opts.Shared && (d.FaultDeny != 1 || d.Execs != 2 || d.ExecFail != 1 || d.ExecOK != 1 || d.Decisions != 3) {
		fail("retired generation counters: %+v", d)
	}
	faults := 0
	for _, ev := range r.events {
		if ev.Kind == EventFault {
			faults++
			if ev.Fault != FaultNoGeneration || ev.Gen != old {
				fail("retired generation fault: %+v", ev)
			}
		}
	}
	if faults != 1 {
		fail("retired generation: %d fault events, want 1", faults)
	}
	return bad, nil
}

// probeStorm: workers exec an allowed and a denied file in a loop while the
// generation switches between two policies that swap which one is allowed.
// Every decision must match the generation it names, every outcome must match
// its decision, and no worker may ever see an older generation again.
func probeStorm(s *session, cg *cgroupRef) (bad []string, err error) {
	fail := func(format string, a ...any) {
		if len(bad) < 20 {
			bad = append(bad, fmt.Sprintf(format, a...))
		}
	}
	workers, iters := s.opts.stormWorkers(), s.opts.stormIters()
	total := uint64(workers * iters * 2)
	sides := [][]string{{"allow"}, {"deny"}}
	first, err := s.publish(cg, sides[0])
	if err != nil {
		return nil, err
	}
	gens := []uint64{first}
	const switches = 3
	r, err := s.step(stepSpec{cg: cg, adopt: true, timeout: 4 * s.opts.probeTimeout(),
		tokens: []string{fmt.Sprintf("storm:%d:%d:allow:deny", workers, iters)},
		during: func(uint32) error {
			base, err := s.eng.Counters()
			if err != nil {
				return err
			}
			deadline := time.Now().Add(3 * s.opts.probeTimeout())
			for k := 1; k <= switches; k++ {
				for {
					c, err := s.eng.Counters()
					if err != nil {
						return err
					}
					if c.Execs-base.Execs >= total*uint64(k)/(switches+1) {
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("storm stalled at %d of %d execs", c.Execs-base.Execs, total)
					}
					time.Sleep(200 * time.Microsecond)
				}
				gen, err := s.publish(cg, sides[k%2])
				if err != nil {
					return err
				}
				gens = append(gens, gen)
			}
			return nil
		}})
	if err != nil {
		return nil, err
	}
	bad = append(bad, s.invariants(r, ranSkip)...)
	decisions := map[uint32][]Event{}
	perGen := map[uint64]int{}
	for _, ev := range r.events {
		if ev.Kind == EventDecision {
			decisions[ev.PID] = append(decisions[ev.PID], ev)
			perGen[ev.Gen]++
		}
	}
	if uint64(len(r.out.Storm)) != total {
		fail("storm: %d attempts reported, want %d", len(r.out.Storm), total)
	}
	last := map[int]uint64{}
	for _, line := range r.out.Storm {
		ds := decisions[line.PID]
		if len(ds) != 1 {
			fail("storm: pid %d (%s) has %d decisions", line.PID, line.File, len(ds))
			continue
		}
		d := ds[0]
		if d.File != s.st.files[line.File] {
			fail("storm: pid %d execed %s, decision names another file: %+v", line.PID, line.File, d)
		}
		want := 0
		if d.Blocked {
			want = int(unix.EPERM)
		}
		if line.Code != want {
			fail("storm: pid %d (%s) code %d but the engine decided blocked=%v under generation %d", line.PID, line.File, line.Code, d.Blocked, d.Gen)
		}
		if d.Gen < last[line.Worker] {
			fail("storm: worker %d went back from generation %d to %d", line.Worker, last[line.Worker], d.Gen)
		}
		last[line.Worker] = d.Gen
	}
	for _, gen := range gens {
		if perGen[gen] == 0 {
			fail("storm: no exec was decided under generation %d: the switch raced nothing", gen)
		}
	}
	if !s.opts.Shared && r.delta.Execs != total {
		fail("storm: %d execs decided, want %d", r.delta.Execs, total)
	}
	if _, err := s.publish(cg, baseAllow); err != nil {
		return bad, err
	}
	for _, gen := range gens {
		err = errors.Join(err, s.eng.Retire(cg.id, gen))
	}
	return bad, err
}

// probeRaces: execs racing thread-group exit, sibling execs and SIGKILL. The
// outcomes are not deterministic; the invariants are.
func probeRaces(s *session, cg *cgroupRef) (bad []string, err error) {
	var tokens []string
	for i := 0; i < s.opts.raceRounds(); i++ {
		tokens = append(tokens, "exitrace+exec:allow", "killrace+exec:sh_ok", "threadrace+exec:allow",
			"exitrace+exec:deny", "killrace+exec:deny", "threadrace+exec:sh_deny_interp", "killrace+exec:c1", "exitrace+exec:garbage")
	}
	r, err := s.step(stepSpec{cg: cg, adopt: true, tokens: tokens, timeout: 2 * s.opts.probeTimeout()})
	if err != nil {
		return nil, err
	}
	bad = append(bad, s.invariants(r, ranSubset)...)
	if len(r.out.Results) != len(tokens) {
		bad = append(bad, fmt.Sprintf("races: %d results for %d tokens", len(r.out.Results), len(tokens)))
	}
	for _, res := range r.out.Results {
		if res.Code >= 300 && res.Code < 1000 || res.Code == 71 {
			bad = append(bad, fmt.Sprintf("races: %s could not run: code %d", res.Token, res.Code))
		}
		// Whatever raced, a denied file's image never runs under Strict.
		if cg.mode == ModeStrict && r.out.Ran[res.PID] && (strings.HasSuffix(res.Token, ":deny") || strings.HasSuffix(res.Token, ":sh_deny_interp")) {
			bad = append(bad, fmt.Sprintf("races: %s RAN under Strict", res.Token))
		}
	}
	return bad, nil
}

// Probes is the admission suite, in run order.
var Probes = []Probe{
	{Name: "basic", Canary: true, run: probeBasic,
		Proves: "allow runs; Strict deny is EPERM; Audit deny runs and is reported would_deny; each exec has one decision and one outcome",
		Guards: "decision hook not firing or its verdict ignored (no bpf LSM, ftrace off, hook detached)"},
	{Name: "creators", run: probeCreators,
		Proves: "vfork, clone(CLONE_VM) and posix_spawn children inherit the binding",
		Guards: "a creation path whose child is untracked or undecided"},
	{Name: "fd-exec", Canary: true, run: probeFdExec,
		Proves: "execveat(AT_EMPTY_PATH), fexecve, /proc/self/fd and dirfd execs are decided on the file's identity; a memfd copy of an allowed file is not that file",
		Guards: "path-less or fd-based exec bypassing the decision"},
	{Name: "scripts", run: probeScripts,
		Proves: "every binfmt pass is decided: an allowed script with a denied interpreter is blocked, a denied script never reaches its interpreter",
		Guards: "interpreter pass not evaluated"},
	{Name: "exec-failures", run: probeExecFailures,
		Proves: "ENOENT/EACCES before the hook leave no record; ENOENT (missing interpreter), EACCES (bad interpreter) and ENOEXEC after an allow or a would-deny settle as failures with the kernel's errno",
		Guards: "a failed exec leaking its pending record, later mistaken for a continuation"},
	{Name: "recursion", run: probeRecursion,
		Proves: "a five-deep #! chain is decided on six passes and runs; a six-deep chain is refused ELOOP after six decisions",
		Guards: "nested interpreter passes skipped or mis-counted"},
	{Name: "binfmt-misc", run: probeBinfmtMisc,
		Proves: "a binfmt_misc interpreter is a decided pass like a #! interpreter",
		Guards: "binfmt_misc handler bypassing the per-pass decision"},
	{Name: "threads", run: probeThreads,
		Proves: "exec from a non-leader thread (de_thread) is decided, settles on the surviving leader and leaves no dead-thread residue",
		Guards: "multi-threaded exec escaping or leaking"},
	{Name: "inheritance", run: probeInheritance,
		Proves: "clone3(CLONE_INTO_CGROUP) into the same, or into an unbound, cgroup keeps the child under its lineage's policy",
		Guards: "escaping a binding by being born in another cgroup"},
	{Name: "unknown-task", run: probeUnknownTask,
		Proves: "an untracked task in a bound cgroup cannot fork or exec, in every mode; a child cloned into the cgroup by an outsider is unknown",
		Guards: "untracked task allowed by default"},
	{Name: "unbound", run: probeUnbound,
		Proves: "tasks outside every binding are neither blocked, counted nor reported",
		Guards: "engine blocking or mis-attributing foreign tasks (which would also corrupt the counters every other probe relies on)"},
	{Name: "injected-fault", run: probeInjectedFault,
		Proves: "a fault before classification is EPERM in Strict AND Audit, counted, and recoverable",
		Guards: "fault paths that fall through to allow"},
	{Name: "execve-check", run: probeExecveCheck,
		Proves: "AT_EXECVE_CHECK (or its EINVAL) runs nothing and leaves no record",
		Guards: "a check-only exec leaking a pending record"},
	{Name: "exit-mid-exec", run: probeExitMidExec,
		Proves: "SIGKILL between the script's decision and the interpreter's (parked with fanotify) settles the record exactly once",
		Guards: "pending record leaked by task death"},
	{Name: "frozen-generation", run: probeFrozenGeneration,
		Proves: "an exec parked across a generation switch finishes under its first generation; the next exec is decided under the new one",
		Guards: "one exec evaluated under two generations"},
	{Name: "retired-generation", run: probeRetiredGeneration,
		Proves: "an exec whose generation is retired between passes is denied in every mode (a natural pre-classification fault)",
		Guards: "missing policy state treated as allow"},
	{Name: "storm", run: probeStorm,
		Proves: "under a concurrent exec storm with three generation switches every decision matches the generation it names, every outcome matches its decision, and no worker goes back a generation",
		Guards: "non-atomic publication (statistical)"},
	{Name: "races", run: probeRaces,
		Proves: "execs racing exit_group, sibling execs and SIGKILL settle every record; a denied image never runs under Strict",
		Guards: "rare-race leaks and bypasses (statistical)"},
}
