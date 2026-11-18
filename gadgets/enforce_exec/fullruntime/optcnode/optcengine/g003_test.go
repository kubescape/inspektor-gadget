// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package optcengine_test

// G003: experiments E2 (recorded actor facts, the ancestor walk through task
// storage on real_parent: R15, R16), E3 (generation retire during parked
// multi-pass execs and the storm, no drain: R6) and E4 (the witness without
// sys_exit and the exec-receipt guard, with ftrace off: R26) of design 005
// §9.4, on the option C engine of E1.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/optcengine"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/selfqual"
)

// actorPolicy denies curl when the actor's recorded exe is one of paths. It
// is an audit-mode policy in both bindings: an actor-path predicate is
// consulted before the target, so under an enforced rule every exec by a
// task whose exe facts are UNKNOWN (the adopted probe root, R15) would be an
// evaluation error. The decision still shows whether the recorded fact
// matched (deny, error 0) or not.
func (o *oracle) actorPolicy(paths ...string) fullpolicy.Policy {
	return fullpolicy.Policy{ID: "e2-actor", Revision: "1", Mode: fullpolicy.Audit, Default: fullpolicy.Allow, Rules: []fullpolicy.Rule{
		{Name: "deny-curl-by-actor", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{Path: o.paths(paths...)}, Target: fullpolicy.Target{Path: o.paths("curl")}},
	}}
}

// ancestorPolicy denies curl when an ancestor within depth is one of paths.
func (o *oracle) ancestorPolicy(depth int32, paths ...string) fullpolicy.Policy {
	return fullpolicy.Policy{ID: "e2-ancestor", Revision: "1", Mode: o.fpMode(), Default: fullpolicy.Allow, Rules: []fullpolicy.Rule{
		{Name: "deny-curl-by-ancestor", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{Ancestor: &fullpolicy.Ancestor{Path: o.paths(paths...), Depth: depth}}, Target: fullpolicy.Target{Path: o.paths("curl")}},
	}}
}

// curlDecision is the one decision for the curl path among pids no result
// names (curl exec'ed by a task the harness does not report), or by pid.
func (o *oracle) curlDecisions(obs selfqual.Observation) []optcengine.Detail {
	var out []optcengine.Detail
	seen := map[uint32]bool{}
	for _, ev := range obs.Events {
		if ev.Kind != selfqual.EventDecision || seen[ev.PID] {
			continue
		}
		seen[ev.PID] = true
		for _, d := range o.details(ev.PID, selfqual.EventDecision) {
			if d.Path == o.h.Path("curl") {
				out = append(out, d)
			}
		}
	}
	return out
}

func (o *oracle) wantOneCurl(obs selfqual.Observation, what string, deny bool, unknown bool) {
	o.wantOneCurlMode(obs, what, deny, unknown, o.strict())
}

// wantAuditCurl: the deciding rule is audit-mode (never blocks).
func (o *oracle) wantAuditCurl(obs selfqual.Observation, what string, deny bool) {
	o.wantOneCurlMode(obs, what, deny, false, false)
}

func (o *oracle) wantOneCurlMode(obs selfqual.Observation, what string, deny bool, unknown bool, enforced bool) {
	ds := o.curlDecisions(obs)
	if len(ds) != 1 {
		o.errorf("%s: %d curl decisions, want 1: %+v", what, len(ds), ds)
		return
	}
	d := ds[0]
	switch {
	case unknown && enforced:
		if !d.Deny || !d.Blocked || d.Error == 0 {
			o.errorf("%s: %+v, want an evaluation error that denies (UNKNOWN fact)", what, d)
		}
	case unknown:
		if d.Blocked || d.AuditUnknown == 0 {
			o.errorf("%s: %+v, want audit-unknown, not blocked", what, d)
		}
	default:
		if d.Deny != deny || d.Error != 0 || d.Blocked != (deny && enforced) {
			o.errorf("%s: deny=%v error=%d blocked=%v, want deny=%v by a known fact", what, d.Deny, d.Error, d.Blocked, deny)
		}
	}
}

// g003Scenarios run in TestOracle-style per mode (TestG003).
var g003Scenarios = []scenario{
	// ---------------------------------------------------------------- E2
	{"E2_ActorFactsAreTheFinalPass_Interpreter", func(o *oracle) {
		// sh_ok's interpreter is allow: the recorded actor is allow.
		o.publish(o.allowList(e1Allow()...), o.actorPolicy("allow"))
		// The root first becomes plain: every actor below has known facts
		// (a rule's actor-path predicate is consulted before its target).
		obs := o.run("self+rerun:plain,via:sh_ok:fork+exec:curl")
		o.wantAuditCurl(obs, "curl from the interpreter of sh_ok", true)
	}},
	{"E2_ActorFactsSurviveRenameAndReplaceOnDisk", func(o *oracle) {
		o.publish(o.allowList(e1Allow("renamee")...), o.actorPolicy("renamee"))
		obs := o.run("self+rerun:plain,via:renamee:rename:renamee>renamed;replace:renamee;fork+exec:curl")
		for _, tok := range []string{"rename:renamee>renamed", "replace:renamee"} {
			if r, _ := o.result(obs, tok); r.Code != 0 {
				o.errorf("%s: code %d", tok, r.Code)
			}
		}
		// Recorded at exec: still renamee (a live read would see renamed).
		o.wantAuditCurl(obs, "curl after the actor's binary was renamed and replaced", true)
	}},
	{"E2_AncestorWithinDepthMatches", func(o *oracle) {
		o.publish(o.allowList(e1Allow()...), o.ancestorPolicy(4, "setter"))
		obs := o.run("self+rerun:plain,chain:5:3:fork+exec:curl")
		o.wantOneCurl(obs, "curl with setter 3 levels up", true, false)
	}},
	{"E2_AncestorBeyondTheDepthLimitDoesNotMatch", func(o *oracle) {
		// 21 ancestors: the walk keeps 16 (known prefix, incomplete); the
		// setter at level 18 is beyond any policy depth (max 16).
		o.publish(o.allowList(e1Allow()...), o.ancestorPolicy(16, "setter"))
		obs := o.run("self+rerun:plain,chain:20:18:fork+exec:curl")
		o.wantOneCurl(obs, "curl with setter 18 levels up", false, false)
	}},
	{"E2_AncestorWithUnknownExeMakesTheFactUnknown", func(o *oracle) {
		// The adopted root's exe facts are UNKNOWN (R15): a walk through it
		// is UNKNOWN as a whole, never a shorter complete chain.
		o.publish(o.allowList(e1Allow()...), o.ancestorPolicy(4, "setter"))
		obs := o.run("chain:1:9:fork+exec:curl")
		o.wantOneCurl(obs, "curl whose grandparent's exe is UNKNOWN", true, true)
	}},
	{"KnownGapProbe_ReparentedTaskLosesItsOriginalAncestry", func(o *oracle) {
		// Known gap (R16, review E2-1): the walk follows real_parent, so
		// orphaning or double-forking loses the original ancestry, as in
		// the product. g is forked by a setter process that exits at once;
		// g is reparented to the root (plain, a subreaper), then execs curl:
		// the setter is no longer an ancestor.
		o.publish(o.allowList(e1Allow()...), o.ancestorPolicy(1, "setter"))
		obs := o.run("self+rerun:plain,subreaper,orphan:setter:self+exec:curl,reapall")
		o.wantOneCurl(obs, "curl from a task reparented to the subreaper", false, false)
	}},
	{"R4_BlockedExecLeavesNoWorkArea", func(o *oracle) {
		// Review R4: a Strict-blocked exec deletes its work area at once;
		// an Audit exec commits and deletes it at commit.
		pidfile := o.h.HostPath("ready")
		var found, err2 = true, error(nil)
		// A root that stays alive after its own blocked exec.
		obs, err := o.h.Run(selfqual.Where{Mode: o.mode, Adopt: true, During: func() error {
			for i := 0; i < 5000; i++ {
				if _, err := os.Stat(pidfile); err == nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			root, rerr := rootOf(o)
			if rerr == nil {
				found, err2 = o.eng.WorkArea(root)
				unix.Close(root)
			} else {
				err2 = rerr
			}
			return os.WriteFile(o.h.HostPath("go"), nil, 0o644)
		}}, "fork+exec:allow", "self+exec:deny", "touch:ready", "waitfile:go")
		if err != nil {
			o.fatalf("%v", err)
		}
		if o.strict() {
			if r, _ := o.result(obs, "self+exec:deny"); r.Code != ePERM {
				o.errorf("strict self exec of deny: code %d", r.Code)
			}
			if err2 != nil || found {
				o.errorf("blocked exec left its work area (found=%v, %v)", found, err2)
			}
		}
		if ready, err := o.eng.Ready(); !ready || err != nil {
			o.errorf("engine not Ready after the scenario (%v)", err)
		}
	}},
	// ---------------------------------------------------------------- E3
	{"R2_ReevaluationSeesCommittedRolesValidForNextGen", func(o *oracle) {
		// Review R2: N+1 holds an enforced role rule; the straddling exec's
		// committed role (clean) is valid for N+1's (uid, epoch), so the
		// re-evaluation sees it and must not kill.
		// Generation N's role policy carries a role rule (for plain, not
		// run here): under R1 only role-bearing policies have a row, and
		// without one the role would be UNKNOWN under N+1.
		n := o.publish(o.allowList(e1Allow()...), rolePolicy(o.fpMode(), o.setRule("tainted", "plain")))
		next := []fullpolicy.Policy{o.allowList(e1Allow()...), rolePolicy(o.fpMode(), o.setRule("tainted", "plain"), o.denyIfRole("tainted", "dyn"))}
		obs, err := o.h.RunHeldOn(o.mode, "ldso", func(uint32) error {
			nn, err := o.eng.PublishPolicies(o.cg(), next)
			if err != nil {
				return err
			}
			o.h.SetGeneration(o.mode, nn)
			return o.eng.Retire(o.cg(), n)
		}, "fork+exec:dyn")
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		r, _ := o.result(obs, "fork+exec:dyn")
		c, _ := o.commit(r.PID)
		if r.Code != 0 || !r.Ran || c.Flags&optcengine.CommitKilled != 0 || c.Flags&optcengine.CommitReevalDeny != 0 || c.Flags&optcengine.CommitGenMismatch == 0 {
			o.errorf("straddling exec, N+1 role rule, role clean: %+v flags %#x, want it to run, not killed, no re-evaluation deny", r, c.Flags)
		}
	}},
	{"E3_StormWithImmediateRetireNoDrain", func(o *oracle) {
		const workers, iters, switches = 8, 150, 5
		total := workers * iters * 2
		allowed := map[uint64]string{}
		prev, err := o.h.Publish(o.mode, "allow")
		if err != nil {
			o.fatalf("%v", err)
		}
		allowed[prev] = "allow"
		var maxPublish time.Duration
		obs, err := o.h.Run(selfqual.Where{Mode: o.mode, Adopt: true, Timeout: 120 * time.Second, During: func() error {
			base, err := o.h.Counters()
			if err != nil {
				return err
			}
			deadline := time.Now().Add(90 * time.Second)
			for k := 1; k <= switches; k++ {
				for {
					c, err := o.h.Counters()
					if err != nil {
						return err
					}
					if c.Execs-base.Execs >= uint64(total*k/(switches+1)) {
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("storm stalled")
					}
				}
				name := []string{"allow", "deny"}[k%2]
				t0 := time.Now()
				gen, err := o.h.Publish(o.mode, name)
				if err != nil {
					return err
				}
				// No drain: the previous generation is retired at once.
				if err := o.h.Retire(o.mode, prev); err != nil {
					return err
				}
				if dt := time.Since(t0); dt > maxPublish {
					maxPublish = dt
				}
				allowed[gen] = name
				prev = gen
			}
			return nil
		}}, fmt.Sprintf("storm:%d:%d:allow:deny", workers, iters))
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		if maxPublish > time.Second {
			o.errorf("publish + retire took %v", maxPublish)
		}
		dec := map[uint32][]selfqual.Event{}
		faults := map[uint32]bool{}
		for _, ev := range obs.Events {
			switch ev.Kind {
			case selfqual.EventDecision:
				dec[ev.PID] = append(dec[ev.PID], ev)
			case selfqual.EventFault:
				if ev.Fault != selfqual.FaultNoGeneration || ev.Blocked != o.strict() {
					o.errorf("unexpected fault %+v", ev)
				}
				faults[ev.PID] = true
			}
		}
		if len(obs.Storm) != total {
			o.fatalf("%d attempts, want %d", len(obs.Storm), total)
		}
		bad, retired, straddled, midPass := 0, 0, 0, 0
		for _, a := range obs.Storm {
			ds := dec[a.PID]
			switch {
			case faults[a.PID]:
				// Frozen generation retired before its pass (R6 b).
				retired++
				if o.strict() && a.Code != ePERM || !o.strict() && a.Code != 0 {
					bad++
					o.errorf("retired-generation fault, attempt %+v: want %v", a, map[bool]string{true: "EPERM", false: "run"}[o.strict()])
				}
			case len(ds) != 1:
				bad++
				o.errorf("attempt %+v: %d decisions", a, len(ds))
			case o.decisionError(a.PID) != 0 && ds[0].Gen != prev:
				// Its generation was retired while its rule windows ran:
				// the blobs vanished mid-evaluation, an evaluation error
				// (R6 b, the class decides): Strict denies, Audit allows.
				midPass++
				if o.strict() && a.Code != ePERM || !o.strict() && a.Code != 0 {
					bad++
					o.errorf("retired mid-pass, attempt %+v: want %v", a, map[bool]string{true: "EPERM", false: "run"}[o.strict()])
				}
			default:
				name, known := allowed[ds[0].Gen]
				wantDeny := name != a.File
				ok := known && ds[0].Deny == wantDeny
				switch {
				case wantDeny && o.strict():
					ok = ok && a.Code == ePERM
				case o.strict() && a.Code == killed:
					// Compromise-8 alternative: straddled, N+1 denies.
					// Review E3-1: only with the commit's own evidence.
					cs := o.details(a.PID, optcengine.EventCommit)
					ok = ok && len(cs) == 1 && cs[0].Flags&optcengine.CommitKilled != 0 && cs[0].Flags&optcengine.CommitGenMismatch != 0
					straddled++
				default:
					ok = ok && a.Code == 0
				}
				if !ok {
					bad++
					if bad <= 5 {
						o.errorf("attempt %+v decided %+v under a generation allowing %q", a, ds[0], name)
					}
				}
			}
		}
		o.t.Logf("storm with immediate retire: %d attempts, %d hit a retired generation (R6 b fault), %d retired mid-pass (evaluation error), %d straddlers killed, max publish+retire %v", total, retired, midPass, straddled, maxPublish)
		if bad != 0 {
			o.errorf("%d attempts violate R6", bad)
		}
	}},
}

// rootOf opens a pidfd for the probe root: the stage's child running tokens
// in the mode's cgroup (the newest task in that cgroup).
func rootOf(o *oracle) (int, error) {
	b, err := os.ReadFile(o.h.CgroupPath(o.mode) + "/cgroup.procs")
	if err != nil {
		return -1, err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return -1, fmt.Errorf("no task in %s", o.h.CgroupPath(o.mode))
	}
	var pid int
	fmt.Sscanf(f[0], "%d", &pid)
	return unix.PidfdOpen(pid, 0)
}

func (o *oracle) decisionError(pid uint32) uint32 {
	for _, d := range o.details(pid, selfqual.EventDecision) {
		if d.Error != 0 {
			return d.Error
		}
	}
	return 0
}

// TestG003 runs the E2 and E3 scenarios, Strict and Audit. The E3 parked
// multi-pass retire and switch scenarios are TestOracle's
// RetiredGenerationMidExec_StrictDeniesAuditAllows and
// ExecParkedAcrossGenerationSwitch_Compromise8Alternative.
func TestG003(t *testing.T) {
	requireOracle(t)
	for _, mode := range modes() {
		t.Run(mode.String(), func(t *testing.T) {
			for _, sc := range g003Scenarios {
				t.Run(sc.name, func(t *testing.T) {
					for _, e := range runScenario(t, mode, engineSetup{}, sc) {
						t.Error(e)
					}
				})
			}
		})
	}
}

// TestG003Mutants: each E2/E3 mutant fails the scenario guarding it.
func TestG003Mutants(t *testing.T) {
	requireOracle(t)
	all := map[string]scenario{}
	for _, sc := range append(append(append([]scenario{}, d4Scenarios...), e1Scenarios...), g003Scenarios...) {
		all[sc.name] = sc
	}
	S, A := selfqual.ModeStrict, selfqual.ModeAudit
	cases := []mutantCase{
		{optcengine.MutantActorFirstPass, S, "E2_ActorFactsAreTheFinalPass_Interpreter", "want deny=true by a known fact"},
		{optcengine.MutantActorFirstPass, A, "E2_ActorFactsAreTheFinalPass_Interpreter", "want deny=true by a known fact"},
		{optcengine.MutantAncestorOff, S, "E2_AncestorWithinDepthMatches", "want deny=true by a known fact"},
		{optcengine.MutantAncestorOff, A, "E2_AncestorWithinDepthMatches", "want deny=true by a known fact"},
		{optcengine.MutantAncestorSkipUnknown, S, "E2_AncestorWithUnknownExeMakesTheFactUnknown", "want an evaluation error"},
		{optcengine.MutantAncestorSkipUnknown, A, "E2_AncestorWithUnknownExeMakesTheFactUnknown", "want audit-unknown"},
		{optcengine.MutantNoFreeze, S, "ExecParkedAcrossGenerationSwitch_Compromise8Alternative", "parked exec decided under generation"},
		{optcengine.MutantNoFreeze, A, "ExecParkedAcrossGenerationSwitch_Compromise8Alternative", "parked exec decided under generation"},
		{optcengine.MutantRetiredAllows, S, "RetiredGenerationMidExec_StrictDeniesAuditAllows", "strict:"},
		{optcengine.MutantReevalNoRoles, S, "R2_ReevaluationSeesCommittedRolesValidForNextGen", "no re-evaluation deny"},
		{optcengine.MutantKeepBlockedWork, S, "R4_BlockedExecLeavesNoWorkArea", "blocked exec left its work area"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("mutant%d/%s/%s", c.mutant, c.mode, c.scenario), func(t *testing.T) {
			sc, ok := all[c.scenario]
			if !ok {
				t.Fatalf("no scenario %s", c.scenario)
			}
			errs := runScenario(t, c.mode, engineSetup{opts: optcengine.Options{Mutant: c.mutant}, allowLatch: true}, sc)
			if !containsAny(errs, c.want) {
				t.Fatalf("mutant %d: no finding containing %q (findings: %q)", c.mutant, c.want, errs)
			}
		})
	}
}

// ---------------------------------------------------------------- E4

func setFtrace(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return os.WriteFile("/proc/sys/kernel/ftrace_enabled", []byte(v), 0)
}

// TestG003WitnessNoCapacityCliff (S1 review N1): more than 8192 un-reaped
// zombies and io-wq workers (task_alloc runs, sched_process_fork does not)
// leave no latch and no failed mark: marks live in task storage.
func TestG003WitnessNoCapacityCliff(t *testing.T) {
	requireOracle(t)
	// io_uring may be disabled by default (RHEL 9: kernel.io_uring_disabled);
	// enable it for the test, restore it afterwards.
	const knob = "/proc/sys/kernel/io_uring_disabled"
	if v, err := os.ReadFile(knob); err == nil && strings.TrimSpace(string(v)) != "0" {
		t.Logf("kernel.io_uring_disabled=%s: set to 0 for the test", strings.TrimSpace(string(v)))
		if err := os.WriteFile(knob, []byte("0"), 0); err != nil {
			t.Fatalf("enable io_uring: %v", err)
		}
		defer os.WriteFile(knob, v, 0)
	}
	for _, e := range runScenario(t, selfqual.ModeStrict, engineSetup{}, scenario{"cliff", func(o *oracle) {
		obs, err := o.h.Run(selfqual.Where{Mode: o.mode, Adopt: true, Timeout: 120 * time.Second}, "zombies:9000", "iouring:32", "fork+exec:allow", "reapall")
		if err != nil {
			o.fatalf("%v", err)
		}
		for _, tok := range []string{"zombies:9000", "iouring:32", "fork+exec:allow"} {
			if r, _ := o.result(obs, tok); r.Code != 0 {
				o.errorf("%s: code %d", tok, r.Code)
			}
		}
		w, err := o.eng.Witness()
		o.t.Logf("witness after 9000 zombies and 32 io-wq requests: %+v (%v)", w, err)
		if err != nil || !w.Armed || w.Latched || w.MarkFail != 0 {
			o.errorf("witness %+v: want armed, not latched, no failed mark", w)
		}
	}}) {
		t.Error(e)
	}
}

// silencer turns the engine's LSM programs off and on: ftrace (where the
// kernel allows it) or detaching the four LSM links (review E4-2: works on
// every kernel, so the witness and the guard run on 5.15 too).
type silencer struct {
	name    string
	off, on func(*optcengine.Engine) error
}

var silencers = []silencer{
	{"detach", func(e *optcengine.Engine) error { return e.DetachLSM() }, func(e *optcengine.Engine) error { return e.ReattachLSM() }},
	{"ftrace", func(*optcengine.Engine) error { return setFtrace(false) }, func(*optcengine.Engine) error { return setFtrace(true) }},
}

// ftraceRefused: the kernel refuses ftrace off while BPF trampolines are
// attached (EBUSY).
func ftraceRefused(t *testing.T) (refused bool) {
	// Its own subtest: the probe engine (attached, so that 5.15 refuses
	// with EBUSY) is gone before the silencer subtests turn ftrace off.
	// Where ftrace does go off, its witness may latch: on purpose.
	t.Run("ftrace/probe", func(t *testing.T) {
		newOracle(t, selfqual.ModeStrict, engineSetup{allowLatch: true})
		err := setFtrace(false)
		setFtrace(true)
		if err != nil && !errors.Is(err, unix.EBUSY) {
			t.Fatalf("ftrace off: %v", err)
		}
		refused = err != nil
	})
	return refused
}

// silenced runs the E4 sequence on one engine with one silencer.
func silenced(t *testing.T, opts optcengine.Options, sil silencer) []string {
	o := newOracle(t, selfqual.ModeStrict, engineSetup{opts: opts, allowLatch: true})
	if o == nil {
		return nil
	}
	defer sil.on(o.eng)
	func() {
		defer func() {
			if r := recover(); r != nil && r != errFatal {
				panic(r)
			}
		}()
		w0, err := o.eng.Witness()
		if err != nil || !w0.Armed || w0.Latched {
			o.fatalf("witness before: %+v %v", w0, err)
		}
		o.publish(o.allowList(e1Allow()...))
		// (a) A Strict task decided an exec earlier (its receipt existed);
		// the LSM goes silent; its next exec (of the denied file) must not run.
		ready, goFile := o.h.HostPath("ready"), o.h.HostPath("go")
		obs, err := o.h.Run(selfqual.Where{Mode: selfqual.ModeStrict, Adopt: true, During: func() error {
			for i := 0; i < 5000; i++ {
				if _, err := os.Stat(ready); err == nil {
					if err := sil.off(o.eng); err != nil {
						return err
					}
					return os.WriteFile(goFile, nil, 0o644)
				}
				time.Sleep(time.Millisecond)
			}
			return fmt.Errorf("root never got ready")
		}}, "self+rerun:plain,touch:ready,waitfile:go,self+exec:deny")
		if err != nil {
			o.fatalf("%v", err)
		}
		if obs.RootRan {
			o.errorf("strict root exec of deny ran with the LSM silent (stale receipt or no guard)")
		}
		// (b) Still silent: a Strict fork + exec (no record, no mark).
		obs = o.runWhere(selfqual.Where{Mode: selfqual.ModeStrict, Adopt: true}, "fork+exec:allow", "fork+exec:deny")
		for _, r := range obs.Results {
			if r.Code != killed || r.Ran {
				o.errorf("strict exec ran with the LSM silent: %+v, want SIGKILL by the guard", r)
			}
		}
		// (c) Audit is never killed.
		obs = o.runWhere(selfqual.Where{Mode: selfqual.ModeAudit, Adopt: true}, "fork+exec:allow", "fork+exec:deny")
		for _, r := range obs.Results {
			if r.Code != 0 || !r.Ran {
				o.errorf("audit exec killed with the LSM silent: %+v", r)
			}
		}
		w1, _ := o.eng.Witness()
		o.t.Logf("witness with the LSM silent (%s): %+v", sil.name, w1)
		if !w1.Latched || w1.ExecUnmarked == 0 || w1.ForkUnmarked == 0 || w1.GuardKills == 0 || w1.SignalFail != 0 {
			o.errorf("witness did not latch, or the guard did not kill: %+v", w1)
		}
		if ready, _ := o.eng.Ready(); ready {
			o.errorf("engine Ready with a latched witness")
		}
		// (d) The LSM back: enforcement resumes, the latch stays.
		if err := sil.on(o.eng); err != nil {
			o.fatalf("%v", err)
		}
		obs = o.runWhere(selfqual.Where{Mode: selfqual.ModeStrict, Adopt: true}, "fork+exec:allow")
		if len(obs.Results) != 1 || obs.Results[0].Code != 0 {
			o.errorf("strict allow after the LSM came back: %+v", obs.Results)
		}
		w2, _ := o.eng.Witness()
		if !w2.Latched {
			o.errorf("latch cleared after the LSM came back: %+v", w2)
		}
	}()
	return o.errs
}

// TestG004Silenced (E4): with the LSM programs silent the tracepoint witness
// latches (sticky) and the exec-receipt guard kills every Strict exec the
// engine did not decide; Audit is never killed. Silencers: link detach (all
// kernels) and ftrace off (where the kernel allows it). A silencer the
// kernel refuses is reported NOT-RUN, never PASS.
func TestG004Silenced(t *testing.T) {
	requireOracle(t)
	refused := ftraceRefused(t)
	for _, sil := range silencers {
		if sil.name == "ftrace" && refused {
			t.Logf("NOT-RUN: silencer ftrace: kernel.ftrace_enabled=0 is refused (EBUSY) while BPF trampolines are attached; the engine and its 4 mutants are not run with it")
			continue
		}
		sil := sil
		t.Run(sil.name+"/Engine", func(t *testing.T) {
			for _, e := range silenced(t, optcengine.Options{}, sil) {
				t.Error(e)
			}
		})
		for _, c := range []struct {
			m    optcengine.Mutant
			want string
		}{
			{optcengine.MutantWitnessOff, "witness did not latch"},
			{optcengine.MutantGuardOff, "ran with the LSM silent"},
			{optcengine.MutantGuardAuditKills, "audit exec killed"},
			{optcengine.MutantGuardAnyReceipt, "strict root exec of deny ran"},
		} {
			t.Run(fmt.Sprintf("%s/mutant%d", sil.name, c.m), func(t *testing.T) {
				if errs := silenced(t, optcengine.Options{Mutant: c.m}, sil); !containsAny(errs, c.want) {
					t.Fatalf("mutant %d not caught: want %q, findings %q", c.m, c.want, errs)
				}
			})
		}
	}
	if refused {
		t.Run("ftrace/RefusedLeavesEnforcementOn", func(t *testing.T) {
			o := newOracle(t, selfqual.ModeStrict, engineSetup{})
			if err := setFtrace(false); !errors.Is(err, unix.EBUSY) {
				setFtrace(true)
				t.Fatalf("ftrace off: %v, want EBUSY", err)
			}
			on, _ := os.ReadFile("/proc/sys/kernel/ftrace_enabled")
			obs := o.runWhere(selfqual.Where{Mode: selfqual.ModeStrict, Adopt: true}, "fork+exec:deny")
			if strings.TrimSpace(string(on)) != "1" || len(obs.Results) != 1 || obs.Results[0].Code != ePERM {
				t.Errorf("ftrace %q, strict deny %+v", on, obs.Results)
			}
			for _, e := range o.errs {
				t.Error(e)
			}
		})
	}
	// Review E4-1: only the decision hook silent (detached): the exec is
	// committed undecided; no receipt, so the guard kills it, and the
	// commit latches the witness (UNDECIDED).
	t.Run("checkOnly/Engine", func(t *testing.T) {
		for _, e := range checkOnly(t, optcengine.Options{}) {
			t.Error(e)
		}
	})
	t.Run("checkOnly/mutant31", func(t *testing.T) {
		if errs := checkOnly(t, optcengine.Options{Mutant: optcengine.MutantReceiptUndecided}); !containsAny(errs, "undecided strict exec ran") {
			t.Fatalf("mutant 31 not caught: %q", errs)
		}
	})
}

func checkOnly(t *testing.T, opts optcengine.Options) []string {
	o := newOracle(t, selfqual.ModeStrict, engineSetup{opts: opts, allowLatch: true})
	if o == nil {
		return nil
	}
	func() {
		defer func() {
			if r := recover(); r != nil && r != errFatal {
				panic(r)
			}
		}()
		o.publish(o.allowList(e1Allow()...))
		if err := o.eng.DetachProgram("oc_bprm_check"); err != nil {
			o.fatalf("%v", err)
		}
		defer o.eng.ReattachLSM()
		obs := o.runWhere(selfqual.Where{Mode: selfqual.ModeStrict, Adopt: true}, "fork+exec:deny")
		if len(obs.Results) != 1 || obs.Results[0].Code != killed || obs.Results[0].Ran {
			o.errorf("undecided strict exec ran (or was not killed): %+v", obs.Results)
		}
		if w, _ := o.eng.Witness(); !w.Latched || w.Undecided == 0 {
			o.errorf("witness after an undecided commit: %+v, want latched (undecided)", w)
		}
	}()
	return o.errs
}
