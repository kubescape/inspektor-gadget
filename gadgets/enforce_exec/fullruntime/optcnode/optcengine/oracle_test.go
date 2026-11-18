// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package optcengine_test

// E1 oracle: the D4 oracle's 17 scenarios with the option C expectations of
// design 005 §9.3 (no failure outcome; commit at bprm_committed_creds; R11
// Strict denies and Audit allows; R6 b/c), plus the role, anchoring and
// generation scenarios of §9.2 and the two colleague-proposal checks. Every
// expectation is hand-written; nothing skips once EE_OPTC_ORACLE=1 is set.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/optcengine"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/selfqual"
)

const (
	ePERM   = int(unix.EPERM)
	eNOENT  = int(unix.ENOENT)
	eNOEXEC = int(unix.ENOEXEC)
	eACCES  = int(unix.EACCES)
	eLOOP   = int(unix.ELOOP)
	killed  = 1000 + int(unix.SIGKILL)
)

func requireOracle(t *testing.T) {
	t.Helper()
	if os.Getenv("EE_OPTC_ORACLE") != "1" {
		t.Skip("set EE_OPTC_ORACLE=1 (root, bpf LSM, cgroup v2, binfmt_misc) to run the option C oracle")
	}
}

var errFatal = errors.New("scenario aborted")

// oracle drives one scenario in one mode. Errors are recorded, so a scenario
// can also be run against a mutant engine and required to fail.
type oracle struct {
	t    *testing.T
	eng  *optcengine.Engine
	h    *selfqual.Harness
	mode selfqual.Mode
	errs []string
}

type engineSetup struct {
	opts       optcengine.Options
	noInit     bool // no seeded-init exec at bind (anchor capture scenario)
	allowLatch bool // the scenario latches the witness on purpose (E4)
}

// productRun (review C3): EE_OPTC_PRODUCT=1 runs the oracle on the product
// object (the pinned one). A scenario that needs a test-only option or knob
// is NOT-RUN there (logged), never passed.
func productRun() bool { return os.Getenv("EE_OPTC_PRODUCT") != "" }

func testOnlyOptions(o optcengine.Options) bool {
	return o.Mutant != optcengine.MutantNone || o.StageCap != 0 || o.UnsafeNoPublishLimit || o.StaleInitAdopt ||
		o.WrongInitStart || o.NoReevaluate
}

// newOracle returns nil (and logs NOT-RUN) for a test-only setup in a
// product run.
func newOracle(t *testing.T, mode selfqual.Mode, setup engineSetup) *oracle {
	t.Helper()
	if productRun() {
		if testOnlyOptions(setup.opts) {
			t.Logf("NOT-RUN: product object: %s needs test-only options %+v", t.Name(), setup.opts)
			return nil
		}
		setup.opts.Product = true
	}
	eng, err := optcengine.Load(setup.opts)
	if err != nil {
		t.Fatalf("load engine: %v", err)
	}
	t.Logf("engine %s", eng.Name())
	t.Cleanup(func() { eng.Close() })
	h, err := selfqual.NewHarness(eng, selfqual.Options{InitExec: !setup.noInit, NoPendingGauge: true})
	if err != nil {
		t.Fatalf("harness: %v", err)
	}
	o := &oracle{t: t, eng: eng, h: h, mode: mode}
	t.Cleanup(func() {
		// G003 E4: no scenario may latch the witness by accident.
		if w, err := eng.Witness(); !setup.allowLatch && (err != nil || !w.Armed || w.Latched) {
			t.Errorf("witness after the scenario: %+v (%v), want armed and not latched", w, err)
		}
		c, cErr := h.Counters()
		if err := h.Close(); err != nil {
			t.Errorf("teardown: %v", err)
		}
		if cErr != nil || c.Pending != 0 || c.Live != 0 || c.StalePending != 0 || c.EventLost != 0 || c.StorageFail != 0 {
			t.Errorf("engine not clean at the end: %+v (%v)", c, cErr)
		}
	})
	return o
}

// testKnob reports whether a test-object knob (fault injection, test flags,
// owner-stamp clobber) is available; in a product run it logs NOT-RUN.
func (o *oracle) testKnob(what string) bool {
	if productRun() {
		o.t.Logf("NOT-RUN: product object: %s needs the test knob %s", o.t.Name(), what)
		return false
	}
	return true
}

func (o *oracle) errorf(format string, a ...any) {
	o.errs = append(o.errs, fmt.Sprintf(format, a...))
}

func (o *oracle) fatalf(format string, a ...any) {
	o.errorf(format, a...)
	panic(errFatal)
}

func (o *oracle) strict() bool { return o.mode == selfqual.ModeStrict }

func (o *oracle) cg() uint64 { return o.h.CgroupID(o.mode) }

func (o *oracle) run(tokens ...string) selfqual.Observation {
	return o.runWhere(selfqual.Where{Mode: o.mode, Adopt: true}, tokens...)
}

func (o *oracle) runWhere(w selfqual.Where, tokens ...string) selfqual.Observation {
	obs, err := o.h.Run(w, tokens...)
	if err != nil {
		o.fatalf("run %v: %v", tokens, err)
	}
	o.quiet(obs)
	return obs
}

func (o *oracle) quiet(obs selfqual.Observation) {
	d := obs.Delta
	if !obs.Quiesced || d.Pending != 0 || d.Live != 0 {
		o.errorf("engine not quiet: quiesced=%v pending=%d live=%d", obs.Quiesced, d.Pending, d.Live)
	}
	if d.StalePending != 0 || d.EventLost != 0 || d.StorageFail != 0 {
		o.errorf("engine faults: %+v", d)
	}
}

type decided struct {
	file string
	deny bool
}

func (o *oracle) result(obs selfqual.Observation, token string) (selfqual.TokenResult, bool) {
	for _, r := range obs.Results {
		if r.Token == token {
			return r, true
		}
	}
	o.errorf("no result for %s in %+v", token, obs.Results)
	return selfqual.TokenResult{}, false
}

func (o *oracle) events(obs selfqual.Observation, pid uint32, kind uint32) []selfqual.Event {
	var out []selfqual.Event
	for _, ev := range obs.Events {
		if ev.PID == pid && ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

func (o *oracle) details(pid uint32, kind uint32) []optcengine.Detail {
	var out []optcengine.Detail
	for _, d := range o.eng.Details(pid) {
		if d.Kind == kind {
			out = append(out, d)
		}
	}
	return out
}

// wantExec checks result i: code, image ran, the per-pass decisions, and
// whether the exec committed (option C: a commit event, never a failure
// outcome).
func (o *oracle) wantExec(obs selfqual.Observation, i, code int, ran, committed bool, passes ...decided) {
	if i >= len(obs.Results) {
		o.errorf("no result %d (have %d)", i, len(obs.Results))
		return
	}
	res := obs.Results[i]
	if res.Code != code || res.Ran != ran {
		o.errorf("%s: code %d ran=%v, want code %d ran=%v", res.Token, res.Code, res.Ran, code, ran)
	}
	ds := o.events(obs, res.PID, selfqual.EventDecision)
	if len(ds) != len(passes) {
		o.errorf("%s: %d decisions, want %d: %+v", res.Token, len(ds), len(passes), ds)
	} else {
		for j, p := range passes {
			d := ds[j]
			wantBlocked := p.deny && o.strict()
			if d.File != o.h.File(p.file) || d.Deny != p.deny || d.Blocked != wantBlocked || int(d.Pass) != j || d.Mode != o.mode || d.Cgroup != o.cg() || d.Gen != ds[0].Gen {
				o.errorf("%s pass %d: %+v, want file %s deny=%v blocked=%v", res.Token, j, d, p.file, p.deny, wantBlocked)
			}
		}
	}
	cs := o.events(obs, res.PID, optcengine.EventCommit)
	if committed && len(cs) != 1 || !committed && len(cs) != 0 {
		o.errorf("%s: %d commits, want committed=%v", res.Token, len(cs), committed)
	}
	if len(o.events(obs, res.PID, selfqual.EventFault)) != 0 {
		o.errorf("%s: unexpected fault events", res.Token)
	}
}

func (o *oracle) wantCounters(obs selfqual.Observation, want selfqual.Counters) {
	got := obs.Delta
	got.Births, got.Exits, got.Adopted = 0, 0, 0
	if got != want {
		o.errorf("counters\n got  %+v\n want %+v", got, want)
	}
}

// ------------------------------------------------------------ policies

func (o *oracle) fpMode() fullpolicy.Mode {
	if o.strict() {
		return fullpolicy.Enforce
	}
	return fullpolicy.Audit
}

func (o *oracle) paths(names ...string) []string {
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, "/") {
			out = append(out, n)
		} else {
			out = append(out, o.h.Path(n))
		}
	}
	return out
}

// e1Allow is the base allow-list plus the E1 fixtures.
func e1Allow(extra ...string) []string {
	return append(append(selfqual.BaseAllow(), "setter", "plain", "curl", "dyn"), extra...)
}

func (o *oracle) allowList(names ...string) fullpolicy.Policy {
	return optcengine.AllowList(o.mode, o.paths(names...))[0]
}

func (o *oracle) publish(ps ...fullpolicy.Policy) uint64 {
	gen, err := o.eng.PublishPolicies(o.cg(), ps)
	if err != nil {
		o.fatalf("publish: %v", err)
	}
	o.h.SetGeneration(o.mode, gen)
	return gen
}

// rolePolicy: root role "clean"; rules as given; default allow (it never
// decides on its own when no rule matches).
func rolePolicy(mode fullpolicy.Mode, rules ...fullpolicy.Rule) fullpolicy.Policy {
	return fullpolicy.Policy{ID: "e1-roles", Revision: "1", Mode: mode, RootRole: "clean", Default: fullpolicy.Allow, Rules: rules}
}

func (o *oracle) setRule(role string, targets ...string) fullpolicy.Rule {
	return fullpolicy.Rule{Name: "set-" + role, Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: o.paths(targets...), SetRole: role}}
}

func (o *oracle) denyIfRole(role string, targets ...string) fullpolicy.Rule {
	return fullpolicy.Rule{Name: "deny-" + role, Action: fullpolicy.Deny, Actor: fullpolicy.Actor{Role: []string{role}}, Target: fullpolicy.Target{Path: o.paths(targets...)}}
}

// commit returns the first commit detail of pid (its token's exec; under
// Audit the image may exec again from the same pid).
func (o *oracle) commit(pid uint32) (optcengine.Detail, bool) {
	cs := o.details(pid, optcengine.EventCommit)
	if len(cs) == 0 {
		o.errorf("pid %d: no commit", pid)
		return optcengine.Detail{}, false
	}
	return cs[0], true
}

// wantCurl checks a nested "...+exec:curl" token: denied by a known role
// (error 0) or allowed.
func (o *oracle) wantCurl(obs selfqual.Observation, token string, denied bool) {
	for _, r := range obs.Results {
		if r.Token != token {
			continue
		}
		if r.PID == 0 {
			// posix_spawn reports a failed exec without the child's pid:
			// find the one curl decision of a pid no result names.
			o.wantOrphanCurl(obs, token, r, denied)
			continue
		}
		ds := o.details(r.PID, selfqual.EventDecision)
		if len(ds) == 0 {
			o.errorf("%s (pid %d): no decision", token, r.PID)
			continue
		}
		d := ds[len(ds)-1]
		if d.Path != o.h.Path("curl") {
			o.errorf("%s: last decision is for %q", token, d.Path)
			continue
		}
		wantCode := 0
		if denied && o.strict() {
			wantCode = ePERM
		}
		if d.Deny != denied || d.Error != 0 || r.Code != wantCode {
			o.errorf("%s: code %d deny=%v error=%d, want code %d deny=%v error 0", token, r.Code, d.Deny, d.Error, wantCode, denied)
		}
	}
}

func (o *oracle) wantOrphanCurl(obs selfqual.Observation, token string, r selfqual.TokenResult, denied bool) {
	named := map[uint32]bool{obs.Root: true}
	for _, x := range obs.Results {
		named[x.PID] = true
	}
	var found []optcengine.Detail
	for _, ev := range obs.Events {
		if ev.Kind != selfqual.EventDecision || named[ev.PID] {
			continue
		}
		for _, d := range o.details(ev.PID, selfqual.EventDecision) {
			if d.Path == o.h.Path("curl") && d.ExecID == ev.ExecID && d.Pass == ev.Pass {
				found = append(found, d)
			}
		}
	}
	wantCode := 0
	if denied && o.strict() {
		wantCode = ePERM
	}
	if len(found) != 1 || found[0].Deny != denied || found[0].Error != 0 || r.Code != wantCode {
		o.errorf("%s: code %d, curl decisions of unnamed pids %+v, want code %d and one deny=%v by a known role", token, r.Code, found, wantCode, denied)
	}
}

// ------------------------------------------------------------ scenarios

type scenario struct {
	name string
	run  func(o *oracle)
}

// d4Scenarios: the 17 scenarios of the D4 oracle, option C expectations.
var d4Scenarios = []scenario{
	{"Allow", func(o *oracle) {
		obs := o.run("fork+exec:allow")
		o.wantExec(obs, 0, 0, true, true, decided{"allow", false})
		o.wantCounters(obs, selfqual.Counters{Execs: 1, Decisions: 1, Allow: 1, ExecOK: 1})
	}},
	{"DenyStrictEPERM_AuditWouldDenyDoesNotBlock", func(o *oracle) {
		obs := o.run("fork+exec:deny")
		if o.strict() {
			o.wantExec(obs, 0, ePERM, false, false, decided{"deny", true})
			o.wantCounters(obs, selfqual.Counters{Execs: 1, Decisions: 1, Deny: 1})
		} else {
			o.wantExec(obs, 0, 0, true, true, decided{"deny", true})
			o.wantCounters(obs, selfqual.Counters{Execs: 1, Decisions: 1, WouldDeny: 1, ExecOK: 1})
		}
	}},
	{"FaultBeforeClassificationDeniesInEveryMode", func(o *oracle) {
		if !o.testKnob("fault injection") {
			return
		}
		if err := o.h.InjectFault(o.mode, true); err != nil {
			o.fatalf("%v", err)
		}
		obs, err := o.h.Run(selfqual.Where{Mode: o.mode, Adopt: true}, "fork+exec:allow")
		if offErr := o.h.InjectFault(o.mode, false); offErr != nil {
			o.fatalf("%v", offErr)
		}
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		if len(obs.Results) != 1 || obs.Results[0].Code != ePERM || obs.Results[0].Ran {
			o.errorf("injected fault: %+v, want EPERM in %s", obs.Results, o.mode)
			return
		}
		o.wantCounters(obs, selfqual.Counters{Execs: 1, FaultDeny: 1})
		faults := 0
		for _, ev := range obs.Events {
			if ev.Kind == selfqual.EventFault && ev.Fault == selfqual.FaultInjected && ev.Blocked {
				faults++
			}
		}
		if faults != 1 {
			o.errorf("%d injected-fault events, want 1", faults)
		}
		obs = o.run("fork+exec:allow")
		o.wantExec(obs, 0, 0, true, true, decided{"allow", false})
	}},
	{"RetiredGenerationMidExec_StrictDeniesAuditAllows", func(o *oracle) {
		// R6 b: a fault after classification follows the frozen class.
		old := o.h.Generation(o.mode)
		obs, err := o.h.RunHeld(o.mode, false, func(uint32) error {
			if _, err := o.h.Publish(o.mode, selfqual.BaseAllow()...); err != nil {
				return err
			}
			return o.h.Retire(o.mode, old)
		}, "fork+exec:sh_hold")
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		if len(obs.Results) != 1 {
			o.fatalf("results %+v", obs.Results)
		}
		res := obs.Results[0]
		faults := o.events(obs, res.PID, selfqual.EventFault)
		if len(faults) != 1 || faults[0].Fault != selfqual.FaultNoGeneration || faults[0].Blocked != o.strict() {
			o.errorf("faults %+v, want one no-generation fault, blocked=%v", faults, o.strict())
		}
		if o.strict() {
			if res.Code != ePERM || res.Ran || len(o.events(obs, res.PID, optcengine.EventCommit)) != 0 {
				o.errorf("strict: %+v, want EPERM and no commit", res)
			}
			o.wantCounters(obs, selfqual.Counters{Execs: 1, Decisions: 1, Allow: 1, FaultDeny: 1})
		} else {
			c, ok := o.commit(res.PID)
			if res.Code != 0 || !res.Ran || !ok || c.Flags&optcengine.CommitGenMismatch == 0 || c.KnownMask != 0 {
				o.errorf("audit: %+v commit %+v, want run, generation mismatch, every role UNKNOWN", res, c)
			}
			o.wantCounters(obs, selfqual.Counters{Execs: 1, Decisions: 1, Allow: 1, ExecOK: 1})
		}
	}},
	{"ExecFailsAfterAllow_ENOENT_ENOEXEC_BadInterpreter_ELOOP", func(o *oracle) {
		obs := o.run("fork+exec:sh_nointerp", "fork+exec:garbage", "fork+exec:sh_dirinterp", "fork+exec:l1", "fork+exec:allow")
		o.wantExec(obs, 0, eNOENT, false, false, decided{"sh_nointerp", false})
		o.wantExec(obs, 1, eNOEXEC, false, false, decided{"garbage", false})
		o.wantExec(obs, 2, eACCES, false, false, decided{"sh_dirinterp", false})
		o.wantExec(obs, 3, eLOOP, false, false,
			decided{"l1", false}, decided{"l2", false}, decided{"l3", false}, decided{"l4", false}, decided{"l5", false}, decided{"l6", false})
		o.wantExec(obs, 4, 0, true, true, decided{"allow", false})
		o.wantCounters(obs, selfqual.Counters{Execs: 5, Decisions: 10, Allow: 10, ExecOK: 1})
	}},
	{"ExecFailsBeforeDecisionLeavesNoRecord", func(o *oracle) {
		obs := o.run("fork+exec:missing", "fork+exec:noperm")
		o.wantExec(obs, 0, eNOENT, false, false)
		o.wantExec(obs, 1, eACCES, false, false)
		o.wantCounters(obs, selfqual.Counters{})
	}},
	{"ExecFailsAfterDeny", func(o *oracle) {
		obs := o.run("fork+exec:garbage_denied", "fork+exec:sh_deny_interp", "fork+exec:sh_denied")
		if o.strict() {
			o.wantExec(obs, 0, ePERM, false, false, decided{"garbage_denied", true})
			o.wantExec(obs, 1, ePERM, false, false, decided{"sh_deny_interp", false}, decided{"deny", true})
			o.wantExec(obs, 2, ePERM, false, false, decided{"sh_denied", true})
			o.wantCounters(obs, selfqual.Counters{Execs: 3, Decisions: 4, Allow: 1, Deny: 3})
		} else {
			o.wantExec(obs, 0, eNOEXEC, false, false, decided{"garbage_denied", true})
			o.wantExec(obs, 1, 0, true, true, decided{"sh_deny_interp", false}, decided{"deny", true})
			o.wantExec(obs, 2, 0, true, true, decided{"sh_denied", true}, decided{"allow", false})
			o.wantCounters(obs, selfqual.Counters{Execs: 3, Decisions: 5, Allow: 2, WouldDeny: 3, ExecOK: 2})
		}
	}},
	{"InterpreterChainAndBinfmtMisc", func(o *oracle) {
		if !o.h.HasBinfmtMisc() {
			o.fatalf("binfmt_misc is not available: the oracle does not skip")
		}
		obs := o.run("fork+exec:sh_ok", "fork+exec:c1", "fork+exec:bm_file")
		o.wantExec(obs, 0, 0, true, true, decided{"sh_ok", false}, decided{"allow", false})
		o.wantExec(obs, 1, 0, true, true,
			decided{"c1", false}, decided{"c2", false}, decided{"c3", false}, decided{"c4", false}, decided{"c5", false}, decided{"allow", false})
		o.wantExec(obs, 2, 0, true, true, decided{"bm_file", false}, decided{"allow", false})
		o.wantCounters(obs, selfqual.Counters{Execs: 3, Decisions: 10, Allow: 10, ExecOK: 3})
	}},
	{"FdBasedExec_AtEmptyPath_Fexecve_Memfd", func(o *oracle) {
		obs := o.run("fork+at_empty:deny", "fork+fexecve:deny", "fork+fdpath:deny", "fork+dirfd:deny", "fork+at_empty:allow", "fork+memfd:allow")
		code, ran := 0, true
		if o.strict() {
			code, ran = ePERM, false
		}
		for i := 0; i < 4; i++ {
			o.wantExec(obs, i, code, ran, !o.strict(), decided{"deny", true})
		}
		o.wantExec(obs, 4, 0, true, true, decided{"allow", false})
		if len(obs.Results) == 6 {
			res := obs.Results[5]
			if res.Code != code || res.Ran != ran {
				o.errorf("memfd exec: code %d ran=%v, want %d %v", res.Code, res.Ran, code, ran)
			}
			for _, d := range o.details(res.PID, selfqual.EventDecision) {
				// A memfd lives on a kernel-internal mount: UNKNOWN as
				// internal, or as unreachable on kernels whose internal
				// mounts carry no MNT_NS_INTERNAL marker.
				if !d.Deny || d.File == o.h.File("allow") || d.Path != "" ||
					d.PathReason != optcengine.PathInternal && d.PathReason != optcengine.PathUnreachable {
					o.errorf("memfd exec decided as the allowed file, or with a known path: %+v", d)
				}
			}
		} else {
			o.errorf("%d results, want 6", len(obs.Results))
		}
		if o.strict() {
			o.wantCounters(obs, selfqual.Counters{Execs: 6, Decisions: 6, Allow: 1, Deny: 5, ExecOK: 1})
		} else {
			o.wantCounters(obs, selfqual.Counters{Execs: 6, Decisions: 6, Allow: 1, WouldDeny: 5, ExecOK: 6})
		}
	}},
	{"ForkCloneInheritance", func(o *oracle) {
		same, alt := "into@"+o.h.CgroupPath(o.mode), "into@"+o.h.AltPath()
		creators := []string{"fork", "vfork", "clonevm", same, alt}
		var tokens []string
		for _, c := range creators {
			tokens = append(tokens, c+"+exec:allow", c+"+exec:deny")
		}
		obs := o.run(tokens...)
		for i := range creators {
			o.wantExec(obs, 2*i, 0, true, true, decided{"allow", false})
			if o.strict() {
				o.wantExec(obs, 2*i+1, ePERM, false, false, decided{"deny", true})
			} else {
				o.wantExec(obs, 2*i+1, 0, true, true, decided{"deny", true})
			}
		}
		if obs.Delta.Births != 10 || obs.Delta.Adopted != 1 || obs.Delta.Exits != 11 {
			o.errorf("births %d adopted %d exits %d, want 10, 1, 11", obs.Delta.Births, obs.Delta.Adopted, obs.Delta.Exits)
		}
	}},
	{"UnknownTaskInBoundCgroup_StrictDeniesAuditAllows", func(o *oracle) {
		// R11, aligned: the D4 reference engine denied in both modes.
		obs, err := o.h.Run(selfqual.Where{Mode: o.mode}, "fork+exec:allow", "self+exec:allow")
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		if o.strict() {
			if len(obs.Results) != 2 || obs.Results[0].Code != 300+ePERM || obs.Results[1].Code != ePERM || obs.Results[0].Ran || obs.Results[1].Ran {
				o.errorf("unknown task: %+v, want fork EPERM and exec EPERM", obs.Results)
			}
			o.wantCounters(obs, selfqual.Counters{UnknownFork: 1, UnknownExec: 1})
		} else {
			// The root's own exec succeeds and replaces it: no result line.
			if len(obs.Results) != 1 || obs.Results[0].Code != 0 || !obs.Results[0].Ran {
				o.errorf("unknown task: %+v, want the child to run (Audit allows and reports)", obs.Results)
			}
			o.wantCounters(obs, selfqual.Counters{UnknownFork: 1, UnknownExec: 2})
		}
		for _, ev := range obs.Events {
			if ev.Kind != selfqual.EventFault || ev.Fault != selfqual.FaultUnknownTask || ev.Blocked != o.strict() {
				o.errorf("unknown-task event %+v, want a report blocked=%v", ev, o.strict())
			}
		}
		if obs.Delta.Births != 0 || obs.Delta.Adopted != 0 {
			o.errorf("unknown task was tracked: %+v", obs.Delta)
		}
		obs, err = o.h.Run(selfqual.Where{Outside: true}, "into@"+o.h.CgroupPath(o.mode)+"+exec:allow")
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		wantCode := 0
		if o.strict() {
			wantCode = ePERM
		}
		if len(obs.Results) != 1 || obs.Results[0].Code != wantCode || obs.Results[0].Ran == o.strict() {
			o.errorf("cloned-in unknown child: %+v, want code %d", obs.Results, wantCode)
		}
		o.wantCounters(obs, selfqual.Counters{UnknownExec: 1})
	}},
	{"TaskOutsideEveryBindingIsUntouched", func(o *oracle) {
		obs, err := o.h.Run(selfqual.Where{Outside: true}, "fork+exec:deny", "fork+exec:allow")
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		if len(obs.Results) != 2 || obs.Results[0].Code != 0 || !obs.Results[0].Ran || obs.Results[1].Code != 0 || !obs.Results[1].Ran {
			o.errorf("outside task: %+v, want both to run", obs.Results)
		}
		if len(obs.Events) != 0 || obs.Delta != (selfqual.Counters{}) {
			o.errorf("outside task was observed: %d events, %+v", len(obs.Events), obs.Delta)
		}
	}},
	{"MultiThreadedExecDeThread", func(o *oracle) {
		obs := o.run("thread+exec:allow", "thread+exec:deny", "thread+exec:sh_ok")
		o.wantExec(obs, 0, 0, true, true, decided{"allow", false})
		if o.strict() {
			o.wantExec(obs, 1, ePERM, false, false, decided{"deny", true})
		} else {
			o.wantExec(obs, 1, 0, true, true, decided{"deny", true})
		}
		o.wantExec(obs, 2, 0, true, true, decided{"sh_ok", false}, decided{"allow", false})
		if obs.Delta.Births != 15 || obs.Delta.Exits != 16 {
			o.errorf("births %d exits %d, want 15 and 16", obs.Delta.Births, obs.Delta.Exits)
		}
	}},
	{"ExecRacingThreadGroupExitAndKill", func(o *oracle) {
		var tokens []string
		for i := 0; i < 25; i++ {
			tokens = append(tokens, "exitrace+exec:allow", "exitrace+exec:deny", "threadrace+exec:allow", "killrace+exec:sh_ok")
		}
		obs := o.run(tokens...)
		d := obs.Delta
		if len(obs.Results) != len(tokens) {
			o.fatalf("%d results for %d tokens", len(obs.Results), len(tokens))
		}
		if d.ExecOK > d.Execs {
			o.errorf("%d commits for %d execs", d.ExecOK, d.Execs)
		}
		if d.Exits != d.Births+d.Adopted {
			o.errorf("%d exits, %d births + %d adopted", d.Exits, d.Births, d.Adopted)
		}
		committed := map[uint32]bool{}
		blocked := map[uint32]bool{}
		for _, ev := range obs.Events {
			if ev.Kind == optcengine.EventCommit {
				committed[ev.PID] = true
			}
			if ev.Kind == selfqual.EventDecision && ev.Blocked {
				blocked[ev.PID] = true
			}
		}
		for i, res := range obs.Results {
			if res.Ran && !committed[res.PID] {
				o.errorf("%s: image ran, no commit recorded", res.Token)
			}
			if o.strict() && tokens[i] == "exitrace+exec:deny" && (res.Ran || committed[res.PID]) {
				o.errorf("%s: a denied image ran under Strict", res.Token)
			}
			if blocked[res.PID] && committed[res.PID] {
				o.errorf("%s: blocked and committed", res.Token)
			}
		}
	}},
	{"TaskKilledMidExecLeavesNoResidue", func(o *oracle) {
		obs, err := o.h.RunHeld(o.mode, true, nil, "fork+exec:sh_hold", "fork+exec:allow")
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		if len(obs.Results) != 2 || obs.Results[0].Code != killed || obs.Results[0].Ran || obs.Results[1].Code != 0 || !obs.Results[1].Ran {
			o.errorf("results %+v, want SIGKILL then a normal exec", obs.Results)
		}
		d := obs.Delta
		if d.Execs != 2 || d.ExecOK != 1 || d.Decisions != 2 {
			o.errorf("counters %+v, want 2 execs, 1 commit, 2 decisions", d)
		}
	}},
	{"ExecParkedAcrossGenerationSwitch_Compromise8Alternative", func(o *oracle) {
		// One generation per exec: both passes under the old one. At commit
		// the generation changed: roles UNKNOWN, and the final pass
		// (hold_interp) is re-evaluated under the new generation, which
		// denies it: Strict kills (SIGKILL, past the point of no return),
		// Audit reports. The next exec meets the new generation.
		old := o.h.Generation(o.mode)
		var next uint64
		var without []string
		for _, name := range selfqual.BaseAllow() {
			if name != "hold_interp" {
				without = append(without, name)
			}
		}
		obs, err := o.h.RunHeld(o.mode, false, func(uint32) error {
			var err error
			next, err = o.h.Publish(o.mode, without...)
			return err
		}, "fork+exec:sh_hold", "fork+exec:sh_hold")
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		if len(obs.Results) != 2 {
			o.fatalf("results %+v", obs.Results)
		}
		first := obs.Results[0]
		c, _ := o.commit(first.PID)
		if c.Flags&optcengine.CommitGenMismatch == 0 || c.Flags&optcengine.CommitReevalDeny == 0 || c.KnownMask != 0 {
			o.errorf("parked exec commit %+v: want generation mismatch, re-evaluation deny, roles UNKNOWN", c)
		}
		if o.strict() {
			if first.Code != killed || first.Ran || c.Flags&optcengine.CommitKilled == 0 {
				o.errorf("strict parked exec: %+v flags %#x, want SIGKILL before its image ran", first, c.Flags)
			}
			o.wantExec(obs, 1, ePERM, false, false, decided{"sh_hold", false}, decided{"hold_interp", true})
		} else {
			if first.Code != 0 || !first.Ran || c.Flags&optcengine.CommitKilled != 0 {
				o.errorf("audit parked exec: %+v flags %#x, want it to run, reported", first, c.Flags)
			}
			o.wantExec(obs, 1, 0, true, true, decided{"sh_hold", false}, decided{"hold_interp", true})
		}
		for _, ev := range obs.Events {
			if ev.Kind != selfqual.EventDecision {
				continue
			}
			if ev.PID == first.PID && ev.Gen != old {
				o.errorf("parked exec decided under generation %d, want %d", ev.Gen, old)
			}
			if ev.PID == obs.Results[1].PID && ev.Gen != next {
				o.errorf("next exec decided under generation %d, want %d", ev.Gen, next)
			}
		}
	}},
	{"AtomicGenerationSwitchDuringConcurrentExecs_Storm", func(o *oracle) {
		const workers, iters, switches = 8, 150, 5
		total := uint64(workers * iters * 2)
		allowed := map[uint64]string{}
		gen, err := o.h.Publish(o.mode, "allow")
		if err != nil {
			o.fatalf("%v", err)
		}
		allowed[gen] = "allow"
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
					if c.Execs-base.Execs >= total*uint64(k)/(switches+1) {
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("storm stalled at %d of %d execs", c.Execs-base.Execs, total)
					}
				}
				name := []string{"allow", "deny"}[k%2]
				t0 := time.Now()
				gen, err := o.h.Publish(o.mode, name)
				if dt := time.Since(t0); dt > maxPublish {
					maxPublish = dt
				}
				if err != nil {
					return err
				}
				allowed[gen] = name
			}
			return nil
		}}, fmt.Sprintf("storm:%d:%d:allow:deny", workers, iters))
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		o.t.Logf("storm: max publish latency %v", maxPublish)
		if maxPublish > time.Second {
			o.errorf("a publication took %v during the storm: publication must not wait for execs", maxPublish)
		}
		decisions := map[uint32][]selfqual.Event{}
		seen := map[uint64]int{}
		for _, ev := range obs.Events {
			if ev.Kind == selfqual.EventDecision {
				decisions[ev.PID] = append(decisions[ev.PID], ev)
				seen[ev.Gen]++
			}
		}
		if uint64(len(obs.Storm)) != total || obs.Delta.Execs != total || obs.Delta.Decisions != total {
			o.fatalf("%d attempts, %d execs, %d decisions, want %d each", len(obs.Storm), obs.Delta.Execs, obs.Delta.Decisions, total)
		}
		last := map[int]uint64{}
		bad, straddled := 0, 0
		for _, a := range obs.Storm {
			ds := decisions[a.PID]
			if len(ds) != 1 {
				bad++
				continue
			}
			d := ds[0]
			name, known := allowed[d.Gen]
			wantDeny := name != a.File
			wantCode := 0
			if wantDeny && o.strict() {
				wantCode = ePERM
			}
			// Compromise-8 alternative: an exec allowed under N whose
			// commit came after N+1 (which denies it) is killed under
			// Strict, past the point of no return.
			if !wantDeny && o.strict() && a.Code == killed {
				cs := o.details(a.PID, optcengine.EventCommit)
				if len(cs) == 1 && cs[0].Flags&optcengine.CommitKilled != 0 && cs[0].Flags&optcengine.CommitGenMismatch != 0 {
					straddled++
					wantCode = killed
				}
			}
			if !known || d.Deny != wantDeny || d.File != o.h.File(a.File) || a.Code != wantCode || d.Gen < last[a.Worker] {
				bad++
				if bad <= 5 {
					o.errorf("attempt %+v decided %+v: generation allows %q, worker last saw %d", a, d, name, last[a.Worker])
				}
			}
			last[a.Worker] = d.Gen
		}
		o.t.Logf("storm: %d execs straddled a switch and were killed at commit (compromise-8 alternative)", straddled)
		if bad != 0 {
			o.errorf("%d of %d attempts violate the generation they were decided under", bad, total)
		}
		if len(seen) != switches+1 {
			o.errorf("execs were decided under %d generations, want %d", len(seen), switches+1)
		}
	}},
}

// e1Scenarios: §9.2 / §9.3 role, anchoring and generation scenarios.
var e1Scenarios = []scenario{
	{"RoleVisibleToNextExecAndToChildrenOfEveryCreator", func(o *oracle) {
		o.publish(o.allowList(e1Allow()...), rolePolicy(o.fpMode(), o.setRule("marked", "setter"), o.denyIfRole("marked", "curl")))
		same, alt := "into@"+o.h.CgroupPath(o.mode), "into@"+o.h.AltPath()
		nested := []string{"fork+exec:curl", "vfork+exec:curl", "clonevm+exec:curl", "spawn+exec:curl", same + "+exec:curl", alt + "+exec:curl", "self+exec:curl"}
		obs := o.run("fork+fexecve:curl", "fork+rerun:setter,"+strings.Join(nested, ","))
		// Before the role: allowed.
		r0, _ := o.result(obs, "fork+fexecve:curl")
		if ds := o.details(r0.PID, selfqual.EventDecision); r0.Code != 0 || len(ds) != 1 || ds[0].Deny {
			o.errorf("curl before the role: %+v %+v, want allowed", r0, ds)
		}
		setter, _ := o.result(obs, "fork+rerun:setter,"+strings.Join(nested, ","))
		c, ok := o.commit(setter.PID)
		role := c.Roles[1]
		if !ok || c.KnownMask&2 == 0 || o.eng.RoleName(role) != "marked" {
			o.errorf("setter commit %+v (row 1 role %q), want the role marked, known", c, o.eng.RoleName(role))
		}
		for _, tok := range nested {
			o.wantCurl(obs, tok, true)
		}
	}},
	{"RoleNotCommittedByAnyFailedExec_NorByTheNextExecOfAnotherFile", func(o *oracle) {
		setters := []string{"sh_nointerp", "garbage", "sh_dirinterp", "l1", "setter", "sh_mark_deny"}
		o.publish(o.allowList(e1Allow("sh_mark_deny")...), rolePolicy(o.fpMode(), o.setRule("marked", setters...), o.denyIfRole("marked", "curl")))
		tokens := []string{
			"self+exec:sh_nointerp", "fork+exec:curl", // ENOENT (missing interpreter) after allow
			"self+exec:garbage", "fork+exec:curl", // ENOEXEC
			"self+exec:sh_dirinterp", "fork+exec:curl", // EACCES (bad interpreter)
			"self+exec:l1", "fork+exec:curl", // ELOOP after 6 passes
		}
		if o.strict() {
			tokens = append(tokens, "self+exec:sh_mark_deny", "fork+exec:curl") // denied interpreter pass
		}
		// The following successful exec of a different file (plain, no role
		// write) must not commit the failed execs' proposal.
		tokens = append(tokens, "self+rerun:plain,fork+exec:curl")
		obs := o.run(tokens...)
		for _, r := range obs.Results {
			if r.Token == "fork+exec:curl" {
				o.wantCurl(obs, r.Token, false)
			}
		}
		want := map[string]int{"self+exec:sh_nointerp": eNOENT, "self+exec:garbage": eNOEXEC, "self+exec:sh_dirinterp": eACCES, "self+exec:l1": eLOOP, "self+exec:sh_mark_deny": ePERM}
		for tok, code := range want {
			for _, r := range obs.Results {
				if r.Token == tok && r.Code != code {
					o.errorf("%s: code %d, want %d", tok, r.Code, code)
				}
			}
		}
		// The root's only commit is plain's (the failed execs commit
		// nothing), with the role still clean.
		var commits []optcengine.Detail
		for _, d := range o.eng.Details(obs.Root) {
			if d.Kind == optcengine.EventCommit {
				commits = append(commits, d)
			}
		}
		if len(commits) != 1 || commits[0].Path != o.h.Path("plain") || commits[0].KnownMask&2 == 0 || o.eng.RoleName(commits[0].Roles[1]) != "clean" {
			o.errorf("root commits %+v: want exactly plain's, role still clean", commits)
		}
	}},
	{"DenyInLaterPassCancelsProposalOfEarlierPass", func(o *oracle) {
		o.publish(o.allowList(e1Allow("sh_mark_deny")...), rolePolicy(o.fpMode(), o.setRule("marked", "sh_mark_deny"), o.denyIfRole("marked", "curl")))
		tok := "fork+rerun:sh_mark_deny,fork+exec:curl"
		obs := o.run(tok)
		r, _ := o.result(obs, tok)
		ds := o.details(r.PID, selfqual.EventDecision)
		if len(ds) < 2 || ds[0].Deny || !ds[1].Deny || ds[1].Path != o.h.Path("deny") {
			o.errorf("passes %+v: want sh_mark_deny allowed (proposes marked), deny denied", ds)
		}
		if o.strict() {
			if r.Code != ePERM || len(o.details(r.PID, optcengine.EventCommit)) != 0 {
				o.errorf("strict: %+v, want EPERM, no commit", r)
			}
			return
		}
		c, _ := o.commit(r.PID)
		if c.Flags&optcengine.CommitKnownDeny == 0 || o.eng.RoleName(c.Roles[1]) != "clean" || c.KnownMask&2 == 0 {
			o.errorf("audit commit %+v: want known deny, role still clean", c)
		}
		o.wantCurl(obs, "fork+exec:curl", false)
	}},
	{"UncertainRoleWriteCommitsUnknown_StrictRuleThenDenies", func(o *oracle) {
		// An Audit rule whose actor-path fact is UNKNOWN (the adopted root's
		// exe facts are UNKNOWN, R15) would set "restricted"; the role
		// becomes UNKNOWN, not "restricted" and not the old "plain". An
		// enforced rule that tests the role is then an evaluation error.
		roles := fullpolicy.Policy{ID: "e1-uncertain", Revision: "1", Mode: fullpolicy.Audit, RootRole: "plain", Default: fullpolicy.Allow, Rules: []fullpolicy.Rule{
			{Name: "uncertain-write", Action: fullpolicy.Allow, Mode: fullpolicy.Audit, Actor: fullpolicy.Actor{Path: []string{"/nonexistent/e1-actor"}}, Target: fullpolicy.Target{Path: o.paths("dyn"), SetRole: "restricted"}},
			{Name: "needs-plain", Action: fullpolicy.Allow, Mode: fullpolicy.Enforce, Actor: fullpolicy.Actor{Role: []string{"plain"}}, Target: fullpolicy.Target{Path: o.paths("curl")}},
		}}
		o.publish(o.allowList(e1Allow()...), roles)
		obs := o.run("fork+execarg:dyn,curl")
		r, _ := o.result(obs, "fork+execarg:dyn,curl")
		c, ok := o.commit(r.PID)
		if !ok || c.Flags&optcengine.CommitUncertain == 0 || c.KnownMask&2 != 0 {
			o.errorf("dyn commit %+v: want the uncertain bit to commit UNKNOWN", c)
		}
		ds := o.details(r.PID, selfqual.EventDecision)
		if r.Code != ePERM || len(ds) != 2 || !ds[1].Deny || !ds[1].Blocked || ds[1].Path != o.h.Path("curl") {
			o.errorf("curl after the uncertain write: %+v %+v, want EPERM in every mode (enforced rule, UNKNOWN role)", r, ds)
		}
	}},
	{"ParkedPTInterpExecAcrossRetire_TaintedCurl", func(o *oracle) {
		// N's role policy is role-bearing (a rule for plain, not run
		// here), so the task has a known row under N (review R1): the
		// mismatch must make it UNKNOWN, not find it absent.
		n := o.publish(o.allowList(e1Allow()...), rolePolicy(o.fpMode(), o.setRule("tainted", "plain")))
		next := []fullpolicy.Policy{o.allowList(e1Allow()...), rolePolicy(o.fpMode(), o.setRule("tainted", "dyn"), o.denyIfRole("tainted", "curl"))}
		// Control: an exec of dyn wholly under N leaves the role clean.
		obs := o.run("fork+execarg:dyn,curl")
		if r, _ := o.result(obs, "fork+execarg:dyn,curl"); r.Code != 0 {
			o.errorf("control under N: %+v, want curl to run", r)
		} else if c, ok := o.commit(r.PID); ok && (c.KnownMask&2 == 0 || o.eng.RoleName(c.Roles[1]) != "clean") {
			o.errorf("control dyn commit under N %+v: want the role policy's row known and clean", c)
		}
		var publishTook time.Duration
		var nn uint64
		obs, err := o.h.RunHeldOn(o.mode, "ldso", func(uint32) error {
			t0 := time.Now()
			var err error
			if nn, err = o.eng.PublishPolicies(o.cg(), next); err != nil {
				return err
			}
			o.h.SetGeneration(o.mode, nn)
			err = o.eng.Retire(o.cg(), n)
			publishTook = time.Since(t0)
			return err
		}, "fork+execarg:dyn,curl")
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		o.t.Logf("publish + retire while the exec was parked at PT_INTERP: %v", publishTook)
		if publishTook > time.Second {
			o.errorf("publication took %v while an exec was parked: it must not wait", publishTook)
		}
		r, _ := o.result(obs, "fork+execarg:dyn,curl")
		c, _ := o.commit(r.PID)
		if c.Flags&optcengine.CommitGenMismatch == 0 || c.KnownMask != 0 || c.Gen != n {
			o.errorf("parked dyn commit %+v: want generation %d, mismatch, every role UNKNOWN", c, n)
		}
		// curl under N+1 consults the UNKNOWN role: an enforced rule
		// denies (Strict); an audit rule reports audit-unknown (Audit).
		ds := o.details(r.PID, selfqual.EventDecision)
		if len(ds) != 2 || ds[0].Gen != n || ds[1].Gen != nn || ds[1].Path != o.h.Path("curl") ||
			o.strict() && (!ds[1].Deny || !ds[1].Blocked) || !o.strict() && (ds[1].Blocked || ds[1].AuditUnknown == 0) {
			o.errorf("decisions %+v: want dyn under N, curl under N+1 denied (Strict) or audit-unknown (Audit)", ds)
		}
		if o.strict() && r.Code != ePERM || !o.strict() && r.Code != 0 {
			o.errorf("curl from the parked task: code %d, want %d", r.Code, map[bool]int{true: ePERM, false: 0}[o.strict()])
		}
		// Control: an exec of dyn wholly under N+1 gets a known tainted role.
		obs = o.run("fork+execarg:dyn,curl")
		r, _ = o.result(obs, "fork+execarg:dyn,curl")
		o.wantCurlFrom(r, true)
	}},
	{"ParkedExecDeniedByNextGeneration_StrictKillsAuditReports", func(o *oracle) {
		n := o.publish(o.allowList(e1Allow()...))
		without := []string{}
		for _, name := range e1Allow() {
			if name != "dyn" {
				without = append(without, name)
			}
		}
		obs, err := o.h.RunHeldOn(o.mode, "ldso", func(uint32) error {
			nn, err := o.eng.PublishPolicies(o.cg(), []fullpolicy.Policy{o.allowList(without...)})
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
		if c.Flags&optcengine.CommitReevalDeny == 0 {
			o.errorf("commit %+v: want the re-evaluation under N+1 to deny", c)
		}
		if o.strict() && (r.Code != killed || r.Ran || c.Flags&optcengine.CommitKilled == 0) {
			o.errorf("strict: %+v flags %#x, want SIGKILL before the image ran", r, c.Flags)
		}
		if !o.strict() && (r.Code != 0 || !r.Ran || c.Flags&optcengine.CommitKilled != 0) {
			o.errorf("audit: %+v flags %#x, want it to run, reported", r, c.Flags)
		}
	}},
	{"ChrootSpoofOfAnAllowedPathIsUnknown", func(o *oracle) {
		obs := o.run("fork+chroot:allow")
		r, _ := o.result(obs, "fork+chroot:allow")
		ds := o.details(r.PID, selfqual.EventDecision)
		if len(ds) != 1 || !ds[0].Deny || ds[0].PathReason != optcengine.PathRootMismatch || ds[0].Path != "" {
			o.errorf("chroot spoof decisions %+v: want deny with the path UNKNOWN (root mismatch)", ds)
		}
		if o.strict() && (r.Code != ePERM || r.Ran) || !o.strict() && (r.Code != 0 || !r.Ran) {
			o.errorf("chroot spoof: %+v", r)
		}
	}},
	{"DeletedTargetIsUnknown", func(o *oracle) {
		o.publish(o.allowList(e1Allow("deltmp")...))
		obs := o.run("fork+deleted:allow")
		r, _ := o.result(obs, "fork+deleted:allow")
		ds := o.details(r.PID, selfqual.EventDecision)
		if len(ds) != 1 || !ds[0].Deny || ds[0].PathReason != optcengine.PathDeleted {
			o.errorf("deleted target decisions %+v: want deny, path UNKNOWN (deleted)", ds)
		}
		if o.strict() && r.Code != ePERM || !o.strict() && r.Code != 0 {
			o.errorf("deleted target: %+v", r)
		}
	}},
	{"FFlagInterpreterOpenedOutsideIsUnknown", func(o *oracle) {
		fflagScenario(o, true)
	}},
	{"DeepPathWalkExhaustionIsUnknown", func(o *oracle) {
		// 70 directories: longer than the 64-step reachability walk.
		deep := "deep" + strings.Repeat("/a", 70) + "/allow"
		o.publish(o.allowList(e1Allow(deep)...))
		obs := o.run("fork+deep:allow")
		r, _ := o.result(obs, "fork+deep:allow")
		ds := o.details(r.PID, selfqual.EventDecision)
		if len(ds) != 1 || !ds[0].Deny || ds[0].PathReason != optcengine.PathWalkUnknown {
			o.errorf("deep path decisions %+v: want deny, path UNKNOWN (walk exhausted)", ds)
		}
		if o.strict() && r.Code != ePERM || !o.strict() && r.Code != 0 {
			o.errorf("deep path exec: %+v", r)
		}
	}},
	{"ParkedExecAuditDenyUnderNextGen_ReportedNotKilled", func(o *oracle) {
		// F2: a class-2 binding (enforced allow-list) whose N+1 adds an
		// audit-mode deny of X. A straddling exec of X: the fresh N+1
		// verdict does not block, so the re-evaluation must not kill; it
		// reports would-deny.
		n := o.publish(o.allowList(e1Allow()...))
		auditDeny := fullpolicy.Policy{ID: "e1-audit-deny", Revision: "1", Mode: fullpolicy.Audit, Default: fullpolicy.Allow,
			Rules: []fullpolicy.Rule{{Name: "deny-dyn", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: o.paths("dyn")}}}}
		obs, err := o.h.RunHeldOn(o.mode, "ldso", func(uint32) error {
			nn, err := o.eng.PublishPolicies(o.cg(), []fullpolicy.Policy{o.allowList(e1Allow()...), auditDeny})
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
		if r.Code != 0 || !r.Ran || c.Flags&optcengine.CommitKilled != 0 || c.Flags&optcengine.CommitReevalDeny == 0 || c.Flags&optcengine.CommitGenMismatch == 0 {
			o.errorf("straddling exec with an audit deny under N+1: %+v flags %#x, want it to run, not killed, would-deny reported", r, c.Flags)
		}
	}},
	{"RoleGrantedByPolicyPublishedAfterAdoption", func(o *oracle) {
		// F3: the lineage exists (root adopted under N, no role policy);
		// N+1 adds a role policy; the root then runs the setter: the grant
		// must create the row, so its children see the role.
		next := []fullpolicy.Policy{o.allowList(e1Allow()...), rolePolicy(o.fpMode(), o.setRule("marked", "setter"), o.denyIfRole("marked", "curl"))}
		obs, err := o.h.RunHeld(o.mode, false, func(uint32) error {
			nn, err := o.eng.PublishPolicies(o.cg(), next)
			if err == nil {
				o.h.SetGeneration(o.mode, nn)
			}
			return err
		}, "fork+exec:sh_hold", "self+rerun:setter,fork+exec:curl")
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		var setter optcengine.Detail
		for _, d := range o.eng.Details(obs.Root) {
			if d.Kind == optcengine.EventCommit && d.Path == o.h.Path("setter") {
				setter = d
			}
		}
		marked := false
		for i, role := range setter.Roles {
			if setter.KnownMask&(1<<i) != 0 && o.eng.RoleName(role) == "marked" {
				marked = true
			}
		}
		if !marked {
			o.errorf("setter commit %+v: want a new row with the role marked, known", setter)
		}
		o.wantCurl(obs, "fork+exec:curl", true)
	}},
	{"PinnedCPUConcurrentExecsNoVerdictLeak", func(o *oracle) {
		// F1: every exec of the storm on one CPU, allow and deny files
		// interleaved: each decision and each outcome is the exec's own.
		const workers, iters = 8, 100
		obs, err := o.h.Run(selfqual.Where{Mode: o.mode, Adopt: true, Timeout: 120 * time.Second}, "pin:0", fmt.Sprintf("storm:%d:%d:allow:deny", workers, iters))
		if err != nil {
			o.fatalf("%v", err)
		}
		o.quiet(obs)
		if r, _ := o.result(obs, "pin:0"); r.Code != 0 {
			o.fatalf("pin to CPU 0: code %d", r.Code)
		}
		decisions := map[uint32][]selfqual.Event{}
		for _, ev := range obs.Events {
			if ev.Kind == selfqual.EventDecision {
				decisions[ev.PID] = append(decisions[ev.PID], ev)
			}
			if ev.Kind == selfqual.EventFault {
				o.errorf("fault during the pinned storm: %+v", ev)
			}
		}
		if len(obs.Storm) != workers*iters*2 {
			o.fatalf("%d attempts, want %d", len(obs.Storm), workers*iters*2)
		}
		bad := 0
		for _, a := range obs.Storm {
			ds := decisions[a.PID]
			wantDeny := a.File == "deny"
			wantCode := 0
			if wantDeny && o.strict() {
				wantCode = ePERM
			}
			if len(ds) != 1 || ds[0].Deny != wantDeny || ds[0].File != o.h.File(a.File) || a.Code != wantCode {
				bad++
				if bad <= 5 {
					o.errorf("attempt %+v decided %+v: a verdict that is not its own", a, ds)
				}
			}
		}
		if bad != 0 {
			o.errorf("%d of %d attempts leaked or lost a verdict", bad, len(obs.Storm))
		}
	}},
	// Known-gap probe (not an option C property): it asserts that the gap
	// exists, so a change in the exec hook's view is noticed.
	{"KnownGapProbe_LdLinuxRunsABinaryTheExecHookNeverSees", func(o *oracle) {
		ldso, err := filepath.EvalSymlinks("/lib64/ld-linux-x86-64.so.2")
		if err != nil {
			o.fatalf("ld.so: %v", err)
		}
		var allow []string
		for _, n := range e1Allow() {
			if n != "dyn" {
				allow = append(allow, n)
			}
		}
		o.publish(o.allowList(append(allow, ldso)...))
		obs := o.run("fork+exec:dyn", "fork+ldso:dyn")
		direct, _ := o.result(obs, "fork+exec:dyn")
		via, _ := o.result(obs, "fork+ldso:dyn")
		dd := o.details(direct.PID, selfqual.EventDecision)
		vd := o.details(via.PID, selfqual.EventDecision)
		o.t.Logf("direct exec of dyn: code %d ran %v decisions %+v", direct.Code, direct.Ran, dd)
		o.t.Logf("ld.so %s dyn: code %d ran %v decisions %+v", ldso, via.Code, via.Ran, vd)
		if len(dd) != 1 || !dd[0].Deny || dd[0].Path != o.h.Path("dyn") {
			o.errorf("direct exec of dyn: %+v, want denied as dyn", dd)
		}
		// The gap: one pass, for ld.so, allowed; dyn's code runs.
		if len(vd) != 1 || vd[0].Deny || vd[0].Path != ldso || via.Code != 0 || !via.Ran {
			o.errorf("ld.so exec: %+v %+v, want one allowed pass for %s and dyn's code running", via, vd, ldso)
		}
	}},
}

// perRule is one policy with one allow rule per fixture (rule count = len).
func (o *oracle) perRule(names ...string) fullpolicy.Policy {
	p := o.allowList()
	p.Rules = nil
	for i, n := range names {
		p.Rules = append(p.Rules, fullpolicy.Rule{Name: fmt.Sprintf("allow-%d", i), Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: o.paths(n)}})
	}
	return p
}

// manyNames returns n allow-list names: the real fixtures, then paths that
// name nothing (still distinct rules).
func manyNames(n int) []string {
	out := e1Allow()
	for i := len(out); i < n; i++ {
		out = append(out, fmt.Sprintf("/nonexistent/e1-rule-%d", i))
	}
	return out[:n]
}

// limitScenarios: a policy the loaded build cannot walk is refused at
// publication; a pass whose rule window cannot run denies in every mode.
var limitScenarios = []struct {
	name  string
	setup engineSetup
	run   func(o *oracle)
}{
	{"OversizedPolicyRefusedAtPublish", engineSetup{opts: optcengine.Options{StageCap: 1}}, func(o *oracle) {
		lim := o.eng.Limits()
		o.t.Logf("limits of the %s build with a window cap of 1: %+v", o.eng.Variant(), lim)
		if !lim.Staged || lim.MaxRules != optcengine.RulesPerWindow {
			o.fatalf("limits %+v, want a staged build walking %d rules", lim, optcengine.RulesPerWindow)
		}
		before := o.h.Generation(o.mode)
		_, err := o.eng.PublishPolicies(o.cg(), []fullpolicy.Policy{o.perRule(manyNames(lim.MaxRules + 1)...)})
		if !errors.Is(err, optcengine.ErrUnsupportedPolicy) {
			o.errorf("publish of %d rules: %v, want ErrUnsupportedPolicy", lim.MaxRules+1, err)
		}
		// At the limit it publishes and decides normally.
		o.publish(o.perRule(manyNames(lim.MaxRules)...))
		obs := o.run("fork+exec:allow")
		o.wantExec(obs, 0, 0, true, true, decided{"allow", false})
		// The refused attempt left nothing behind: the generation before the
		// accepted one is the bind generation.
		if before == 0 {
			o.errorf("no bind generation")
		}
		// And the default build refuses past the compiler's maximum.
		if _, err := o.eng.PublishPolicies(o.cg(), []fullpolicy.Policy{o.perRule(manyNames(fullpolicy.MaxRules + 1)...)}); err == nil {
			o.errorf("publish of %d rules accepted", fullpolicy.MaxRules+1)
		}
	}},
	// F5: a window that cannot run is a fault after classification: Strict
	// denies, Audit allows and reports (a fault event that did not block).
	{"MissingStageProgram_StrictDeniesAuditReports", engineSetup{}, func(o *oracle) {
		if err := o.eng.ClearStages(); err != nil {
			o.fatalf("%v", err)
		}
		o.wantStageFault(o.run("fork+exec:allow"), "no stage program")
	}},
	{"WindowCapReached_StrictDeniesAuditReports", engineSetup{opts: optcengine.Options{StageCap: 1, UnsafeNoPublishLimit: true}}, func(o *oracle) {
		// 40 rules need 3 windows; the cap allows 1.
		o.publish(o.perRule(manyNames(40)...))
		o.wantStageFault(o.run("fork+exec:allow"), "past the window cap")
	}},
	// F1: the owner stamp is checked at window entry and finish; a foreign
	// stamp (forced by a test knob) is a stage fault, never a decision.
	{"OwnerStampMismatch_StrictDeniesAuditReports", engineSetup{}, func(o *oracle) {
		if !o.testKnob("owner-stamp clobber") {
			return
		}
		if err := o.eng.ClobberStamp(o.cg(), true); err != nil {
			o.fatalf("%v", err)
		}
		o.wantStageFault(o.run("fork+exec:allow"), "foreign owner stamp")
	}},
}

func (o *oracle) wantStageFault(obs selfqual.Observation, what string) {
	if len(obs.Results) != 1 {
		o.errorf("%s: results %+v", what, obs.Results)
		return
	}
	r := obs.Results[0]
	if o.strict() && (r.Code != ePERM || r.Ran) || !o.strict() && (r.Code != 0 || !r.Ran) {
		o.errorf("exec with %s: %+v, want %s", what, r, map[bool]string{true: "EPERM (Strict)", false: "it to run (Audit)"}[o.strict()])
	}
	n := 0
	for _, ev := range obs.Events {
		switch {
		case ev.Kind == selfqual.EventFault && ev.Fault == optcengine.FaultStage && ev.Deny && ev.Blocked == o.strict():
			n++
		case ev.Kind == selfqual.EventDecision:
			o.errorf("%s: the undecided pass produced a decision: %+v", what, ev)
		}
	}
	if n != 1 {
		o.errorf("%s: %d stage-fault events (blocked=%v), want 1", what, n, o.strict())
	}
	if want := map[bool]uint64{true: 1, false: 0}[o.strict()]; obs.Delta.FaultDeny != want {
		o.errorf("%s: counters %+v, want %d fault denies", what, obs.Delta, want)
	}
}

func (o *oracle) wantCurlFrom(r selfqual.TokenResult, denied bool) {
	ds := o.details(r.PID, selfqual.EventDecision)
	if len(ds) != 2 || ds[1].Path != o.h.Path("curl") || ds[1].Deny != denied || ds[1].Error != 0 {
		o.errorf("%s: decisions %+v, want curl deny=%v by a known role", r.Token, ds, denied)
		return
	}
	want := 0
	if denied && o.strict() {
		want = ePERM
	}
	if r.Code != want {
		o.errorf("%s: code %d, want %d", r.Token, r.Code, want)
	}
}

// fflagScenario registers a binfmt_misc F-flag entry from the host mount
// namespace (outside the stage's): its interpreter is opened there, at a host
// path whose string equals an allowed fixture path. anchored: the engine's
// R31 checks are on (UNKNOWN expected), else the spoof is expected to work.
func fflagScenario(o *oracle, anchored bool) {
	// A binfmt_misc mount of our own, in the host mount namespace.
	bm, err := os.MkdirTemp("", "e1-binfmt-")
	if err != nil {
		o.fatalf("%v", err)
	}
	defer os.Remove(bm)
	if err := unix.Mount("binfmt_misc", bm, "binfmt_misc", 0, ""); err != nil {
		o.fatalf("binfmt_misc in the host namespace: %v", err)
	}
	defer unix.Unmount(bm, unix.MNT_DETACH)
	reg := filepath.Join(bm, "register")
	// The interpreter lives on an exec-able tmpfs of the host's mount
	// namespace (host /run and /tmp may be noexec); the policy allows its
	// path string, which in the stage's namespace names nothing.
	host, err := os.MkdirTemp("/run", "e1-fflag-")
	if err != nil {
		o.fatalf("%v", err)
	}
	defer os.Remove(host)
	if err := unix.Mount("e1-fflag", host, "tmpfs", 0, "mode=0755,size=16m"); err != nil {
		o.fatalf("host tmpfs: %v", err)
	}
	defer unix.Unmount(host, unix.MNT_DETACH)
	spoof := filepath.Join(host, "allow")
	img, err := os.ReadFile(o.h.HostPath("allow"))
	if err != nil {
		o.fatalf("%v", err)
	}
	if err := os.WriteFile(spoof, img, 0o755); err != nil {
		o.fatalf("%v", err)
	}
	name := fmt.Sprintf("e1F%d", os.Getpid())
	magic := fmt.Sprintf("E1FFLAG%08x", time.Now().UnixNano()&0xffffffff)
	if err := os.WriteFile(reg, []byte(fmt.Sprintf(":%s:M::%s::%s:F", name, magic, spoof)), 0); err != nil {
		o.fatalf("register F-flag entry: %v", err)
	}
	defer os.WriteFile(filepath.Join(bm, name), []byte("-1"), 0)
	if err := os.WriteFile(o.h.HostPath("bmF_file"), []byte(magic+"\n"), 0o755); err != nil {
		o.fatalf("%v", err)
	}
	o.publish(o.allowList(e1Allow("bmF_file", spoof)...))
	obs := o.run("fork+exec:bmF_file")
	r, _ := o.result(obs, "fork+exec:bmF_file")
	ds := o.details(r.PID, selfqual.EventDecision)
	o.t.Logf("F-flag exec: code %d ran %v decisions %+v", r.Code, r.Ran, ds)
	if len(ds) != 2 || ds[0].Deny || ds[0].Path != o.h.Path("bmF_file") {
		o.errorf("F-flag passes %+v: want bmF_file allowed, then the interpreter", ds)
		return
	}
	if anchored {
		if !ds[1].Deny || ds[1].PathReason != optcengine.PathUnreachable {
			o.errorf("F-flag interpreter pass %+v: want deny, path UNKNOWN (unreachable)", ds[1])
		}
		if o.strict() && r.Code != ePERM || !o.strict() && (r.Code != 0 || !r.Ran) {
			o.errorf("F-flag exec: %+v", r)
		}
		return
	}
	if ds[1].Deny || ds[1].Path != spoof || r.Code != 0 {
		o.errorf("without R31 the F-flag interpreter was expected to pass as %s: %+v %+v", spoof, r, ds[1])
	}
}

func runScenario(t *testing.T, mode selfqual.Mode, setup engineSetup, sc scenario) []string {
	o := newOracle(t, mode, setup)
	if o == nil {
		return nil
	}
	func() {
		defer func() {
			if r := recover(); r != nil && r != errFatal {
				panic(r)
			}
		}()
		sc.run(o)
	}()
	return o.errs
}

func modes() []selfqual.Mode { return []selfqual.Mode{selfqual.ModeStrict, selfqual.ModeAudit} }

// TestOracle: the D4 oracle's 17 scenarios and the E1 scenarios, Strict and
// Audit, on the engine variant that loads.
func TestOracle(t *testing.T) {
	requireOracle(t)
	for _, mode := range modes() {
		t.Run(mode.String(), func(t *testing.T) {
			for _, sc := range append(append([]scenario{}, d4Scenarios...), e1Scenarios...) {
				t.Run(sc.name, func(t *testing.T) {
					for _, e := range runScenario(t, mode, engineSetup{}, sc) {
						t.Error(e)
					}
				})
			}
			for _, sc := range limitScenarios {
				t.Run(sc.name, func(t *testing.T) {
					for _, e := range runScenario(t, mode, sc.setup, scenario{sc.name, sc.run}) {
						t.Error(e)
					}
				})
			}
			t.Run("StaleInitAdoptEntryCapturesNoAnchor", func(t *testing.T) {
				for _, e := range staleInitAdopt(t, mode) {
					t.Error(e)
				}
			})
			t.Run("AnchorCapture", func(t *testing.T) {
				for _, e := range anchorCapture(t, mode) {
					t.Error(e)
				}
			})
			t.Run("ParkedExec_Compromise8Baseline_NoReevaluation", func(t *testing.T) {
				// Baseline (alternative off): the parked exec runs with every
				// role UNKNOWN; nothing kills it.
				for _, e := range runScenario(t, mode, engineSetup{opts: optcengine.Options{NoReevaluate: true}}, scenario{"baseline", func(o *oracle) {
					n := o.publish(o.allowList(e1Allow()...))
					obs, err := o.h.RunHeldOn(o.mode, "ldso", func(uint32) error {
						nn, err := o.eng.PublishPolicies(o.cg(), []fullpolicy.Policy{o.allowList(selfqual.BaseAllow()...)})
						if err != nil {
							return err
						}
						o.h.SetGeneration(o.mode, nn)
						return o.eng.Retire(o.cg(), n)
					}, "fork+exec:dyn")
					if err != nil {
						o.fatalf("%v", err)
					}
					r, _ := o.result(obs, "fork+exec:dyn")
					c, _ := o.commit(r.PID)
					if r.Code != 0 || !r.Ran || c.Flags != optcengine.CommitGenMismatch || c.KnownMask != 0 {
						o.errorf("baseline: %+v commit %+v, want the image to run with every role UNKNOWN", r, c)
					}
				}}) {
					t.Error(e)
				}
			})
		})
	}
}

// anchorCapture: before the seeded init's first exec every path fact of the
// binding is UNKNOWN; the anchor is the init's root, captured once, never
// rewritten (a second, chrooted init cannot move it), and a chrooted task
// mismatches it.
func anchorCapture(t *testing.T, mode selfqual.Mode) []string {
	return anchorCaptureWith(t, mode, optcengine.Options{})
}

func anchorCaptureWith(t *testing.T, mode selfqual.Mode, opts optcengine.Options) []string {
	o := newOracle(t, mode, engineSetup{noInit: true, opts: opts})
	if o == nil {
		return nil
	}
	func() {
		defer func() {
			if r := recover(); r != nil && r != errFatal {
				panic(r)
			}
		}()
		if _, ok, err := o.eng.Anchor(o.cg()); ok || err != nil {
			o.fatalf("anchor before any init exec: ok=%v err=%v", ok, err)
		}
		obs := o.run("fork+exec:allow")
		r, _ := o.result(obs, "fork+exec:allow")
		ds := o.details(r.PID, selfqual.EventDecision)
		if len(ds) != 1 || !ds[0].Deny || ds[0].PathReason != optcengine.PathNoAnchor {
			o.errorf("exec before the anchor: %+v, want deny with the path UNKNOWN (no anchor)", ds)
		}
		if o.strict() && r.Code != ePERM || !o.strict() && r.Code != 0 {
			o.errorf("exec before the anchor: %+v", r)
		}
		if err := o.h.RunInit(o.mode); err != nil {
			o.fatalf("init exec: %v", err)
		}
		a, ok, err := o.eng.Anchor(o.cg())
		if !ok || err != nil {
			o.fatalf("anchor after the init exec: ok=%v err=%v", ok, err)
		}
		var st unix.Stat_t
		if err := unix.Stat(fmt.Sprintf("/proc/%d/root", o.h.StagePID()), &st); err != nil {
			o.fatalf("%v", err)
		}
		var ns unix.Stat_t
		if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", o.h.StagePID()), &ns); err != nil {
			o.fatalf("%v", err)
		}
		major, minor := a.RootDev>>20, a.RootDev&0xfffff
		mntID, err := rootMountID(o.h.StagePID())
		if err != nil {
			o.fatalf("%v", err)
		}
		if a.RootIno != st.Ino || major != unix.Major(st.Dev) || minor != unix.Minor(st.Dev) || uint64(a.MntNS) != ns.Ino || a.RootMntID != mntID {
			o.errorf("anchor %+v, want the init's root ino %d dev %d:%d mntns %d mnt_id %d", a, st.Ino, unix.Major(st.Dev), unix.Minor(st.Dev), ns.Ino, mntID)
		}
		obs = o.run("fork+exec:allow")
		o.wantExec(obs, 0, 0, true, true, decided{"allow", false})
		// A second seeded init whose first exec is from a chroot.
		// A chrooted descendant (an adopted task, not the init) mismatches it.
		obs = o.run("self+chroot:allow")
		if ds := o.details(obs.Root, selfqual.EventDecision); len(ds) != 1 || !ds[0].Deny || ds[0].PathReason != optcengine.PathRootMismatch {
			o.errorf("chrooted task exec: %+v, want root mismatch", ds)
		}
		b, ok, err := o.eng.Anchor(o.cg())
		if !ok || err != nil || b != a {
			o.errorf("anchor rewritten: %+v, was %+v", b, a)
		}
		if err := chrootedInit(o); err != nil {
			o.errorf("%v", err)
		}
		if b, _, _ := o.eng.Anchor(o.cg()); b != a {
			o.errorf("anchor rewritten by a chrooted init: %+v, was %+v", b, a)
		}
	}()
	return o.errs
}

// rootMountID is the mount id of pid's root (/proc/<pid>/mountinfo: the
// line whose mount point is "/" as seen from pid).
func rootMountID(pid int) (uint32, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return 0, err
	}
	var id uint32
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 4 && f[4] == "/" {
			var v uint32
			if _, err := fmt.Sscanf(f[0], "%d", &v); err == nil {
				id, found = v, true // the last "/" line is the one on top
			}
		}
	}
	if !found {
		return 0, fmt.Errorf("no root mount in /proc/%d/mountinfo", pid)
	}
	return id, nil
}

// staleInitAdopt (F8): an adopt entry marked init for a task the binding
// does not name as its init (stale or reused) must not capture the anchor.
func staleInitAdopt(t *testing.T, mode selfqual.Mode) []string {
	o := newOracle(t, mode, engineSetup{noInit: true, opts: optcengine.Options{StaleInitAdopt: true}})
	if o == nil {
		return nil
	}
	func() {
		defer func() {
			if r := recover(); r != nil && r != errFatal {
				panic(r)
			}
		}()
		obs, err := o.h.RunAsInit(o.mode, "self+exec:allow")
		if err != nil {
			o.fatalf("%v", err)
		}
		if _, ok, err := o.eng.Anchor(o.cg()); ok || err != nil {
			o.errorf("an anchor was captured from a stale init adopt entry (err %v)", err)
		}
		if ds := o.details(obs.Root, selfqual.EventDecision); len(ds) != 1 || !ds[0].Deny || ds[0].PathReason != optcengine.PathNoAnchor {
			o.errorf("exec through a stale init entry: %+v, want deny with no anchor", ds)
		}
	}()
	return o.errs
}

// chrootedInit adopts a probe root as a second seeded init whose first exec
// comes from a chroot: the anchor stays, the exec mismatches it.
func chrootedInit(o *oracle) error {
	obs, err := o.h.RunAsInit(o.mode, "self+chroot:allow")
	if err != nil {
		return err
	}
	ds := o.details(obs.Root, selfqual.EventDecision)
	if len(ds) != 1 || !ds[0].Deny || ds[0].PathReason != optcengine.PathRootMismatch {
		return fmt.Errorf("chrooted init exec: %+v %+v, want root mismatch", obs.Results, ds)
	}
	return nil
}

// mutantCase: a mutant engine the oracle must catch, the scenario that
// catches it, and the specific failure it must produce (F6).
type mutantCase struct {
	mutant   optcengine.Mutant
	mode     selfqual.Mode
	scenario string
	want     string
}

// TestMutantsDetected: each deliberately broken engine fails the scenario
// that guards its property with the expected finding (005 §9.4 E7), in each
// mode where the property applies.
func TestMutantsDetected(t *testing.T) {
	requireOracle(t)
	all := map[string]scenario{}
	for _, sc := range append(append([]scenario{}, d4Scenarios...), e1Scenarios...) {
		all[sc.name] = sc
	}
	S, A := selfqual.ModeStrict, selfqual.ModeAudit
	cases := []mutantCase{
		{optcengine.MutantAuditBlocks, A, "DenyStrictEPERM_AuditWouldDenyDoesNotBlock", "fork+exec:deny: code 1 ran=false"},
		{optcengine.MutantFaultAllows, S, "FaultBeforeClassificationDeniesInEveryMode", "injected fault"},
		{optcengine.MutantFaultAllows, A, "FaultBeforeClassificationDeniesInEveryMode", "injected fault"},
		// The undecided pass also latches the witness and the receipt
		// guard kills the image (E4-1); the missing decision is the finding.
		{optcengine.MutantSkipInterpPass, S, "ExecFailsAfterDeny", "fork+exec:sh_deny_interp: 1 decisions, want 2"},
		{optcengine.MutantSkipInterpPass, A, "ExecFailsAfterDeny", "fork+exec:sh_deny_interp: 1 decisions, want 2"},
		{optcengine.MutantNoRootCheck, S, "ChrootSpoofOfAnAllowedPathIsUnknown", "chroot spoof decisions"},
		{optcengine.MutantNoRootCheck, A, "ChrootSpoofOfAnAllowedPathIsUnknown", "chroot spoof decisions"},
		{optcengine.MutantNoReachCheck, S, "FFlagInterpreterOpenedOutsideIsUnknown", "F-flag interpreter pass"},
		{optcengine.MutantNoReachCheck, A, "FFlagInterpreterOpenedOutsideIsUnknown", "F-flag interpreter pass"},
		{optcengine.MutantNoDeletedCheck, S, "DeletedTargetIsUnknown", "deleted target decisions"},
		{optcengine.MutantNoDeletedCheck, A, "DeletedTargetIsUnknown", "deleted target decisions"},
		{optcengine.MutantWalkExhaustAllows, S, "DeepPathWalkExhaustionIsUnknown", "deep path decisions"},
		{optcengine.MutantWalkExhaustAllows, A, "DeepPathWalkExhaustionIsUnknown", "deep path decisions"},
		{optcengine.MutantNoRevalidate, S, "ParkedPTInterpExecAcrossRetire_TaintedCurl", "parked dyn commit"},
		{optcengine.MutantNoRevalidate, A, "ParkedPTInterpExecAcrossRetire_TaintedCurl", "parked dyn commit"},
		{optcengine.MutantOnlyProposedUnknown, S, "ParkedPTInterpExecAcrossRetire_TaintedCurl", "parked dyn commit"},
		{optcengine.MutantOnlyProposedUnknown, A, "ParkedPTInterpExecAcrossRetire_TaintedCurl", "parked dyn commit"},
		{optcengine.MutantReevalNoKill, S, "ParkedExecDeniedByNextGeneration_StrictKillsAuditReports", "want SIGKILL"},
		// Audit: under Strict the denied interpreter pass of sh_mark_deny
		// sets the leaked record's deny flag, which hides the leak.
		{optcengine.MutantNoReset, A, "RoleNotCommittedByAnyFailedExec_NorByTheNextExecOfAnotherFile", "fork+exec:curl: code 0 deny=true"},
		{optcengine.MutantNoUncertain, S, "UncertainRoleWriteCommitsUnknown_StrictRuleThenDenies", "dyn commit"},
		{optcengine.MutantNoUncertain, A, "UncertainRoleWriteCommitsUnknown_StrictRuleThenDenies", "dyn commit"},
		{optcengine.MutantNoInherit, S, "RoleVisibleToNextExecAndToChildrenOfEveryCreator", "deny=true error 0"},
		{optcengine.MutantNoInherit, A, "RoleVisibleToNextExecAndToChildrenOfEveryCreator", "deny=true error 0"},
		{optcengine.MutantR11Allows, S, "UnknownTaskInBoundCgroup_StrictDeniesAuditAllows", "unknown task:"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("mutant%d/%s/%s", c.mutant, c.mode, c.scenario), func(t *testing.T) {
			sc, ok := all[c.scenario]
			if !ok {
				t.Fatalf("no scenario %s", c.scenario)
			}
			// A mutant may latch the witness (a second detection).
			errs := runScenario(t, c.mode, engineSetup{opts: optcengine.Options{Mutant: c.mutant}, allowLatch: true}, sc)
			for _, e := range errs {
				if strings.Contains(e, c.want) {
					t.Logf("detected: %s", e)
					return
				}
			}
			t.Fatalf("mutant %d: no finding containing %q (findings: %q)", c.mutant, c.want, errs)
		})
	}
	// Anchor recapture and a stage fault that allows are caught by the
	// AnchorCapture and limit scenarios (their own setups).
	t.Run("mutantAnchorRecapture", func(t *testing.T) {
		for _, mode := range []selfqual.Mode{S, A} {
			if errs := anchorCaptureWith(t, mode, optcengine.Options{Mutant: optcengine.MutantAnchorRecapture}); !containsAny(errs, "anchor rewritten") {
				t.Errorf("%s: mutant not caught: %q", mode, errs)
			}
		}
	})
	t.Run("mutantStageFaultAllows", func(t *testing.T) {
		for _, sc := range limitScenarios {
			if !strings.HasPrefix(sc.name, "MissingStageProgram") {
				continue
			}
			setup := sc.setup
			setup.opts.Mutant = optcengine.MutantStageFaultAllows
			if errs := runScenario(t, S, setup, scenario{sc.name, sc.run}); !containsAny(errs, "want EPERM (Strict)") {
				t.Errorf("mutant not caught: %q", errs)
			}
		}
	})
}

func containsAny(errs []string, s string) bool {
	for _, e := range errs {
		if strings.Contains(e, s) {
			return true
		}
	}
	return false
}

// TestSpoofsWithoutR31: scenario (b) of the colleague-proposal review: a
// bpf_d_path path fact without the R31 anchor is spoofable by chroot and by
// an F-flag interpreter opened outside; with it, both are UNKNOWN (TestOracle).
func TestSpoofsWithoutR31(t *testing.T) {
	requireOracle(t)
	// Each spoof with only the check that catches it removed: the root
	// comparison for the chroot, the reachability walk for the F-flag.
	t.Run("Chroot", func(t *testing.T) {
		setup := engineSetup{opts: optcengine.Options{Mutant: optcengine.MutantNoRootCheck}}
		for _, e := range runScenario(t, selfqual.ModeStrict, setup, scenario{"chroot", func(o *oracle) {
			obs := o.run("fork+chroot:allow")
			r, _ := o.result(obs, "fork+chroot:allow")
			ds := o.details(r.PID, selfqual.EventDecision)
			o.t.Logf("without R31: chroot spoof code %d ran %v decisions %+v", r.Code, r.Ran, ds)
			if len(ds) != 1 || ds[0].Deny || ds[0].Path != o.h.Path("allow") || r.Code != 0 || !r.Ran {
				o.errorf("without R31 the chroot spoof was expected to pass as %s: %+v %+v", o.h.Path("allow"), r, ds)
			}
		}}) {
			t.Error(e)
		}
	})
	t.Run("FFlag", func(t *testing.T) {
		setup := engineSetup{opts: optcengine.Options{Mutant: optcengine.MutantNoReachCheck}}
		for _, e := range runScenario(t, selfqual.ModeStrict, setup, scenario{"fflag", func(o *oracle) { fflagScenario(o, false) }}) {
			t.Error(e)
		}
	})
}

// TestVariants: the product object (no test switches) and the test object
// both load and attach on this kernel.
func TestVariants(t *testing.T) {
	requireOracle(t)
	for _, product := range []bool{true, false} {
		e, err := optcengine.Load(optcengine.Options{Product: product})
		if err != nil {
			t.Fatalf("product=%v: %v", product, err)
		}
		t.Logf("VARIANT %s: LOADED", e.Variant())
		e.Close()
	}
	t.Logf("SELECTED test")
}
