// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package refengine_test

// The semantic oracle of the D4 prototype: the enforce_exec fail-closed
// contract, stated as hand-written expectations per scenario and checked on
// the live kernel, in Strict and in Audit. It uses the probe plumbing
// (selfqual.Harness) but none of the admission suite's model or invariants.
//
// It needs root, cgroup v2, bpf in the LSM list and binfmt_misc. It runs only
// with EE_SELFQUAL_ORACLE=1. Nothing in it skips once that is set: a missing
// precondition is a failure.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/selfqual"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/selfqual/refengine"
)

const (
	ePERM   = int(unix.EPERM)
	eNOENT  = int(unix.ENOENT)
	eNOEXEC = int(unix.ENOEXEC)
	eACCES  = int(unix.EACCES)
	eLOOP   = int(unix.ELOOP)
)

func requireOracle(t *testing.T) {
	t.Helper()
	if os.Getenv("EE_SELFQUAL_ORACLE") != "1" {
		t.Skip("set EE_SELFQUAL_ORACLE=1 (root, bpf LSM, cgroup v2) to run the kernel oracle")
	}
}

type oracle struct {
	t    *testing.T
	h    *selfqual.Harness
	mode selfqual.Mode
}

func newOracle(t *testing.T, mode selfqual.Mode) *oracle {
	t.Helper()
	eng, err := refengine.Load(refengine.Options{})
	if err != nil {
		t.Fatalf("load engine: %v", err)
	}
	t.Cleanup(func() { eng.Close() })
	h, err := selfqual.NewHarness(eng, selfqual.Options{})
	if err != nil {
		t.Fatalf("harness: %v", err)
	}
	t.Cleanup(func() {
		c, cErr := h.Counters()
		if err := h.Close(); err != nil {
			t.Errorf("teardown: %v", err)
		}
		if cErr != nil || c.Pending != 0 || c.Live != 0 || c.StalePending != 0 || c.EventLost != 0 || c.StorageFail != 0 {
			t.Errorf("engine not clean at the end: %+v (%v)", c, cErr)
		}
	})
	return &oracle{t: t, h: h, mode: mode}
}

func (o *oracle) strict() bool { return o.mode == selfqual.ModeStrict }

// run runs tokens in an adopted root of the mode's cgroup and requires the
// engine to be quiet afterwards: no pending record, no tracked task left.
func (o *oracle) run(tokens ...string) selfqual.Observation {
	o.t.Helper()
	obs, err := o.h.Run(selfqual.Where{Mode: o.mode, Adopt: true}, tokens...)
	if err != nil {
		o.t.Fatalf("run %v: %v", tokens, err)
	}
	o.quiet(obs)
	return obs
}

func (o *oracle) quiet(obs selfqual.Observation) {
	o.t.Helper()
	d := obs.Delta
	if !obs.Quiesced || d.Pending != 0 || d.Live != 0 {
		o.t.Errorf("engine not quiet: quiesced=%v pending=%d live=%d", obs.Quiesced, d.Pending, d.Live)
	}
	if d.StalePending != 0 || d.EventLost != 0 || d.StorageFail != 0 {
		o.t.Errorf("engine faults: %+v", d)
	}
}

// decided is the per-pass expectation of one exec.
type decided struct {
	file string
	deny bool
}

// wantExec checks one token: its code, whether its image ran, the decisions
// the kernel recorded for its pid (file, deny, blocked, pass, mode) and its
// outcome event.
func (o *oracle) wantExec(obs selfqual.Observation, i, code int, ran bool, outcome uint32, ret int, passes ...decided) {
	o.t.Helper()
	if i >= len(obs.Results) {
		o.t.Errorf("no result %d (have %d)", i, len(obs.Results))
		return
	}
	res := obs.Results[i]
	if res.Code != code || res.Ran != ran {
		o.t.Errorf("%s: code %d ran=%v, want code %d ran=%v", res.Token, res.Code, res.Ran, code, ran)
	}
	var ds []selfqual.Event
	var outs []selfqual.Event
	for _, ev := range obs.Events {
		if ev.PID != res.PID {
			continue
		}
		switch ev.Kind {
		case selfqual.EventDecision:
			ds = append(ds, ev)
		case selfqual.EventOutcome:
			outs = append(outs, ev)
		}
	}
	if len(ds) != len(passes) {
		o.t.Errorf("%s: %d decisions, want %d: %+v", res.Token, len(ds), len(passes), ds)
	} else {
		for j, p := range passes {
			d := ds[j]
			wantBlocked := p.deny && o.strict()
			if d.File != o.h.File(p.file) || d.Deny != p.deny || d.Blocked != wantBlocked || int(d.Pass) != j || d.Mode != o.mode || d.Cgroup != o.h.CgroupID(o.mode) || d.Gen != ds[0].Gen {
				o.t.Errorf("%s pass %d: %+v, want file %s deny=%v blocked=%v", res.Token, j, d, p.file, p.deny, wantBlocked)
			}
		}
	}
	switch {
	case outcome == 0 && len(outs) != 0:
		o.t.Errorf("%s: unexpected outcome %+v", res.Token, outs)
	case outcome != 0 && (len(outs) != 1 || outs[0].Outcome != outcome || int(outs[0].Ret) != ret):
		o.t.Errorf("%s: outcomes %+v, want one outcome %d ret %d", res.Token, outs, outcome, ret)
	}
}

func (o *oracle) wantCounters(obs selfqual.Observation, want selfqual.Counters) {
	o.t.Helper()
	got := obs.Delta
	got.Births, got.Exits, got.Adopted = 0, 0, 0
	if got != want {
		o.t.Errorf("counters\n got  %+v\n want %+v", got, want)
	}
}

type scenario struct {
	name string
	run  func(o *oracle)
}

var scenarios = []scenario{
	{"Allow", func(o *oracle) {
		obs := o.run("fork+exec:allow")
		o.wantExec(obs, 0, 0, true, selfqual.OutcomeOK, 0, decided{"allow", false})
		o.wantCounters(obs, selfqual.Counters{Execs: 1, Decisions: 1, Allow: 1, ExecOK: 1})
	}},
	{"DenyStrictEPERM_AuditWouldDenyDoesNotBlock", func(o *oracle) {
		obs := o.run("fork+exec:deny")
		if o.strict() {
			o.wantExec(obs, 0, ePERM, false, selfqual.OutcomeFail, -ePERM, decided{"deny", true})
			o.wantCounters(obs, selfqual.Counters{Execs: 1, Decisions: 1, Deny: 1, ExecFail: 1})
		} else {
			o.wantExec(obs, 0, 0, true, selfqual.OutcomeOK, 0, decided{"deny", true})
			o.wantCounters(obs, selfqual.Counters{Execs: 1, Decisions: 1, WouldDeny: 1, ExecOK: 1})
		}
	}},
	{"FaultBeforeClassificationDeniesInEveryMode", func(o *oracle) {
		if err := o.h.InjectFault(o.mode, true); err != nil {
			o.t.Fatal(err)
		}
		obs, err := o.h.Run(selfqual.Where{Mode: o.mode, Adopt: true}, "fork+exec:allow")
		if offErr := o.h.InjectFault(o.mode, false); offErr != nil {
			o.t.Fatal(offErr)
		}
		if err != nil {
			o.t.Fatal(err)
		}
		o.quiet(obs)
		// EPERM in Strict and in Audit: the exec was never classified.
		o.wantExec(obs, 0, ePERM, false, selfqual.OutcomeFail, -ePERM)
		o.wantCounters(obs, selfqual.Counters{Execs: 1, FaultDeny: 1, ExecFail: 1})
		faults := 0
		for _, ev := range obs.Events {
			if ev.Kind == selfqual.EventFault && ev.Fault == selfqual.FaultInjected && ev.Blocked {
				faults++
			}
		}
		if faults != 1 {
			o.t.Errorf("%d injected-fault events, want 1", faults)
		}
		// And the engine classifies again afterwards.
		obs = o.run("fork+exec:allow")
		o.wantExec(obs, 0, 0, true, selfqual.OutcomeOK, 0, decided{"allow", false})
	}},
	{"RetiredGenerationMidExecDeniesInEveryMode", func(o *oracle) {
		old := o.h.Generation(o.mode)
		obs, err := o.h.RunHeld(o.mode, false, func(uint32) error {
			if _, err := o.h.Publish(o.mode, selfqual.BaseAllow()...); err != nil {
				return err
			}
			return o.h.Retire(o.mode, old)
		}, "fork+exec:sh_hold")
		if err != nil {
			o.t.Fatal(err)
		}
		o.quiet(obs)
		o.wantExec(obs, 0, ePERM, false, selfqual.OutcomeFail, -ePERM, decided{"sh_hold", false})
		o.wantCounters(obs, selfqual.Counters{Execs: 1, Decisions: 1, Allow: 1, FaultDeny: 1, ExecFail: 1})
	}},
	{"ExecFailsAfterAllow_ENOENT_ENOEXEC_BadInterpreter_ELOOP", func(o *oracle) {
		obs := o.run("fork+exec:sh_nointerp", "fork+exec:garbage", "fork+exec:sh_dirinterp", "fork+exec:l1", "fork+exec:allow")
		o.wantExec(obs, 0, eNOENT, false, selfqual.OutcomeFail, -eNOENT, decided{"sh_nointerp", false})
		o.wantExec(obs, 1, eNOEXEC, false, selfqual.OutcomeFail, -eNOEXEC, decided{"garbage", false})
		o.wantExec(obs, 2, eACCES, false, selfqual.OutcomeFail, -eACCES, decided{"sh_dirinterp", false})
		o.wantExec(obs, 3, eLOOP, false, selfqual.OutcomeFail, -eLOOP,
			decided{"l1", false}, decided{"l2", false}, decided{"l3", false}, decided{"l4", false}, decided{"l5", false}, decided{"l6", false})
		o.wantExec(obs, 4, 0, true, selfqual.OutcomeOK, 0, decided{"allow", false})
		o.wantCounters(obs, selfqual.Counters{Execs: 5, Decisions: 10, Allow: 10, ExecFail: 4, ExecOK: 1})
	}},
	{"ExecFailsBeforeDecisionLeavesNoRecord", func(o *oracle) {
		obs := o.run("fork+exec:missing", "fork+exec:noperm")
		o.wantExec(obs, 0, eNOENT, false, 0, 0)
		o.wantExec(obs, 1, eACCES, false, 0, 0)
		o.wantCounters(obs, selfqual.Counters{})
	}},
	{"ExecFailsAfterDeny", func(o *oracle) {
		// A denied file that is also not executable, and an allowed script
		// whose interpreter is denied.
		obs := o.run("fork+exec:garbage_denied", "fork+exec:sh_deny_interp", "fork+exec:sh_denied")
		if o.strict() {
			o.wantExec(obs, 0, ePERM, false, selfqual.OutcomeFail, -ePERM, decided{"garbage_denied", true})
			o.wantExec(obs, 1, ePERM, false, selfqual.OutcomeFail, -ePERM, decided{"sh_deny_interp", false}, decided{"deny", true})
			o.wantExec(obs, 2, ePERM, false, selfqual.OutcomeFail, -ePERM, decided{"sh_denied", true})
			o.wantCounters(obs, selfqual.Counters{Execs: 3, Decisions: 4, Allow: 1, Deny: 3, ExecFail: 3})
		} else {
			// Audit: reported, not blocked; the kernel's own failure stands.
			o.wantExec(obs, 0, eNOEXEC, false, selfqual.OutcomeFail, -eNOEXEC, decided{"garbage_denied", true})
			o.wantExec(obs, 1, 0, true, selfqual.OutcomeOK, 0, decided{"sh_deny_interp", false}, decided{"deny", true})
			o.wantExec(obs, 2, 0, true, selfqual.OutcomeOK, 0, decided{"sh_denied", true}, decided{"allow", false})
			o.wantCounters(obs, selfqual.Counters{Execs: 3, Decisions: 5, Allow: 2, WouldDeny: 3, ExecFail: 1, ExecOK: 2})
		}
	}},
	{"InterpreterChainAndBinfmtMisc", func(o *oracle) {
		if !o.h.HasBinfmtMisc() {
			o.t.Fatal("binfmt_misc is not available: the oracle does not skip")
		}
		obs := o.run("fork+exec:sh_ok", "fork+exec:c1", "fork+exec:bm_file")
		o.wantExec(obs, 0, 0, true, selfqual.OutcomeOK, 0, decided{"sh_ok", false}, decided{"allow", false})
		o.wantExec(obs, 1, 0, true, selfqual.OutcomeOK, 0,
			decided{"c1", false}, decided{"c2", false}, decided{"c3", false}, decided{"c4", false}, decided{"c5", false}, decided{"allow", false})
		o.wantExec(obs, 2, 0, true, selfqual.OutcomeOK, 0, decided{"bm_file", false}, decided{"allow", false})
		o.wantCounters(obs, selfqual.Counters{Execs: 3, Decisions: 10, Allow: 10, ExecOK: 3})
	}},
	{"FdBasedExec_AtEmptyPath_Fexecve_Memfd", func(o *oracle) {
		obs := o.run("fork+at_empty:deny", "fork+fexecve:deny", "fork+fdpath:deny", "fork+dirfd:deny", "fork+at_empty:allow", "fork+memfd:allow")
		code, ran, out, ret := 0, true, uint32(selfqual.OutcomeOK), 0
		if o.strict() {
			code, ran, out, ret = ePERM, false, selfqual.OutcomeFail, -ePERM
		}
		for i := 0; i < 4; i++ {
			o.wantExec(obs, i, code, ran, out, ret, decided{"deny", true})
		}
		o.wantExec(obs, 4, 0, true, selfqual.OutcomeOK, 0, decided{"allow", false})
		// The memfd copy of an allowed file is on no allow-list.
		if len(obs.Results) == 6 {
			res := obs.Results[5]
			if res.Code != code || res.Ran != ran {
				o.t.Errorf("memfd exec: code %d ran=%v, want %d %v", res.Code, res.Ran, code, ran)
			}
			for _, ev := range obs.Events {
				if ev.PID == res.PID && ev.Kind == selfqual.EventDecision && (!ev.Deny || ev.File == o.h.File("allow")) {
					o.t.Errorf("memfd exec decided as the allowed file: %+v", ev)
				}
			}
		} else {
			o.t.Errorf("%d results, want 6", len(obs.Results))
		}
		if o.strict() {
			o.wantCounters(obs, selfqual.Counters{Execs: 6, Decisions: 6, Allow: 1, Deny: 5, ExecFail: 5, ExecOK: 1})
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
			o.wantExec(obs, 2*i, 0, true, selfqual.OutcomeOK, 0, decided{"allow", false})
			if o.strict() {
				o.wantExec(obs, 2*i+1, ePERM, false, selfqual.OutcomeFail, -ePERM, decided{"deny", true})
			} else {
				o.wantExec(obs, 2*i+1, 0, true, selfqual.OutcomeOK, 0, decided{"deny", true})
			}
		}
		if obs.Delta.Births != 10 || obs.Delta.Adopted != 1 || obs.Delta.Exits != 11 {
			o.t.Errorf("births %d adopted %d exits %d, want 10, 1, 11", obs.Delta.Births, obs.Delta.Adopted, obs.Delta.Exits)
		}
	}},
	{"UnknownTaskInBoundCgroupIsNeverAllowed", func(o *oracle) {
		// Not adopted: in the bound cgroup, unknown to the engine.
		obs, err := o.h.Run(selfqual.Where{Mode: o.mode}, "fork+exec:allow", "self+exec:allow")
		if err != nil {
			o.t.Fatal(err)
		}
		o.quiet(obs)
		if len(obs.Results) != 2 || obs.Results[0].Code != 300+ePERM || obs.Results[1].Code != ePERM || obs.Results[0].Ran || obs.Results[1].Ran {
			o.t.Errorf("unknown task: %+v, want fork EPERM and exec EPERM in %s", obs.Results, o.mode)
		}
		o.wantCounters(obs, selfqual.Counters{UnknownFork: 1, UnknownExec: 1})
		if obs.Delta.Births != 0 || obs.Delta.Adopted != 0 {
			o.t.Errorf("unknown task was tracked: %+v", obs.Delta)
		}
		// An outsider clones a child straight into the bound cgroup.
		obs, err = o.h.Run(selfqual.Where{Outside: true}, "into@"+o.h.CgroupPath(o.mode)+"+exec:allow")
		if err != nil {
			o.t.Fatal(err)
		}
		o.quiet(obs)
		if len(obs.Results) != 1 || obs.Results[0].Code != ePERM || obs.Results[0].Ran {
			o.t.Errorf("cloned-in unknown child: %+v, want EPERM", obs.Results)
		}
		o.wantCounters(obs, selfqual.Counters{UnknownExec: 1})
	}},
	{"TaskOutsideEveryBindingIsUntouched", func(o *oracle) {
		obs, err := o.h.Run(selfqual.Where{Outside: true}, "fork+exec:deny", "fork+exec:allow")
		if err != nil {
			o.t.Fatal(err)
		}
		o.quiet(obs)
		if len(obs.Results) != 2 || obs.Results[0].Code != 0 || !obs.Results[0].Ran || obs.Results[1].Code != 0 || !obs.Results[1].Ran {
			o.t.Errorf("outside task: %+v, want both to run", obs.Results)
		}
		if len(obs.Events) != 0 || obs.Delta != (selfqual.Counters{}) {
			o.t.Errorf("outside task was observed: %d events, %+v", len(obs.Events), obs.Delta)
		}
	}},
	{"MultiThreadedExecDeThread", func(o *oracle) {
		obs := o.run("thread+exec:allow", "thread+exec:deny", "thread+exec:sh_ok")
		o.wantExec(obs, 0, 0, true, selfqual.OutcomeOK, 0, decided{"allow", false})
		if o.strict() {
			o.wantExec(obs, 1, ePERM, false, selfqual.OutcomeFail, -ePERM, decided{"deny", true})
		} else {
			o.wantExec(obs, 1, 0, true, selfqual.OutcomeOK, 0, decided{"deny", true})
		}
		o.wantExec(obs, 2, 0, true, selfqual.OutcomeOK, 0, decided{"sh_ok", false}, decided{"allow", false})
		// Five tasks per token (the process, three idle threads, the
		// exec-ing thread): all gone, none left tracked.
		if obs.Delta.Births != 15 || obs.Delta.Exits != 16 {
			o.t.Errorf("births %d exits %d, want 15 and 16", obs.Delta.Births, obs.Delta.Exits)
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
			o.t.Fatalf("%d results for %d tokens", len(obs.Results), len(tokens))
		}
		if d.Execs != d.ExecOK+d.ExecFail+d.ExecAbort {
			o.t.Errorf("%d execs decided, %d settled", d.Execs, d.ExecOK+d.ExecFail+d.ExecAbort)
		}
		if d.Exits != d.Births+d.Adopted {
			o.t.Errorf("%d exits, %d births + %d adopted", d.Exits, d.Births, d.Adopted)
		}
		completed := map[uint32]bool{}
		blocked := map[uint32]bool{}
		for _, ev := range obs.Events {
			if ev.Kind == selfqual.EventOutcome && ev.Outcome == selfqual.OutcomeOK {
				completed[ev.PID] = true
			}
			if ev.Kind == selfqual.EventDecision && ev.Blocked {
				blocked[ev.PID] = true
			}
		}
		for i, res := range obs.Results {
			if res.Ran && !completed[res.PID] {
				o.t.Errorf("%s: image ran, no completed exec recorded", res.Token)
			}
			if o.strict() && tokens[i] == "exitrace+exec:deny" && (res.Ran || completed[res.PID]) {
				o.t.Errorf("%s: a denied image ran under Strict", res.Token)
			}
			if blocked[res.PID] && completed[res.PID] {
				o.t.Errorf("%s: blocked and completed", res.Token)
			}
		}
	}},
	{"TaskKilledMidExecLeavesNoPendingRecord", func(o *oracle) {
		obs, err := o.h.RunHeld(o.mode, true, nil, "fork+exec:sh_hold", "fork+exec:allow")
		if err != nil {
			o.t.Fatal(err)
		}
		o.quiet(obs)
		if len(obs.Results) != 2 || obs.Results[0].Code != 1000+int(unix.SIGKILL) || obs.Results[0].Ran || obs.Results[1].Code != 0 || !obs.Results[1].Ran {
			o.t.Errorf("results %+v, want SIGKILL then a normal exec", obs.Results)
		}
		d := obs.Delta
		if d.Execs != 2 || d.ExecOK != 1 || d.ExecFail+d.ExecAbort != 1 || d.Decisions != 2 {
			o.t.Errorf("counters %+v, want 2 execs: 1 completed, 1 settled by failure or abort", d)
		}
	}},
	{"ExecParkedAcrossGenerationSwitchKeepsItsGeneration", func(o *oracle) {
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
			o.t.Fatal(err)
		}
		o.quiet(obs)
		// The parked exec was decided under the old generation on both
		// passes and runs; the next one meets the new generation.
		o.wantExec(obs, 0, 0, true, selfqual.OutcomeOK, 0, decided{"sh_hold", false}, decided{"hold_interp", false})
		if o.strict() {
			o.wantExec(obs, 1, ePERM, false, selfqual.OutcomeFail, -ePERM, decided{"sh_hold", false}, decided{"hold_interp", true})
		} else {
			o.wantExec(obs, 1, 0, true, selfqual.OutcomeOK, 0, decided{"sh_hold", false}, decided{"hold_interp", true})
		}
		for _, ev := range obs.Events {
			if ev.Kind != selfqual.EventDecision || len(obs.Results) != 2 {
				continue
			}
			if ev.PID == obs.Results[0].PID && ev.Gen != old {
				o.t.Errorf("parked exec decided under generation %d, want %d", ev.Gen, old)
			}
			if ev.PID == obs.Results[1].PID && ev.Gen != next {
				o.t.Errorf("next exec decided under generation %d, want %d", ev.Gen, next)
			}
		}
	}},
	{"AtomicGenerationSwitchDuringConcurrentExecs", func(o *oracle) {
		const workers, iters, switches = 8, 150, 5
		total := uint64(workers * iters * 2)
		// Odd generations allow only "allow"; even ones allow only "deny".
		allowed := map[uint64]string{}
		gen, err := o.h.Publish(o.mode, "allow")
		if err != nil {
			o.t.Fatal(err)
		}
		allowed[gen] = "allow"
		obs, err := o.h.Run(selfqual.Where{Mode: o.mode, Adopt: true, Timeout: 90 * time.Second, During: func() error {
			base, err := o.h.Counters()
			if err != nil {
				return err
			}
			deadline := time.Now().Add(60 * time.Second)
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
				gen, err := o.h.Publish(o.mode, name)
				if err != nil {
					return err
				}
				allowed[gen] = name
			}
			return nil
		}}, fmt.Sprintf("storm:%d:%d:allow:deny", workers, iters))
		if err != nil {
			o.t.Fatal(err)
		}
		o.quiet(obs)
		decisions := map[uint32][]selfqual.Event{}
		seen := map[uint64]int{}
		for _, ev := range obs.Events {
			if ev.Kind == selfqual.EventDecision {
				decisions[ev.PID] = append(decisions[ev.PID], ev)
				seen[ev.Gen]++
			}
		}
		if uint64(len(obs.Storm)) != total || obs.Delta.Execs != total || obs.Delta.Decisions != total {
			o.t.Fatalf("%d attempts, %d execs, %d decisions, want %d each", len(obs.Storm), obs.Delta.Execs, obs.Delta.Decisions, total)
		}
		last := map[int]uint64{}
		bad := 0
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
			if !known || d.Deny != wantDeny || d.File != o.h.File(a.File) || a.Code != wantCode || d.Gen < last[a.Worker] {
				bad++
				if bad <= 5 {
					o.t.Errorf("attempt %+v decided %+v: generation allows %q, worker last saw %d", a, d, name, last[a.Worker])
				}
			}
			last[a.Worker] = d.Gen
		}
		if bad != 0 {
			o.t.Errorf("%d of %d attempts violate the generation they were decided under", bad, total)
		}
		if len(seen) != switches+1 {
			o.t.Errorf("execs were decided under %d generations, want %d: the switches raced nothing", len(seen), switches+1)
		}
	}},
}

func TestOracle(t *testing.T) {
	requireOracle(t)
	for _, mode := range []selfqual.Mode{selfqual.ModeStrict, selfqual.ModeAudit} {
		t.Run(mode.String(), func(t *testing.T) {
			for _, sc := range scenarios {
				t.Run(sc.name, func(t *testing.T) {
					sc.run(newOracle(t, mode))
				})
			}
		})
	}
}

// TestOracleAdmission: the self-qualification admits the engine the oracle
// passes on, and refuses engines and helpers that are broken on purpose.
func TestOracleAdmission(t *testing.T) {
	requireOracle(t)
	qualify := func(t *testing.T, eopts refengine.Options, opts selfqual.Options) (*selfqual.Report, error) {
		t.Helper()
		eng, err := refengine.Load(eopts)
		if err != nil {
			t.Fatalf("load engine: %v", err)
		}
		defer eng.Close()
		opts.RequireBinfmtMisc = true
		return selfqual.Run(context.Background(), eng, opts)
	}
	t.Run("AdmitsTheEngineTheOraclePassesOn", func(t *testing.T) {
		rep, err := qualify(t, refengine.Options{}, selfqual.Options{})
		if err != nil || !rep.Admitted || rep.Failed != 0 || rep.NotApplic != 0 {
			t.Fatalf("not admitted: %v (%d failed, %d n/a)", err, rep.Failed, rep.NotApplic)
		}
	})
	refused := func(t *testing.T, rep *selfqual.Report, err error) {
		t.Helper()
		if !errors.Is(err, selfqual.ErrNotQualified) || rep.Admitted {
			t.Fatalf("ADMITTED a broken configuration: err=%v admitted=%v", err, rep.Admitted)
		}
		t.Logf("refused: %s", rep.Reason)
	}
	t.Run("RefusesDetachedDecisionHook", func(t *testing.T) {
		rep, err := qualify(t, refengine.Options{Detach: []string{"rq_bprm_check"}}, selfqual.Options{})
		refused(t, rep, err)
	})
	t.Run("RefusesAuditThatBlocks", func(t *testing.T) {
		rep, err := qualify(t, refengine.Options{Mutant: refengine.MutantAuditBlocks}, selfqual.Options{})
		refused(t, rep, err)
	})
	t.Run("RefusesFaultThatAllows", func(t *testing.T) {
		rep, err := qualify(t, refengine.Options{Mutant: refengine.MutantFaultAllows}, selfqual.Options{})
		refused(t, rep, err)
	})
	t.Run("RefusesTamperedHelper", func(t *testing.T) {
		rep, err := qualify(t, refengine.Options{}, selfqual.Options{HelperImage: selfqual.TamperedHelperForTest()})
		refused(t, rep, err)
	})
}
