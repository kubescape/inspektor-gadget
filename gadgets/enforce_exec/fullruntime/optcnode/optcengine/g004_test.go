// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package optcengine_test

// G004: the option C engine's conditions from the E1 re-review (R1-R6) and
// the G003 review (E2-2, E2-3, E3-2, E4-4/R12), each with its mutant.

import (
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

var g004Scenarios = []scenario{
	{"E2_EnforcedActorRuleWithUnknownActorIsAnError", func(o *oracle) {
		// Review E2-2: an enforced actor-path rule consulted for a task whose
		// exe facts are UNKNOWN (the adopted root's child) is an evaluation
		// error: Strict denies, Audit (audit-mode policy) reports.
		p := o.actorPolicy("plain")
		p.Mode = o.fpMode()
		o.publish(o.allowList(e1Allow()...), p)
		obs := o.run("fork+exec:curl")
		o.wantOneCurl(obs, "curl from a task whose actor facts are UNKNOWN", true, true)
	}},
	{"Kleene_UnknownActorAndKnownTargetMissIsNoMatch", func(o *oracle) {
		// G004 user decision (Kleene AND): the same enforced actor rule as
		// above, for an exec whose target is a KNOWN miss: the rule is known
		// false, so the exec is decided without an error (allowed), in
		// every mode. A target match stays an error (the scenario above).
		p := o.actorPolicy("plain")
		p.Mode = o.fpMode()
		o.publish(o.allowList(e1Allow()...), p)
		obs := o.run("fork+exec:allow")
		r, _ := o.result(obs, "fork+exec:allow")
		ds := o.details(r.PID, selfqual.EventDecision)
		if r.Code != 0 || !r.Ran || len(ds) != 1 || ds[0].Deny || ds[0].Error != 0 || ds[0].AuditUnknown != 0 {
			o.errorf("unknown actor AND target miss: %+v decisions %+v, want it to run, allowed, no error, no audit-unknown", r, ds)
		}
	}},
	{"FSType_ProductClassesKnown_MemfdUnknownOnTmpfs", func(o *oracle) {
		// G004: the product's per-class fs facts. tmpfs is known for every
		// exec file; memfd is UNKNOWN on tmpfs/hugetlbfs (no marking hook)
		// and known false elsewhere.
		var st unix.Statfs_t
		if err := unix.Statfs(o.h.HostPath("curl"), &st); err != nil {
			o.fatalf("%v", err)
		}
		onTmpfs := st.Type == unix.TMPFS_MAGIC
		for _, c := range []struct {
			class                 string
			wantDeny, wantUnknown bool
		}{
			{"tmpfs", onTmpfs, false},
			{"memfd", onTmpfs, onTmpfs}, // UNKNOWN on tmpfs: an error, so enforced denies
		} {
			p := fullpolicy.Policy{ID: "g004-fs", Revision: "1", Mode: o.fpMode(), Default: fullpolicy.Allow,
				Rules: []fullpolicy.Rule{{Name: "deny-fs", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: o.paths("curl"), FSType: []string{c.class}}}}}
			o.publish(o.allowList(e1Allow()...), p)
			obs := o.run("fork+exec:curl")
			r, _ := o.result(obs, "fork+exec:curl")
			ds := o.details(r.PID, selfqual.EventDecision)
			if len(ds) != 1 {
				o.errorf("fs %s: decisions %+v", c.class, ds)
				continue
			}
			unknown := ds[0].Error != 0 || ds[0].AuditUnknown != 0
			deny := ds[0].Deny && ds[0].Error == 0
			if o.strict() {
				deny = ds[0].Deny
			}
			o.t.Logf("fs %s (curl on tmpfs=%v): deny=%v error=%d audit-unknown=%d", c.class, onTmpfs, ds[0].Deny, ds[0].Error, ds[0].AuditUnknown)
			if unknown != c.wantUnknown || (!c.wantUnknown && deny != c.wantDeny) || (c.wantUnknown && o.strict() && !ds[0].Deny) {
				o.errorf("fs %s on tmpfs=%v: deny=%v error=%d audit-unknown=%d, want deny=%v unknown=%v", c.class, onTmpfs, ds[0].Deny, ds[0].Error, ds[0].AuditUnknown, c.wantDeny, c.wantUnknown)
			}
		}
	}},
	{"E2_ActorFactsSurviveRealPR_SET_MM_EXE_FILE", func(o *oracle) {
		// Review E2-3: setexe unmaps its own image, then points its exe link
		// at allow (PR_SET_MM_EXE_FILE succeeds), then execs curl. The
		// recorded actor stays setexe.
		o.publish(o.allowList(e1Allow("setexe")...), o.actorPolicy("setexe"))
		obs := o.run("self+rerun:plain,fork+exec2:setexe;allow;curl")
		r, _ := o.result(obs, "fork+exec2:setexe;allow;curl")
		if r.Code >= 100 {
			o.errorf("setexe: exit %d (100+errno: prctl failed; 150+errno: open failed)", r.Code)
		}
		o.wantAuditCurl(obs, "curl after PR_SET_MM_EXE_FILE moved the exe link", true)
	}},
	{"E3_RetireBetweenWindowsIsAnEvaluationError", func(o *oracle) {
		// Review E3-2: 40 rules need 3 windows; a test knob makes the
		// generation's blobs vanish after window 1 (a retire between
		// windows). The pass is an evaluation error: the class decides.
		o.publish(o.perRule(manyNames(40)...))
		if !o.testKnob("retire-after-window") {
			return
		}
		if err := o.eng.SetTestFlags(o.cg(), optcengine.TestRetireAfterWindow); err != nil {
			o.fatalf("%v", err)
		}
		obs := o.run("fork+exec:allow")
		r, _ := o.result(obs, "fork+exec:allow")
		ds := o.details(r.PID, selfqual.EventDecision)
		if len(ds) != 1 || ds[0].Error == 0 || !ds[0].Deny || ds[0].Blocked != o.strict() {
			o.errorf("retire between windows: decisions %+v, want an evaluation error (blocked=%v)", ds, o.strict())
		}
		if o.strict() && r.Code != ePERM || !o.strict() && r.Code != 0 {
			o.errorf("retire between windows: %+v", r)
		}
	}},
	{"R1_RowsOnlyForRoleBearingPolicies_AndReclaim", func(o *oracle) {
		// Review R1: (a) a policy that neither writes nor tests roles takes
		// no row; (b) a grant for a new policy reclaims the row of a policy
		// that is not in the frozen generation.
		o.publish(o.allowList(e1Allow()...))
		obs := o.run("fork+exec:allow")
		r, _ := o.result(obs, "fork+exec:allow")
		if c, ok := o.commit(r.PID); ok && (c.KnownMask != 0 || c.Roles != [8]uint64{}) {
			o.errorf("rows for a policy that bears no role: %+v", c)
		}
		// Gen A: 7 role policies (7 rows). Gen B: 7 new role policies, A's
		// gone, plus the allow-list: the root (adopted under A) runs setter,
		// granted a role by all 7 new policies: 1 free row, 6 reclaimed.
		genA := []fullpolicy.Policy{o.allowList(e1Allow()...)}
		for i := 0; i < 7; i++ {
			genA = append(genA, fullpolicy.Policy{ID: fmt.Sprintf("r1-a%d", i), Revision: "1", Mode: o.fpMode(), RootRole: "a0", Default: fullpolicy.Allow,
				Rules: []fullpolicy.Rule{o.setRule("ra", "plain")}})
		}
		o.publish(genA...)
		var b []fullpolicy.Policy
		b = append(b, o.allowList(e1Allow()...))
		for i := 0; i < 7; i++ {
			b = append(b, fullpolicy.Policy{ID: fmt.Sprintf("r1-b%d", i), Revision: "1", Mode: o.fpMode(), RootRole: "b0", Default: fullpolicy.Allow,
				Rules: []fullpolicy.Rule{o.setRule(fmt.Sprintf("granted%d", i), "setter")}})
		}
		obs, err := o.h.RunHeld(o.mode, false, func(uint32) error {
			nn, err := o.eng.PublishPolicies(o.cg(), b)
			if err == nil {
				o.h.SetGeneration(o.mode, nn)
			}
			return err
		}, "fork+exec:sh_hold", "self+exec:setter")
		if err != nil {
			o.fatalf("%v", err)
		}
		var setter optcengine.Detail
		for _, d := range o.eng.Details(obs.Root) {
			if d.Kind == optcengine.EventCommit && d.Path == o.h.Path("setter") {
				setter = d
			}
		}
		granted := 0
		for i, role := range setter.Roles {
			if setter.KnownMask&(1<<i) != 0 && strings.HasPrefix(o.eng.RoleName(role), "granted") {
				granted++
			}
		}
		if granted != 7 {
			o.errorf("setter commit %+v: %d of 7 grants recorded (rows not reclaimed?)", setter, granted)
		}
	}},
	{"R3_InKernelParity_GlobUTF8Container", func(o *oracle) {
		// Review R3: the kernel's decision equals the Go reference for the
		// BPF-only branches: a glob, a multi-byte UTF-8 path, a container
		// compare.
		utf := "\xc3\xbcn\xc3\xaf"
		cases := []struct {
			name   string
			policy fullpolicy.Policy
			file   string
		}{
			{"glob-match", o.globPolicy(o.h.Path("al*w")), "allow"},
			{"glob-miss", o.globPolicy(o.h.Path("de?x")), "deny"},
			{"utf8-exact", o.globPolicy(o.h.Path(utf)), utf},
			{"utf8-glob", o.globPolicy(o.h.Path("\xc3\xbc*")), utf},
			{"container-match", o.containerPolicy("e1-container"), "curl"},
			{"container-miss", o.containerPolicy("other"), "curl"},
		}
		for _, c := range cases {
			o.publish(o.allowList(e1Allow(utf)...), c.policy)
			ref, err := fullpolicy.CompileReference([]fullpolicy.Policy{o.allowList(e1Allow(utf)...), c.policy})
			if err != nil {
				o.fatalf("%s: reference: %v", c.name, err)
			}
			want, werr := ref.Evaluate(fullpolicy.Facts{TargetPath: o.h.Path(c.file), Container: "e1-container"})
			obs := o.run("fork+exec:" + c.file)
			r, _ := o.result(obs, "fork+exec:"+c.file)
			ds := o.details(r.PID, selfqual.EventDecision)
			if len(ds) != 1 {
				o.errorf("%s: %d decisions", c.name, len(ds))
				continue
			}
			wantDeny := werr != nil || want.Action == fullpolicy.Deny
			o.t.Logf("%s: kernel deny=%v error=%d path=%q; reference %+v (%v)", c.name, ds[0].Deny, ds[0].Error, ds[0].Path, want.Action, werr)
			if ds[0].Deny != wantDeny || (werr == nil && ds[0].Error != 0) {
				o.errorf("%s: kernel deny=%v error=%d, reference deny=%v err=%v", c.name, ds[0].Deny, ds[0].Error, wantDeny, werr)
			}
		}
	}},
	{"R5_MountTreeChangeDuringTheWalkIsUnknown", func(o *oracle) {
		// Review R5: a test knob makes the walk's mount-event bracket read a
		// changed tree: the path is UNKNOWN (walk), never the walk's answer.
		if !o.testKnob("bracket-fail") {
			return
		}
		if err := o.eng.SetTestFlags(o.cg(), optcengine.TestBracketFail); err != nil {
			o.fatalf("%v", err)
		}
		obs := o.run("fork+exec:allow")
		r, _ := o.result(obs, "fork+exec:allow")
		ds := o.details(r.PID, selfqual.EventDecision)
		if len(ds) != 1 || !ds[0].Deny || ds[0].PathReason != optcengine.PathWalkUnknown {
			o.errorf("bracket change decisions %+v: want deny, path UNKNOWN (walk)", ds)
		}
	}},
	{"R12_TaskCeiling", func(o *oracle) {
		// R12 / review E4-4: with a ceiling of 32 tracked tasks per binding,
		// forks past it are refused (Strict) or left untracked (Audit, R11
		// reports them); nothing fails to allocate, nothing latches.
		obs := o.run("sleepers:48", "reapall")
		r, _ := o.result(obs, "sleepers:48")
		ceil, _ := o.eng.Raw(optcengine.CCeiling)
		o.t.Logf("ceiling 32: %d of 48 forks succeeded, %d hit the ceiling", r.Code, ceil)
		if o.strict() && (r.Code >= 48 || r.Code < 20) || !o.strict() && r.Code != 48 || ceil == 0 {
			o.errorf("ceiling: %d forks of 48 succeeded, %d ceiling hits", r.Code, ceil)
		}
		if w, err := o.eng.Witness(); err != nil || w.Latched || w.MarkFail != 0 {
			o.errorf("witness at the ceiling: %+v %v", w, err)
		}
		if sf, _ := o.eng.Raw(optcengine.CStorageFail); sf != 0 {
			o.errorf("%d storage failures at the ceiling", sf)
		}
	}},
}

func (o *oracle) globPolicy(pattern string) fullpolicy.Policy {
	return fullpolicy.Policy{ID: "r3-glob", Revision: "1", Mode: o.fpMode(), Default: fullpolicy.Allow,
		Rules: []fullpolicy.Rule{{Name: "deny-glob", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{pattern}}}}}
}

func (o *oracle) containerPolicy(name string) fullpolicy.Policy {
	return fullpolicy.Policy{ID: "r3-container", Revision: "1", Mode: o.fpMode(), Default: fullpolicy.Allow,
		Rules: []fullpolicy.Rule{{Name: "deny-container", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{Container: []string{name}}, Target: fullpolicy.Target{Path: o.paths("curl")}}}}
}

func g004Setup(name string) engineSetup {
	if name == "R12_TaskCeiling" {
		return engineSetup{opts: optcengine.Options{MaxTasks: 32}}
	}
	if name == "C5_RefusedReevaluationKillLatches" {
		return engineSetup{allowLatch: true} // the refused kill latches on purpose
	}
	return engineSetup{}
}

// TestG004 runs the G004 condition scenarios, Strict and Audit.
func TestG004(t *testing.T) {
	requireOracle(t)
	for _, mode := range modes() {
		t.Run(mode.String(), func(t *testing.T) {
			for _, sc := range g004Scenarios {
				t.Run(sc.name, func(t *testing.T) {
					for _, e := range runScenario(t, mode, g004Setup(sc.name), sc) {
						t.Error(e)
					}
				})
			}
			t.Run("R6_InitStartTimeBindsTheAnchor", func(t *testing.T) {
				for _, e := range wrongInitStart(t, mode, optcengine.Options{WrongInitStart: true}) {
					t.Error(e)
				}
			})
		})
	}
}

// wrongInitStart (review R6): the binding names the right tid but the wrong
// start time (a reused tid): no anchor may be captured.
func wrongInitStart(t *testing.T, mode selfqual.Mode, opts optcengine.Options) []string {
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
		if _, err := o.h.RunAsInit(o.mode, "self+exec:allow"); err != nil {
			o.fatalf("%v", err)
		}
		if _, ok, err := o.eng.Anchor(o.cg()); ok || err != nil {
			o.errorf("anchor captured from an init with the wrong start time (err %v)", err)
		}
	}()
	return o.errs
}

// TestG004Mutants: each G004 mutant fails the scenario guarding it.
func TestG004Mutants(t *testing.T) {
	requireOracle(t)
	all := map[string]scenario{}
	for _, sc := range append(append([]scenario{}, e1Scenarios...), g004Scenarios...) {
		all[sc.name] = sc
	}
	S, A := selfqual.ModeStrict, selfqual.ModeAudit
	cases := []mutantCase{
		{optcengine.MutantEvalErrorAllows, S, "E3_RetireBetweenWindowsIsAnEvaluationError", "retire between windows"},
		{optcengine.MutantSeedAllPolicies, S, "R1_RowsOnlyForRoleBearingPolicies_AndReclaim", "rows for a policy that bears no role"},
		{optcengine.MutantSeedAllPolicies, A, "R1_RowsOnlyForRoleBearingPolicies_AndReclaim", "rows for a policy that bears no role"},
		{optcengine.MutantNoBracket, S, "R5_MountTreeChangeDuringTheWalkIsUnknown", "bracket change decisions"},
		{optcengine.MutantNoBracket, A, "R5_MountTreeChangeDuringTheWalkIsUnknown", "bracket change decisions"},
		{optcengine.MutantReevalKillUnchecked, S, "C5_RefusedReevaluationKillLatches", "refused kill"},
		{optcengine.MutantLeafCgroupOnly, S, "R11_UntrackedTaskInChildCgroupIsGoverned", "child cgroup"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("mutant%d/%s/%s", c.mutant, c.mode, c.scenario), func(t *testing.T) {
			sc := all[c.scenario]
			setup := g004Setup(c.scenario)
			setup.opts.Mutant = c.mutant
			if errs := runScenario(t, c.mode, setup, sc); !containsAny(errs, c.want) {
				t.Fatalf("mutant %d: no finding containing %q (findings: %q)", c.mutant, c.want, errs)
			}
		})
	}
	t.Run("mutant33/Strict/R12_TaskCeiling", func(t *testing.T) {
		setup := engineSetup{opts: optcengine.Options{MaxTasks: 32, Mutant: optcengine.MutantNoCeiling}}
		if errs := runScenario(t, S, setup, all["R12_TaskCeiling"]); !containsAny(errs, "ceiling:") {
			t.Fatalf("mutant 33 not caught: %q", errs)
		}
	})
	t.Run("mutant32/R6_InitStartTimeBindsTheAnchor", func(t *testing.T) {
		for _, mode := range []selfqual.Mode{S, A} {
			if errs := wrongInitStart(t, mode, optcengine.Options{WrongInitStart: true, Mutant: optcengine.MutantAnchorTidOnly}); !containsAny(errs, "anchor captured") {
				t.Errorf("%s: mutant 32 not caught: %q", mode, errs)
			}
		}
	})
}

// TestG004TaskMemory (R12, review E4-4): kernel memory per tracked task,
// measured in the memcg the engine's maps are charged to. The test process
// moves into its own cgroup before the engine loads, so task storage is
// charged there (bpf_map_save_memcg / bpf_mem_alloc take the creator's
// memcg); the sleepers run in probe cgroups elsewhere, so their own
// task_structs are not. Per task: (slab growth with N tracked sleepers -
// slab growth with N sleepers in the never-bound cgroup) / N.
func TestG004TaskMemory(t *testing.T) {
	requireOracle(t)
	memcg := enterMemcg(t)
	for _, e := range runScenario(t, selfqual.ModeStrict, engineSetup{}, scenario{"memory", func(o *oracle) {
		const n = 2000
		// Sample while the sleepers live (they sleep 3 s).
		sample := func(w selfqual.Where) int64 {
			before, err := memcgSlab(memcg)
			if err != nil {
				o.fatalf("%v", err)
			}
			var during int64
			w.During = func() error {
				for i := 0; i < 2000; i++ {
					if _, err := os.Stat(o.h.HostPath("m")); err == nil {
						if during, err = memcgSlab(memcg); err != nil {
							return err
						}
						return os.Remove(o.h.HostPath("m"))
					}
					time.Sleep(time.Millisecond)
				}
				return fmt.Errorf("no marker")
			}
			obs, err := o.h.Run(w, fmt.Sprintf("sleepers:%d", n), "touch:m", "reapall")
			if err != nil {
				o.fatalf("%v", err)
			}
			if r, _ := o.result(obs, fmt.Sprintf("sleepers:%d", n)); r.Code != n {
				o.errorf("sleepers: %d made, want %d", r.Code, n)
			}
			return during - before
		}
		untracked := sample(selfqual.Where{Alt: true})
		tracked := sample(selfqual.Where{Mode: selfqual.ModeStrict, Adopt: true})
		per := (tracked - untracked) / n
		o.t.Logf("MEMORY: engine memcg slab: %d tracked sleepers +%d B, %d untracked +%d B; per tracked task: %d bytes (task record value %d B)", n, tracked, n, untracked, per, o.eng.RecordSize())
		if per < int64(o.eng.RecordSize()) || per > 64*1024 {
			o.errorf("implausible per-task memory %d bytes (record %d B)", per, o.eng.RecordSize())
		}
	}}) {
		t.Error(e)
	}
}

// enterMemcg moves the test process into a fresh cgroup with the memory
// controller and moves it back at cleanup.
func enterMemcg(t *testing.T) string {
	t.Helper()
	const root = "/sys/fs/cgroup"
	ctl, err := os.ReadFile(root + "/cgroup.controllers")
	if err != nil || !strings.Contains(string(ctl), "memory") {
		t.Fatalf("no cgroup v2 memory controller (%v): the per-task memory cannot be measured", err)
	}
	if err := os.WriteFile(root+"/cgroup.subtree_control", []byte("+memory"), 0); err != nil {
		t.Fatalf("enable memory controller: %v", err)
	}
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var orig string
	for _, l := range strings.Split(string(self), "\n") {
		if strings.HasPrefix(l, "0::") {
			orig = root + strings.TrimPrefix(l, "0::")
		}
	}
	if orig == "" {
		t.Fatalf("no cgroup v2 entry in %q", self)
	}
	dir := fmt.Sprintf("%s/ee-g004-mem-%d", root, os.Getpid())
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pid := []byte(fmt.Sprint(os.Getpid()))
	if err := os.WriteFile(dir+"/cgroup.procs", pid, 0); err != nil {
		os.Remove(dir)
		t.Fatalf("enter %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(orig+"/cgroup.procs", pid, 0); err != nil {
			t.Errorf("leave %s: %v", dir, err)
			return
		}
		// The engine's maps are freed asynchronously; the cgroup goes
		// once its charges are gone (an offline memcg is not a leak).
		for i := 0; i < 50 && os.Remove(dir) != nil; i++ {
			time.Sleep(100 * time.Millisecond)
		}
	})
	return dir
}

// memcgSlab is the slab bytes charged to the cgroup dir (memory.stat).
func memcgSlab(dir string) (int64, error) {
	b, err := os.ReadFile(dir + "/memory.stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		var v int64
		if n, _ := fmt.Sscanf(line, "slab %d", &v); n == 1 {
			return v, nil
		}
	}
	return 0, fmt.Errorf("no slab line in %s/memory.stat", dir)
}
