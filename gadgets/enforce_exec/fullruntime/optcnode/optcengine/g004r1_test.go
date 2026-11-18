// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package optcengine_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/optcengine"
)

// g004Review1Scenarios: the G004 review 1 conditions with an engine-level
// test (C5, the child-cgroup question). C4 (late bind) is a node-level test
// (optcnode TestG004OptcLateBind).
var g004Review1Scenarios = []scenario{
	{"C5_RefusedReevaluationKillLatches", func(o *oracle) {
		// Review C5: N+1 denies a parked exec; the re-evaluation's SIGKILL
		// is refused (a test knob). Strict: no KILLED flag, the witness
		// latches SIGNAL_FAIL. Audit: reported, never killed.
		if !o.testKnob("kill-fail") {
			return
		}
		if err := o.eng.SetTestFlags(o.cg(), optcengine.TestKillFail); err != nil {
			o.fatalf("%v", err)
		}
		n := o.publish(o.allowList(e1Allow()...))
		var without []string
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
		w, werr := o.eng.Witness()
		if werr != nil {
			o.fatalf("%v", werr)
		}
		if c.Flags&optcengine.CommitReevalDeny == 0 || c.Flags&optcengine.CommitKilled != 0 {
			o.errorf("refused kill: commit flags %#x, want re-evaluation deny without KILLED", c.Flags)
		}
		if o.strict() && (w.SignalFail == 0 || !w.Latched) {
			o.errorf("refused kill: witness %+v, want SIGNAL_FAIL latched", w)
		}
		if !o.strict() && w.SignalFail != 0 {
			o.errorf("audit: witness %+v, want no kill attempted", w)
		}
	}},
	{"R11_UntrackedTaskInChildCgroupIsGoverned", func(o *oracle) {
		// Review open question: an untracked task in a child cgroup of the
		// bound cgroup (systemd-style sub-cgroup) is R11: Strict denies its
		// exec, Audit lets it through.
		o.publish(o.allowList(e1Allow()...))
		child := filepath.Join(o.h.CgroupPath(o.mode), "g004-sub")
		if err := os.Mkdir(child, 0o755); err != nil {
			o.fatalf("%v", err)
		}
		defer os.Remove(child)
		dir, err := os.Open(child)
		if err != nil {
			o.fatalf("%v", err)
		}
		defer dir.Close()
		before, _ := o.eng.Raw(optcengine.CNestedUnknown)
		cmd := exec.Command(o.h.HostPath("allow"))
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
		runErr := cmd.Run()
		after, _ := o.eng.Raw(optcengine.CNestedUnknown)
		denied := errors.Is(runErr, unix.EPERM) || (runErr != nil && errors.Is(errors.Unwrap(runErr), unix.EPERM))
		o.t.Logf("child cgroup exec: %v (nested-unknown %d -> %d)", runErr, before, after)
		if o.strict() && !denied {
			o.errorf("strict: untracked task in a child cgroup: %v, want EPERM (R11)", runErr)
		}
		if !o.strict() && runErr != nil {
			o.errorf("audit: untracked task in a child cgroup: %v, want it to run", runErr)
		}
		if after == before {
			o.errorf("child cgroup: nested-unknown counter %d unchanged, want the ancestor walk to find the binding", after)
		}
	}},
}

func init() {
	g004Scenarios = append(g004Scenarios, g004Review1Scenarios...)
}
