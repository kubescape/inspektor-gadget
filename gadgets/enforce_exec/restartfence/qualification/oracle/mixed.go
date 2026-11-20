// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	fence "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
)

func (f *fixture) mixedCommand(op string, i int) command {
	p := f.pods[i]
	return command{Op: op, Pod: p.id, Child: p.childID, Identity: p.childID, Mode: p.mode}
}

func (f *fixture) bindMixed() error {
	p := f.pods[0]
	c := command{Op: "census", Pod: p.id, Path: p.root, Hash: 91, Mode: 2}
	for _, child := range f.pods[:4] {
		c.Members = append(c.Members, memberCommand{Path: child.child, Identity: child.childID, Mode: child.mode})
	}
	if _, err := f.owner.call(c); err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		if err := f.protect(i); err != nil {
			return err
		}
	}
	return nil
}

// Every phase records exact observation bounds and expectations independently of
// classification internals. No Lift occurs until ordinary disposable cleanup.
func (f *fixture) mixedObserve(name string, policies []samplePolicy) error {
	starts := make([]uint64, len(f.pods))
	for i, p := range f.pods {
		starts[i] = p.probe.observed
	}
	if err := f.stable(policies); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	ends := make([]uint64, len(f.pods))
	for i, p := range f.pods {
		ends[i] = p.probe.observed
	}
	return f.event("mixed-phase", map[string]any{"name": name, "starts": starts, "ends": ends, "policies": policies})
}

// There are no probe batches in flight between these authorization calls and
// the boundary record. The host can check every preceding raw observation.
func (f *fixture) mixedOffBoundary(i int) error {
	return f.event("mixed-off-boundary", map[string]uint64{
		"probe": uint64(i), "observed": f.pods[i].probe.observed,
	})
}

func (f *fixture) mixedState() (*fence.PodState, error) {
	r, err := f.owner.call(command{Op: "readpod", Pod: f.pods[0].id})
	if err != nil {
		return nil, err
	}
	if r.Pod == nil {
		return nil, fmt.Errorf("missing pod state")
	}
	return r.Pod, nil
}

// Drive one ordinary probe at a time so pod-wide accounting deltas stay
// attributable to the exact boundary being tested.
// Same-owner-unbound retains a native route, so only 100 allowed targets
// reach the fence. Other Strict batches count both targets in all 100 pairs.
func (f *fixture) mixedAccounting(name string, i int, outage bool, expectedDenied uint64) error {
	return f.mixedAccountingBatch(name, i, fencedStrict, f.owner.inc, expectedDenied, outage)
}

func (f *fixture) mixedAccountingBatch(name string, i int, policy samplePolicy, live, expected uint64, outage bool) error {
	p := f.pods[i]
	beforeStart := monotonicNS()
	before, err := f.counterSnapshot()
	if err != nil {
		return err
	}
	beforeEnd := monotonicNS()
	startIndex := p.probe.observed
	const samples = 100
	if err := p.probe.batch(samples, policy, nil); err != nil {
		return err
	}
	endIndex := p.probe.observed
	afterStart := monotonicNS()
	after, err := f.counterSnapshot()
	if err != nil {
		return err
	}
	afterEnd := monotonicNS()
	old, had := before.PerCgroup[p.id]
	now, has := after.PerCgroup[p.id]
	if !had || !has || before.LiveIncarnation != live || after.LiveIncarnation != live ||
		before.Retired || after.Retired || endIndex-startIndex != 2*samples {
		return fmt.Errorf("%s: missing or discontinuous accounting samples", name)
	}
	if err := checkMixedCounterDeltas(old, now, policy == allowAll, expected, outage); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return f.event("mixed-accounting", map[string]any{
		"name": name, "probe": i, "incarnation": after.LiveIncarnation,
		"before_incarnation": before.LiveIncarnation,
		"before":             old, "after": now,
		"before_snapshot_start_ns": beforeStart, "before_snapshot_end_ns": beforeEnd,
		"after_snapshot_start_ns": afterStart, "after_snapshot_end_ns": afterEnd,
		"start_index": startIndex, "end_index": endIndex,
	})
}

// Isolated batches must increment only the expected verdict family. Lost or
// unrelated deltas cannot stand in for positively classified Audit observations.
func checkMixedCounterDeltas(before, after fence.Totals, audit bool, expected uint64, outage bool) error {
	want := fence.Totals{}
	if audit {
		want.Audit = expected
		if outage {
			want.OutageAudit = expected
		}
	} else {
		want.Denied = expected
		if outage {
			want.OutageDenied = expected
		}
	}
	if after.Denied < before.Denied || after.Audit < before.Audit || after.Lost < before.Lost ||
		after.OutageDenied < before.OutageDenied || after.OutageAudit < before.OutageAudit || after.OutageLost < before.OutageLost {
		return fmt.Errorf("counter regression")
	}
	got := fence.Totals{
		Denied: after.Denied - before.Denied, Audit: after.Audit - before.Audit,
		Lost: after.Lost - before.Lost, OutageDenied: after.OutageDenied - before.OutageDenied,
		OutageAudit: after.OutageAudit - before.OutageAudit, OutageLost: after.OutageLost - before.OutageLost,
	}
	if got != want {
		return fmt.Errorf("counter delta=%+v want=%+v", got, want)
	}
	return nil
}

func (f *fixture) mixedScenario() error {
	live := []samplePolicy{liveStrict, liveStrict, allowAll, allowAll, fencedStrict, allowAll}
	down := []samplePolicy{fencedStrict, fencedStrict, allowAll, allowAll, fencedStrict, allowAll}
	if err := f.mixedObserve("live-mixed", live); err != nil {
		return err
	}
	// Omission must retain known children, including Off; Audit fallback cannot
	// downgrade an existing Strict sibling.
	p := f.pods[0]
	if _, err := f.owner.call(command{Op: "census", Pod: p.id, Path: p.root, Hash: 91, Mode: 2}); err != nil {
		return err
	}
	if _, err := f.owner.call(command{Op: "census", Pod: p.id, Path: p.root, Hash: 91, Mode: 1}); err == nil {
		return fmt.Errorf("audit fallback hid retained Strict child")
	}
	if err := f.mixedObserve("omitted-retained", live); err != nil {
		return err
	}
	if _, err := f.owner.call(f.mixedCommand("refence", 1)); err != nil {
		return err
	}
	if err := f.event("mixed-refenced", 1); err != nil {
		return err
	}
	if err := f.mixedAccounting("same-owner-unbound", 1, false, 100); err != nil {
		return err
	}
	if err := f.transition(f.owner.kill); err != nil {
		return err
	}
	if err := f.expectLive(0); err != nil {
		return err
	}
	if err := f.mixedObserve("owner-down", down); err != nil {
		return err
	}
	for _, batch := range []struct {
		name  string
		probe int
	}{
		{"owner-down-audit", 2}, {"owner-down-nested-audit", 5},
	} {
		if err := f.mixedAccountingBatch(batch.name, batch.probe, allowAll, 0, 200, true); err != nil {
			return err
		}
	}
	if err := f.start(); err != nil {
		return err
	}
	if err := f.mixedAccounting("inherited-unbound", 1, true, 200); err != nil {
		return err
	}
	if err := f.protect(0); err != nil {
		return err
	}
	if err := f.mixedAccounting("unreconciled-fallback-after-one-move", 4, true, 200); err != nil {
		return err
	}
	partial := append([]samplePolicy(nil), down...)
	partial[0] = liveStrict
	if err := f.mixedObserve("partial-child-move", partial); err != nil {
		return err
	}
	for i := 1; i < 3; i++ {
		if err := f.protect(i); err != nil {
			return err
		}
	}
	if _, err := f.owner.call(f.mixedCommand("acknowledge-accounting", 0)); err != nil {
		return err
	}
	if err := f.event("mixed-accounting-acknowledged", 0); err != nil {
		return err
	}
	if err := f.mixedAccounting("acknowledged-fallback-remains-fenced", 4, false, 200); err != nil {
		return err
	}
	if err := f.mixedObserve("recovered-mixed", live); err != nil {
		return err
	}
	// Deactivation and committed withdrawal cannot bypass a bound child.
	if _, err := f.owner.call(f.mixedCommand("deactivate", 0)); err == nil {
		return fmt.Errorf("deactivated managed pod")
	}
	if _, err := f.owner.call(f.mixedCommand("commit-withdrawal", 0)); err == nil {
		return fmt.Errorf("withdrew bound child")
	}
	before, err := f.mixedState()
	if err != nil {
		return err
	}
	if err := f.transition(func() error { _, e := f.owner.call(f.mixedCommand("refence", 0)); return e }); err != nil {
		return err
	}
	stale := f.mixedCommand("protect", 0)
	stale.Revision = before.Revision
	if _, err := f.owner.call(stale); err == nil {
		return fmt.Errorf("stale receipt moved child")
	}
	withdrawal := append([]samplePolicy(nil), live...)
	withdrawal[0] = fencedStrict
	if err := f.mixedObserve("refenced-before-backend-withdraw", withdrawal); err != nil {
		return err
	}
	if err := f.transition(func() error { _, e := f.owner.call(f.mixedCommand("backend-withdraw", 0)); return e }); err != nil {
		return err
	}
	if err := f.mixedObserve("backend-withdrawn-still-fenced", withdrawal); err != nil {
		return err
	}
	if _, err := f.owner.call(f.mixedCommand("commit-withdrawal", 0)); err != nil {
		return err
	}
	if err := f.mixedOffBoundary(0); err != nil {
		return err
	}
	withdrawal[0] = allowAll
	if err := f.mixedObserve("authorized-child-off", withdrawal); err != nil {
		return err
	}
	for i := 1; i < 3; i++ {
		for _, op := range []string{"refence", "backend-withdraw", "commit-withdrawal"} {
			if _, err := f.owner.call(f.mixedCommand(op, i)); err != nil {
				return err
			}
		}
		if i == 1 {
			if err := f.mixedOffBoundary(i); err != nil {
				return err
			}
		}
		withdrawal[i] = allowAll
	}
	if err := f.mixedObserve("all-known-off-unknown-fenced", withdrawal); err != nil {
		return err
	}
	if _, err := f.owner.call(f.mixedCommand("deactivate", 0)); err != nil {
		return err
	}
	if err := f.mixedOffBoundary(4); err != nil {
		return err
	}
	withdrawal[4] = allowAll
	if err := f.mixedObserve("authorized-scope-inactive", withdrawal); err != nil {
		return err
	}
	state, err := f.mixedState()
	if err != nil {
		return err
	}
	if !state.Inactive {
		return fmt.Errorf("inactive scope not attested")
	}
	snapshot, err := f.counterSnapshot()
	if err != nil {
		return err
	}
	if snapshot.Retired || snapshot.LiveIncarnation != f.owner.inc {
		return fmt.Errorf("withdrawal accidentally retired or armed global fence: %+v", snapshot)
	}
	return f.event("mixed-withdrawal-attested", state)
}
