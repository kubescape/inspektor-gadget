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
func (f *fixture) mixedAccounting(name string, i int, outage bool, expectedDenied uint64) error {
	p := f.pods[i]
	before, err := f.counterSnapshot()
	if err != nil {
		return err
	}
	const samples = 100
	if err := p.probe.batch(samples, fencedStrict, nil); err != nil {
		return err
	}
	after, err := f.counterSnapshot()
	if err != nil {
		return err
	}
	old, had := before.PerCgroup[p.id]
	now, has := after.PerCgroup[p.id]
	if !had || !has || before.LiveIncarnation == 0 ||
		before.LiveIncarnation != after.LiveIncarnation ||
		now.Denied < old.Denied || now.OutageDenied < old.OutageDenied {
		return fmt.Errorf("%s: missing or discontinuous accounting samples", name)
	}
	denied, outageDenied := now.Denied-old.Denied, now.OutageDenied-old.OutageDenied
	if err := checkMixedAccounting(denied, outageDenied, expectedDenied, outage); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return f.event("mixed-accounting", map[string]any{
		"name": name, "probe": i, "incarnation": after.LiveIncarnation,
		"before": old, "after": now,
	})
}

// Only same-owner-unbound retains a native route, intercepting 100 denied
// targets before the fence. After owner death, or for the unknown fallback
// child, both targets in all 100 pairs must be counted by the fence.
func checkMixedAccounting(denied, outageDenied, expectedDenied uint64, outage bool) error {
	wantOutage := uint64(0)
	if outage {
		wantOutage = expectedDenied
	}
	if denied != expectedDenied || outageDenied != wantOutage {
		return fmt.Errorf("denied=%d outage=%d wantDenied=%d wantOutage=%d", denied, outageDenied, expectedDenied, wantOutage)
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
