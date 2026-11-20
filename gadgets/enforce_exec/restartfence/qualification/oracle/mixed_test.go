// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	fence "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
)

func TestFixtureModeTranslation(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input uint32
		want  fence.Mode
	}{
		{"audit", 1, fence.Audit}, {"strict", 2, fence.Strict}, {"off", 3, fence.Off},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fixtureMode(tt.input)
			if err != nil || got != tt.want {
				t.Fatalf("mode=%v error=%v want=%v", got, err, tt.want)
			}
		})
	}
	for _, mode := range []uint32{0, 4, ^uint32(0)} {
		if _, err := fixtureMode(mode); err == nil {
			t.Fatalf("accepted unknown fixture mode %d", mode)
		}
	}
}

func TestMixedCommandUsesExactChildIdentity(t *testing.T) {
	f := fixture{pods: []pod{{id: 17, childID: 23, mode: 2}, {id: 17, childID: 29, mode: 1}}}
	got := f.mixedCommand("refence", 1)
	if got.Pod != 17 || got.Child != 29 || got.Identity != 29 || got.Mode != 1 || got.Op != "refence" {
		t.Fatalf("wrong child command: %+v", got)
	}
}

func TestMixedAccountingRequiresExactPhaseDeltas(t *testing.T) {
	for _, phase := range []struct {
		name          string
		want          uint64
		outage, audit bool
	}{
		{"same-owner-unbound", 100, false, false},
		{"inherited-unbound", 200, true, false},
		{"unreconciled-fallback-after-one-move", 200, true, false},
		{"acknowledged-fallback-remains-fenced", 200, false, false},
		{"owner-down-audit", 200, true, true},
		{"owner-down-nested-audit", 200, true, true},
	} {
		t.Run(phase.name, func(t *testing.T) {
			before := fence.Totals{Denied: 412, Audit: 201, Lost: 3, OutageDenied: 251, OutageAudit: 103, OutageLost: 2}
			after := before
			if phase.audit {
				after.Audit += phase.want
				if phase.outage {
					after.OutageAudit += phase.want
				}
			} else {
				after.Denied += phase.want
				if phase.outage {
					after.OutageDenied += phase.want
				}
			}
			check := func(got fence.Totals) error {
				return checkMixedCounterDeltas(before, got, phase.audit, phase.want, phase.outage)
			}
			if err := check(after); err != nil {
				t.Fatal(err)
			}
			// Off, wrong verdict families, lost attribution, excess/missing
			// observations, and regressed counters must never attest this batch.
			if err := check(before); err == nil {
				t.Fatal("accepted no accounting delta")
			}
			for field := 0; field < 6; field++ {
				for _, increment := range []bool{false, true} {
					bad := after
					fields := []*uint64{&bad.Denied, &bad.Audit, &bad.Lost, &bad.OutageDenied, &bad.OutageAudit, &bad.OutageLost}
					if increment {
						*fields[field]++
					} else {
						*fields[field]--
					}
					if err := check(bad); err == nil {
						t.Fatalf("accepted field=%d increment=%v", field, increment)
					}
				}
			}
		})
	}
}
