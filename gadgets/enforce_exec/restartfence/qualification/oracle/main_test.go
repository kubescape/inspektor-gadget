// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	fence "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
)

func TestOutageAttestationRequiresAllVerdicts(t *testing.T) {
	pods := []pod{{id: 10, mode: 2}, {id: 20, mode: 1}}
	before := fence.Snapshot{PerCgroup: map[uint64]fence.Totals{
		10: {Denied: 74, OutageDenied: 37},
		20: {Audit: 130, OutageAudit: 65},
	}}
	strict := fence.Totals{Denied: 274, OutageDenied: 237}
	audit := fence.Totals{Audit: 330, OutageAudit: 265}
	after := fence.Snapshot{PerCgroup: map[uint64]fence.Totals{10: strict, 20: audit}}
	if err := attestOutageCounts(before, after, pods); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(a, b *fence.Snapshot)
	}{
		{"half-counted-strict", func(_, b *fence.Snapshot) {
			b.PerCgroup[10] = fence.Totals{Denied: 174, OutageDenied: 137}
		}},
		{"excess-audit", func(_, b *fence.Snapshot) {
			b.PerCgroup[20] = fence.Totals{Audit: 331, OutageAudit: 266}
		}},
		{"lost-strict", func(_, b *fence.Snapshot) {
			b.PerCgroup[10] = fence.Totals{Denied: 274, OutageDenied: 237, Lost: 1, OutageLost: 1}
		}},
		{"missing-before-row", func(a, _ *fence.Snapshot) { a.PerCgroup = nil }},
		{"missing-after-row", func(_, b *fence.Snapshot) { b.PerCgroup = nil }},
		{"live-before", func(a, _ *fence.Snapshot) { a.LiveIncarnation = 1 }},
		{"live-after", func(_, b *fence.Snapshot) { b.LiveIncarnation = 2 }},
		{"retired", func(_, b *fence.Snapshot) { b.Retired = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseline := before
			observed := fence.Snapshot{PerCgroup: map[uint64]fence.Totals{10: strict, 20: audit}}
			tc.change(&baseline, &observed)
			if err := attestOutageCounts(baseline, observed, pods); err == nil {
				t.Fatal("incorrect evidence attested the outage")
			}
		})
	}
}
