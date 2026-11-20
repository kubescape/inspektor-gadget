// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package restartfence

import (
	"testing"
)

func accountingRow(t *testing.T) podRow {
	t.Helper()
	row := podRow{UIDHash: 8}
	if err := mergeCensus(&row, []podChild{testPodChild(t, 10, Strict), testPodChild(t, 20, Audit), testPodChild(t, 30, Off)}, Strict, 3); err != nil {
		t.Fatal(err)
	}
	row.Revision = 1
	if err := verifyPodAccounting(&row, 3); err != nil {
		t.Fatal(err)
	}
	return row
}

func TestAccountingCensusPreservesInheritedEpochs(t *testing.T) {
	row := accountingRow(t)
	if row.FallbackAccountedIncarnation != 3 || row.Children[0].AccountedIncarnation != 3 || row.Children[2].AccountedIncarnation != 0 {
		t.Fatal("initial accounting provenance")
	}
	before := row
	if err := mergeCensus(&row, nil, Strict, 4); err != nil {
		t.Fatal(err)
	}
	if row != before {
		t.Fatal("omission reset old accounting")
	}
	if err := mergeCensus(&row, []podChild{testPodChild(t, 10, Strict), testPodChild(t, 40, Audit)}, Strict, 4); err != nil {
		t.Fatal(err)
	}
	if row.Children[0] != before.Children[0] || row.Children[3].AccountedIncarnation != 3 || row.FallbackAccountedIncarnation != 3 {
		t.Fatal("new child discovered after restart did not preserve inherited fallback provenance")
	}
	if err := verifyPodAccounting(&row, 4); err != nil {
		t.Fatal(err)
	}
	// A newly discovered child remains in outage until explicitly moved/acknowledged.
	if err := acknowledgePodAccounting(&row, 4); err == nil {
		t.Fatal("unsettled newly discovered child allowed pod acknowledgment")
	}
}

func TestAccountingRefenceMoveAndWithdrawal(t *testing.T) {
	row := accountingRow(t)
	first, sibling := &row.Children[0], row.Children[1]
	if err := movePodChild(first, 3, 17); err != nil {
		t.Fatal(err)
	}
	if err := refencePodChild(first); err != nil {
		t.Fatal(err)
	}
	if first.AccountedIncarnation != 3 || first.Owner != 0 || first.Generation != 0 || first.BoundSections != 0 {
		t.Fatal("refence lost provenance or kept native readiness")
	}
	old := *first
	if err := refencePodChild(first); err != nil {
		t.Fatal(err)
	}
	if *first != old {
		t.Fatal("successor refence acknowledged old interval")
	}
	if err := movePodChild(first, 4, 18); err != nil {
		t.Fatal(err)
	}
	if first.AccountedIncarnation != 4 || first.Owner != 4 || row.FallbackAccountedIncarnation != 3 || row.Children[1] != sibling {
		t.Fatal("move did not remain child-specific")
	}
	current := *first
	if err := withdrawPodChild(first); err == nil || *first != current {
		t.Fatal("bound withdrawal accepted")
	}
	if err := refencePodChild(first); err != nil {
		t.Fatal(err)
	}
	if err := withdrawPodChild(first); err != nil {
		t.Fatal(err)
	}
	if first.AccountedIncarnation != 0 || childMode(*first) != Off {
		t.Fatal("Off kept provenance")
	}
	if err := movePodChild(first, 4, 19); err == nil {
		t.Fatal("Off handed over")
	}
	if err := mergeCensus(&row, []podChild{testPodChild(t, 10, Strict)}, Strict, 4); err != nil {
		t.Fatal(err)
	}
	if row.Children[0].AccountedIncarnation != 4 || row.Children[0].BoundSections != 0 {
		t.Fatal("explicit re-entry borrowed handover")
	}
}

func TestAccountingAcknowledgmentRequiresAllManagedChildren(t *testing.T) {
	row := accountingRow(t)
	original := row
	if err := acknowledgePodAccounting(&row, 4); err == nil || row != original {
		t.Fatal("unbound child acknowledged")
	}
	if err := movePodChild(&row.Children[0], 4, 7); err != nil {
		t.Fatal(err)
	}
	partial := row
	if err := acknowledgePodAccounting(&row, 4); err == nil || row != partial {
		t.Fatal("partial recovery acknowledged")
	}
	if err := movePodChild(&row.Children[1], 3, 8); err != nil {
		t.Fatal(err)
	}
	partial = row
	if err := acknowledgePodAccounting(&row, 4); err == nil || row != partial {
		t.Fatal("old owner acknowledged")
	}
	if err := movePodChild(&row.Children[1], 4, 9); err != nil {
		t.Fatal(err)
	}
	settled := row
	if err := acknowledgePodAccounting(&row, 4); err != nil {
		t.Fatal(err)
	}
	settled.FallbackAccountedIncarnation = 4
	if row != settled {
		t.Fatal("accounting acknowledgment changed classification or handoff")
	}
	if err := acknowledgePodAccounting(&row, 4); err != nil || row != settled {
		t.Fatal("non-idempotent acknowledgment")
	}
}

func TestAccountingRejectsMalformedOrFutureProvenance(t *testing.T) {
	good := accountingRow(t)
	for name, mutate := range map[string]func(*podRow){
		"zero fallback":    func(r *podRow) { r.FallbackAccountedIncarnation = 0 },
		"retired fallback": func(r *podRow) { r.FallbackAccountedIncarnation = retired },
		"future fallback":  func(r *podRow) { r.FallbackAccountedIncarnation = 4 },
		"zero child":       func(r *podRow) { r.Children[0].AccountedIncarnation = 0 },
		"retired child":    func(r *podRow) { r.Children[0].AccountedIncarnation = retired },
		"future child":     func(r *podRow) { r.Children[0].AccountedIncarnation = 4 },
		"Off child":        func(r *podRow) { r.Children[2].AccountedIncarnation = 3 },
		"bound epoch mismatch": func(r *podRow) {
			r.Children[0].Owner = 2
			r.Children[0].BoundSections = execSection
			r.Children[0].Generation = 1
		},
		"reserved header": func(r *podRow) { r.Reserved[0] = 1 },
		"reserved child":  func(r *podRow) { r.Children[0].Reserved[0] = 1 },
		"unused child":    func(r *podRow) { r.Children[3].CgroupID = 40 },
	} {
		t.Run(name, func(t *testing.T) {
			row := good
			mutate(&row)
			before := row
			if err := verifyPodAccounting(&row, 3); err == nil {
				t.Fatal("invalid provenance accepted")
			}
			if row != before {
				t.Fatal("invalid provenance normalized")
			}
		})
	}
	inactive := podRow{UIDHash: 1, Revision: 2, Flags: podInactive}
	if err := verifyPodAccounting(&inactive, 0); err != nil {
		t.Fatal(err)
	}
	inactive.FallbackAccountedIncarnation = 3
	if err := verifyPodAccounting(&inactive, 3); err == nil {
		t.Fatal("inactive provenance accepted")
	}
}

func TestAccountingAcknowledgmentRequiresOpenOwner(t *testing.T) {
	f := &Fence{}
	if _, err := f.AcknowledgePodAccounting(PodRef{ID: 1, UIDHash: 1, Revision: 1}); err == nil {
		t.Fatal("closed handle acknowledged")
	}
}

func TestAccountingStoredIdentityAndIssuedEpoch(t *testing.T) {
	row := accountingRow(t)
	for _, tc := range []struct{ id, issued uint64 }{
		{0, 3}, {10, 3}, {99, 0}, {99, 2},
	} {
		if err := verifyStoredPodAccounting(tc.id, &row, tc.issued); err == nil {
			t.Fatalf("accepted identity/issued epoch %+v", tc)
		}
	}
	if err := verifyStoredPodAccounting(99, &row, 3); err != nil {
		t.Fatal(err)
	}
}

func TestAccountingReactivationAndEmptyScopeAcknowledgment(t *testing.T) {
	row := podRow{UIDHash: 8, Revision: 9, Flags: podInactive}
	if err := mergeCensus(&row, nil, Audit, 4); err != nil {
		t.Fatal(err)
	}
	if row.FallbackAccountedIncarnation != 4 || row.Flags != 0 || row.AuditSections != execSection {
		t.Fatal("reactivation provenance")
	}
	before := row
	if err := mergeCensus(&row, nil, Audit, 5); err != nil {
		t.Fatal(err)
	}
	if row != before {
		t.Fatal("empty census implicitly acknowledged recovery")
	}
	// The API's caller must separately establish completeness; this pure helper
	// proves that an explicit acknowledgment changes only telemetry.
	if err := acknowledgePodAccounting(&row, 5); err != nil {
		t.Fatal(err)
	}
	before.FallbackAccountedIncarnation = 5
	if row != before {
		t.Fatal("empty accounting acknowledgment changed classification")
	}
}
