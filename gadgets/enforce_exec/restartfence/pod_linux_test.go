// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package restartfence

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func testPodChild(t *testing.T, id uint64, mode Mode) podChild {
	t.Helper()
	c, err := newPodChild(id, id+100, mode)
	if err != nil {
		t.Fatal(err)
	}
	if mode != Off {
		c.AccountedIncarnation = 3
	}
	return c
}

func TestMixedPodRowABI(t *testing.T) {
	if binary.Size(podRow{}) != 8256 || binary.Size(podChild{}) != 64 || binary.Size(Totals{}) != 48 {
		t.Fatal("Go pod/child/counter size does not match v3 BPF ABI")
	}
	row := podRow{UIDHash: 1, Revision: 2, StrictSections: 3, AuditSections: 4, ChildCount: 5, Flags: 6, FallbackAccountedIncarnation: 7}
	row.Children[0] = podChild{
		CgroupID: 11, Identity: 12, Owner: 13, Generation: 14,
		StrictSections: 15, AuditSections: 16, OffSections: 17, BoundSections: 18, AccountedIncarnation: 19,
	}
	raw, err := binary.Append(nil, binary.LittleEndian, row)
	if err != nil {
		t.Fatal(err)
	}
	for offset, want := range map[int]uint64{0: 1, 8: 2, 32: 7, 112: 19, 64: 11, 72: 12, 80: 13, 88: 14} {
		if got := binary.LittleEndian.Uint64(raw[offset:]); got != want {
			t.Errorf("u64 offset %d = %d, want %d", offset, got, want)
		}
	}
	for offset, want := range map[int]uint32{16: 3, 20: 4, 24: 5, 28: 6, 96: 15, 100: 16, 104: 17, 108: 18} {
		if got := binary.LittleEndian.Uint32(raw[offset:]); got != want {
			t.Errorf("u32 offset %d = %d, want %d", offset, got, want)
		}
	}
}

func TestCensusDoesNotUnbindOrReleaseSiblings(t *testing.T) {
	strict, audit, off := testPodChild(t, 10, Strict), testPodChild(t, 20, Audit), testPodChild(t, 30, Off)
	strict.Owner, strict.Generation, strict.BoundSections = 3, 8, execSection
	row := podRow{UIDHash: 2, Revision: 6, ChildCount: 2, StrictSections: execSection, FallbackAccountedIncarnation: 3}
	row.Children[0], row.Children[1] = strict, audit
	if err := mergeCensus(&row, []podChild{off}, Strict, 4); err != nil {
		t.Fatal(err)
	}
	if err := verifyPodRow(&row); err != nil {
		t.Fatal(err)
	}
	if row.ChildCount != 3 || row.Children[0] != strict || row.Children[1] != audit || row.Children[2] != off {
		t.Fatalf("incomplete census discarded or rebound a sibling: %+v", row.Children[:3])
	}
}

func TestCensusCannotSilentlyReclassifyOrOverflow(t *testing.T) {
	strict := testPodChild(t, 10, Strict)
	row := podRow{UIDHash: 2, Revision: 3, ChildCount: 1, StrictSections: execSection, FallbackAccountedIncarnation: 3}
	row.Children[0] = strict
	for _, variant := range []struct {
		name     string
		added    []podChild
		fallback Mode
	}{
		{"strict to audit", []podChild{testPodChild(t, 10, Audit)}, Strict},
		{"strict to off", []podChild{testPodChild(t, 10, Off)}, Strict},
		{"audit fallback with retained strict", nil, Audit},
		{"unknown fallback", nil, 0},
		{"stale identity", []podChild{{CgroupID: 10, Identity: 999, StrictSections: execSection, AccountedIncarnation: 3}}, Strict},
	} {
		t.Run(variant.name, func(t *testing.T) {
			next := row
			if err := mergeCensus(&next, variant.added, variant.fallback, 4); err == nil || next != row {
				t.Fatalf("unsafe candidate published: %v", err)
			}
		})
	}
	full := make([]podChild, MaxPodMembers)
	for i := range full {
		full[i] = testPodChild(t, uint64(i)+1000, Audit)
	}
	next := row
	if err := mergeCensus(&next, full, Strict, 4); err == nil || next != row {
		t.Fatalf("oversize child census changed last-good row: %v", err)
	}
}

func TestPodRowRejectsCorruptChildAndTombstone(t *testing.T) {
	row := podRow{UIDHash: 1, Revision: 1, StrictSections: execSection, ChildCount: 1, FallbackAccountedIncarnation: 3}
	row.Children[0] = testPodChild(t, 9, Audit)
	for _, corrupt := range []func(*podRow){
		func(r *podRow) { r.Flags = 7 },
		func(r *podRow) { r.Flags = podInactive },
		func(r *podRow) { r.Children[0].OffSections = execSection },
		func(r *podRow) { r.Children[0].BoundSections = execSection },
		func(r *podRow) { r.Children[0].Generation = 1 },
		func(r *podRow) { r.Children[0].Identity = 0 },
	} {
		next := row
		corrupt(&next)
		if err := verifyPodRow(&next); err == nil {
			t.Fatal("accepted malformed snapshot")
		}
	}
	if _, err := row.child(ChildRef{ID: 9, Identity: 100}); !errors.Is(err, ErrStalePod) {
		t.Fatalf("wrong physical child identity accepted: %v", err)
	}
	if err := verifyPodRow(&podRow{UIDHash: 1, Revision: 2, Flags: podInactive}); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveExitedOrphanCounters(t *testing.T) {
	lookupFailure := errors.New("lookup failed")
	deleteFailure := errors.New("delete failed")
	for _, tc := range []struct {
		name                          string
		id                            uint64
		exists                        bool
		lookupErr, deleteErr, wantErr error
		wantReads, wantDeletes        int
	}{
		{name: "infrastructure", id: 0},
		{name: "active or inactive row", id: 42, exists: true, wantErr: ErrStalePod, wantReads: 1},
		{name: "uncertain lookup", id: 42, lookupErr: lookupFailure, wantErr: lookupFailure, wantReads: 1},
		{name: "orphan", id: 42, wantReads: 1, wantDeletes: 1},
		{name: "already absent", id: 42, deleteErr: ebpf.ErrKeyNotExist, wantReads: 1, wantDeletes: 1},
		{name: "delete failure", id: 42, deleteErr: deleteFailure, wantErr: deleteFailure, wantReads: 1, wantDeletes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads, deletes := 0, 0
			err := removeExitedOrphanCounters(tc.id, func(id uint64) (bool, error) {
				reads++
				if id != tc.id {
					t.Fatal("wrong row key")
				}
				return tc.exists, tc.lookupErr
			}, func(id uint64) error {
				deletes++
				if id != tc.id || reads != 1 {
					t.Fatal("wrong key or deletion before authoritative read")
				}
				return tc.deleteErr
			})
			if tc.id == 0 {
				if err == nil {
					t.Fatal("infrastructure accepted")
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error %v, want %v", err, tc.wantErr)
			}
			if reads != tc.wantReads || deletes != tc.wantDeletes {
				t.Fatalf("reads=%d deletes=%d", reads, deletes)
			}
		})
	}
}

func TestRemoveExitedOrphanCountersRechecksEachAttempt(t *testing.T) {
	exists, deletes := false, 0
	lookup := func(uint64) (bool, error) { return exists, nil }
	remove := func(uint64) error { deletes++; return nil }
	if err := removeExitedOrphanCounters(42, lookup, remove); err != nil {
		t.Fatal(err)
	}
	exists = true
	if err := removeExitedOrphanCounters(42, lookup, remove); !errors.Is(err, ErrStalePod) {
		t.Fatalf("new row not preserved: %v", err)
	}
	if deletes != 1 {
		t.Fatal("active telemetry deleted")
	}
}

func TestRemoveExitedOrphanCountersRequiresOpenOwnerHandle(t *testing.T) {
	f := &Fence{}
	if err := f.RemoveExitedOrphanCounters(0); err == nil {
		t.Fatal("zero key accepted")
	}
	if err := f.RemoveExitedOrphanCounters(42); err == nil {
		t.Fatal("closed handle accepted")
	}
}
