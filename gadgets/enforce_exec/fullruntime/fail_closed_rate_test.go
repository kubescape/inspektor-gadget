// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"math"
	"testing"
	"time"
)

func TestFailClosedRate(t *testing.T) {
	base := [FailClosedRateClasses]uint64{10, 20, 30, 40, 50, 60}
	plus := func(d [FailClosedRateClasses]uint64) [FailClosedRateClasses]uint64 {
		out := base
		for i := range out {
			out[i] += d[i]
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		delta     [FailClosedRateClasses]uint64
		attempts  uint64
		threshold float64
		total     uint64
		rate      float64
		degraded  bool
	}{
		{"clean", [FailClosedRateClasses]uint64{}, 1000, 0, 0, 0, false},
		{"clean without attempts", [FailClosedRateClasses]uint64{}, 0, 0, 0, 0, false},
		{"any failure at zero threshold", [FailClosedRateClasses]uint64{0, 0, 0, 1}, 1000, 0, 1, 0.001, true},
		{"below threshold", [FailClosedRateClasses]uint64{1, 1, 0, 0, 0, 0}, 1000, 0.01, 2, 0.002, false},
		{"at threshold", [FailClosedRateClasses]uint64{5, 5}, 1000, 0.01, 10, 0.01, false},
		{"above threshold", [FailClosedRateClasses]uint64{494, 0, 0, 13, 0, 0}, 1000, 0.01, 507, 0.507, true},
		{"every class counts", [FailClosedRateClasses]uint64{1, 1, 1, 1, 1, 1}, 6, 0.99, 6, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := FailClosedRate(base, plus(tc.delta), tc.attempts, tc.threshold)
			if err != nil {
				t.Fatal(err)
			}
			if v.Failures != tc.delta || v.Total != tc.total || math.Abs(v.Rate-tc.rate) > 1e-12 || v.Degraded != tc.degraded {
				t.Fatalf("verdict %+v, want failures %v total %d rate %v degraded %v", v, tc.delta, tc.total, tc.rate, tc.degraded)
			}
		})
	}
}

// The user-approved reporting rule: any failure in the 60 s window is
// Degraded; NotReady needs more than 0.1% over the 5 min window.
func TestFailClosedRateReportingRule(t *testing.T) {
	if FailClosedRateDegradedWindow != time.Minute || FailClosedRateDegradedThreshold != 0 ||
		FailClosedRateNotReadyWindow != 5*time.Minute || FailClosedRateNotReadyThreshold != 0.001 {
		t.Fatal("fail-closed reporting rule drifted from the approved 60 s / any and 5 min / 0.1%")
	}
	var before [FailClosedRateClasses]uint64
	for _, tc := range []struct {
		failures, attempts uint64
		degraded, notReady bool
	}{
		{0, 120000, false, false},
		{1, 120000, true, false},
		{120, 120000, true, false},
		{121, 120000, true, true},
	} {
		after := [FailClosedRateClasses]uint64{0, tc.failures}
		degraded, err := FailClosedRate(before, after, tc.attempts, FailClosedRateDegradedThreshold)
		if err != nil {
			t.Fatal(err)
		}
		notReady, err := FailClosedRate(before, after, tc.attempts, FailClosedRateNotReadyThreshold)
		if err != nil {
			t.Fatal(err)
		}
		if degraded.Degraded != tc.degraded || notReady.Degraded != tc.notReady {
			t.Fatalf("%d failures / %d attempts: degraded=%v notReady=%v, want %v %v",
				tc.failures, tc.attempts, degraded.Degraded, notReady.Degraded, tc.degraded, tc.notReady)
		}
	}
}

func TestFailClosedRateRefusesInvalidInput(t *testing.T) {
	before := [FailClosedRateClasses]uint64{0, 5}
	if _, err := FailClosedRate(before, [FailClosedRateClasses]uint64{0, 4}, 10, 0); err == nil {
		t.Fatal("a counter moving backwards must be an error, not a zero rate")
	}
	overflow := [FailClosedRateClasses]uint64{math.MaxUint64, 1}
	if _, err := FailClosedRate([FailClosedRateClasses]uint64{}, overflow, 10, 0); err == nil {
		t.Fatal("an overflowing total must be an error")
	}
	// More failures than attempts (including failures without attempts)
	// is unknown, never a rate.
	for _, attempts := range []uint64{0, 4} {
		if _, err := FailClosedRate(before, [FailClosedRateClasses]uint64{2, 8}, attempts, 0); err == nil {
			t.Fatalf("5 failures over %d attempts accepted", attempts)
		}
	}
	if v, err := FailClosedRate(before, [FailClosedRateClasses]uint64{2, 8}, 5, 0); err != nil || v.Total != 5 || v.Rate != 1 {
		t.Fatalf("5 failures over 5 attempts: %+v, %v", v, err)
	}
	for _, threshold := range []float64{-0.1, 1.1, math.NaN()} {
		if _, err := FailClosedRate(before, before, 10, threshold); err == nil {
			t.Fatalf("threshold %v accepted", threshold)
		}
	}
}
