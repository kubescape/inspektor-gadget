// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"math"
	"time"
)

// FailClosedRateClasses mirrors the opaque_real_fail_closed_rates witness
// (ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE in
// bpf/opaque_real_owner_child_candidate.bpf.c), indexed by class: TASK
// quota LIMIT, source refusal, missing target, evaluation WORK refusal,
// deferred storage quarantine, and other constructor failure.
//
// Explicit exclusions (G025). The witness does not count every fail-closed
// outcome of the candidate; these are not in any class:
//   - first-exec qualification faults (terminal_fault from
//     real_owner_birth_qualify, built only under
//     ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC);
//   - pending-receipt quarantine (real_owner_reader_begin_core result & 8,
//     real_owner_reader_quarantine_pending);
//   - real_owner_child_open_parent failure in real_owner_child_finish;
//   - the deferred G019/G020 refusals: cross-generation, interpreter
//     refusal and migration relabel.
//
// A zero rate therefore does not prove that no exec failed closed. A future
// Ready gate must also cover these outcomes before its NotReady verdict can
// be trusted; adding counters for them changes the qualified objects and
// belongs to G019/G020.
const FailClosedRateClasses = 6

// FailClosedRateCounters is the witness map size: the classes plus
// FailClosedRateWorkRetry, the WORK start retry-bound exhaustions
// (SE_PROFILE_WORK_RETRIES). That counter is a subset already counted as a
// source or evaluation refusal (or a refused terminal fallback), so it is
// reported apart and never added to a verdict's Total.
const (
	FailClosedRateWorkRetry = FailClosedRateClasses
	FailClosedRateCounters  = FailClosedRateClasses + 1
)

var failClosedRateClassNames = [FailClosedRateClasses]string{
	"quota-limit", "source-refusal", "missing-target",
	"eval-work-refusal", "storage-refusal", "construct-failure",
}

// Runtime reporting rule (G025, user-approved). A future Ready gate built on
// the witness must evaluate FailClosedRate over two sliding windows:
//   - Degraded when the FailClosedRateDegradedWindow verdict at
//     FailClosedRateDegradedThreshold is Degraded, i.e. on any fail-closed
//     refusal (Strict) or unevaluated child (Audit) within 60 s;
//   - NotReady when the FailClosedRateNotReadyWindow verdict at
//     FailClosedRateNotReadyThreshold is Degraded, i.e. a rate above 0.1%
//     over 5 min;
//   - unknown, never zero, when the witness is missing or unreadable or
//     FailClosedRate returns an error.
const (
	FailClosedRateDegradedWindow    = time.Minute
	FailClosedRateDegradedThreshold = 0.0
	FailClosedRateNotReadyWindow    = 5 * time.Minute
	FailClosedRateNotReadyThreshold = 0.001
)

// FailClosedRateVerdict is the degraded verdict for one sampling window.
type FailClosedRateVerdict struct {
	// Failures is the per-class counter delta over the window.
	Failures [FailClosedRateClasses]uint64
	// Total is the sum of Failures.
	Total uint64
	// Rate is Total per managed attempt (0 when attempts is 0).
	Rate float64
	// Degraded is true when Total is nonzero and Rate exceeds the
	// threshold (a threshold of 0 degrades on any failure).
	Degraded bool
}

// FailClosedRate maps two snapshots of the fail-closed rate witness to a
// degraded verdict. attempts is the number of managed births and execs in
// the window, as counted by the caller. A counter that moved backwards
// (reset or reload), or more failures than attempts, is an error (the
// verdict is unknown), never a zero rate.
//
// This is a pure function: nothing calls it to change Ready, which stays
// unavailable. A future Ready gate must apply the runtime reporting rule
// above, and must never treat a missing or unreadable witness as a zero
// rate.
func FailClosedRate(before, after [FailClosedRateClasses]uint64, attempts uint64, threshold float64) (FailClosedRateVerdict, error) {
	var v FailClosedRateVerdict
	if math.IsNaN(threshold) || threshold < 0 || threshold > 1 {
		return v, fmt.Errorf("fail-closed rate threshold %v outside [0, 1]", threshold)
	}
	for i := range after {
		if after[i] < before[i] {
			return v, fmt.Errorf("fail-closed %s counter moved backwards (%d -> %d)",
				failClosedRateClassNames[i], before[i], after[i])
		}
		v.Failures[i] = after[i] - before[i]
		if v.Total+v.Failures[i] < v.Total {
			return v, fmt.Errorf("fail-closed rate total overflows")
		}
		v.Total += v.Failures[i]
	}
	// Every counted failure refuses one counted attempt; more failures
	// than attempts means the two counts disagree.
	if v.Total > attempts {
		return v, fmt.Errorf("fail-closed total %d exceeds %d attempts", v.Total, attempts)
	}
	if attempts > 0 {
		v.Rate = float64(v.Total) / float64(attempts)
	}
	v.Degraded = v.Total > 0 && v.Rate > threshold
	return v, nil
}
