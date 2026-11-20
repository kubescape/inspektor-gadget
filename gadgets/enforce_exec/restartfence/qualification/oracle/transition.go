// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

// transitionObservation keeps the first ordered raw interval ending after the
// published action start. Later intervals cannot overlap an action that this
// interval already starts after. This bounds memory without blocking probes.
// Publication may race one observation and conservatively miss coverage; it
// cannot fabricate coverage, and qualification then fails rather than retries.
type transitionObservation struct {
	start, end uint64
}

func (o *transitionObservation) observe(r observation, actionStart uint64) {
	if o.end == 0 && actionStart != 0 && r.Start != 0 && r.End > r.Start && r.End > actionStart {
		o.start, o.end = r.Start, r.End
	}
}

func (o transitionObservation) covers(start, end uint64) bool {
	return start != 0 && start < end && o.start < end && o.end > start
}
