// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"testing"
)

func TestOwnerAttestationNeverReturnsUnverifiedGeneration(t *testing.T) {
	for _, state := range []string{"not-activated", "closing", "closed", "pending", "canceled", "no-pins"} {
		t.Run(state, func(t *testing.T) {
			publisher, _, _, _ := publicationFixture(t)
			program := slotProgram(t, publisher.slot, 1, "uid")
			if _, err := publisher.Publish(t.Context(), program); err != nil {
				t.Fatal(err)
			}
			o := &Owner{slot: publisher.slot, current: program}
			ctx := t.Context()
			switch state {
			case "not-activated":
				o.current = nil
			case "closing":
				o.closing = true
			case "closed":
				o.closed = true
			case "pending":
				o.pending = program
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err := o.AttestGeneration(ctx)
			if err == nil || got != 0 || o.Generation() != 1 {
				t.Fatalf("unverified generation returned: %d %v", got, err)
			}
			if state == "pending" && !errors.Is(err, ErrGateBusy) {
				t.Fatal(err)
			}
			if state == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}
