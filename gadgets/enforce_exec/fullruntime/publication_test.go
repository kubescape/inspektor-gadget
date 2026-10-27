// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type fakePublicationControl struct {
	slot   *ProgramSlot
	phase  ControlPhase
	health ControlHealth
	calls  []uint32
	fail   uint32
	after  bool
	fault  uint64
	hook   func(ControlCommand)
}

func (c *fakePublicationControl) Phase() (ControlPhase, error)           { return c.phase, nil }
func (c *fakePublicationControl) Health() (ControlHealth, error)         { return c.health, nil }
func (c *fakePublicationControl) GenerationFault(uint64) (uint64, error) { return c.fault, nil }
func (c *fakePublicationControl) Call(ctx context.Context, cmd ControlCommand) (ControlHealth, error) {
	if err := ctx.Err(); err != nil {
		return c.health, err
	}
	c.calls = append(c.calls, cmd.Operation)
	if c.hook != nil {
		c.hook(cmd)
	}
	if c.fail == cmd.Operation && !c.after {
		return c.health, errSlotFailure
	}
	closed, count, err := c.slot.gate.State()
	if err != nil {
		return c.health, err
	}
	if cmd.Operation != OwnerRootCheck && (!closed || count != 0) {
		return c.health, fmt.Errorf("command outside drained gate")
	}
	switch cmd.Operation {
	case OwnerRootCheck:
		c.health.RootMatch = 1
	case OwnerBootstrapA:
		if c.phase.State != OwnerIdle && c.phase.State != OwnerStaging {
			return c.health, errors.New("bad A")
		}
		c.phase = ControlPhase{State: OwnerStaging, CandidateGeneration: cmd.Generation, NewUIDMask: cmd.NewUIDMask}
	case OwnerBootstrapB:
		if c.phase.State != OwnerStaging {
			return c.health, errors.New("bad B")
		}
		c.phase.State = OwnerValidated
		c.health.ReadyGeneration = cmd.Generation
	case OwnerValidate:
		if c.phase.State != OwnerValidated && c.phase.State != OwnerCommitted {
			return c.health, errors.New("bad validate")
		}
		if c.phase.State == OwnerCommitted && cmd.NewUIDMask != 0 {
			return c.health, errors.New("postcommit reroot")
		}
		c.health.ReadyGeneration = cmd.Generation
	case OwnerPublicationBegin:
		if c.phase.State != OwnerValidated {
			return c.health, errors.New("bad publication")
		}
		c.phase.State = OwnerPublishing
	case OwnerPublicationCommitted:
		if c.phase.State != OwnerPublishing || c.slot.Generation() != cmd.Generation {
			return c.health, errors.New("bad commit")
		}
		c.phase.State = OwnerCommitted
		c.phase.CommittedGeneration = cmd.Generation
		c.health.ActiveGeneration = cmd.Generation
	case OwnerPhaseClear:
		if c.phase.State != OwnerCommitted {
			return c.health, errors.New("bad clear")
		}
		c.phase.State = OwnerIdle
		c.phase.CandidateGeneration = 0
	case OwnerBootstrapAbort:
		if c.slot.Generation() == cmd.Generation {
			return c.health, errors.New("rollback after commit")
		}
		c.phase.State = OwnerIdle
		c.phase.CandidateGeneration = 0
		c.health.ReadyGeneration = c.health.ActiveGeneration
	case OwnerRetire:
		c.health.Retired = 1
		c.phase.State = OwnerStopped
	default:
		return c.health, fmt.Errorf("unexpected op %d", cmd.Operation)
	}
	if c.fail == cmd.Operation {
		return c.health, errSlotFailure
	}
	return c.health, nil
}

func publicationFixture(t *testing.T) (*Publisher, *fakePublicationControl, *fakeSlotWriter, *fakeSlotWriter) {
	t.Helper()
	slot, outer, epochs, _ := slotFixture(t)
	c := &fakePublicationControl{slot: slot, health: ControlHealth{MovementArmed: 1}}
	return &Publisher{slot: slot, control: c, verify: func(context.Context) error { return nil }}, c, outer, epochs
}

func TestPublicationSuccessAndRetainedRoles(t *testing.T) {
	p, c, _, _ := publicationFixture(t)
	for _, gen := range []uint64{1, 2} {
		r, err := p.Publish(t.Context(), slotProgram(t, p.slot, gen, "uid"))
		if err != nil || !r.Committed || !r.Admitting || r.Generation != gen {
			t.Fatalf("%+v %v", r, err)
		}
		if c.phase.State != OwnerIdle || p.pending != nil || p.slot.Epochs()["uid"] != 1 {
			t.Fatal("unfinished or rerooted")
		}
	}
}

func TestPublicationPrecommitRefusalRetainsLastGood(t *testing.T) {
	for _, op := range []uint32{OwnerRootCheck, OwnerBootstrapA, OwnerBootstrapB, OwnerValidate, OwnerPublicationBegin} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/after=%t", op, after), func(t *testing.T) {
				p, c, outer, epochs := publicationFixture(t)
				if _, err := p.Publish(t.Context(), slotProgram(t, p.slot, 1, "old")); err != nil {
					t.Fatal(err)
				}
				old := outer.rows[uint32(0)]
				c.fail = op
				c.after = after
				r, err := p.Publish(t.Context(), slotProgram(t, p.slot, 2, "new"))
				if err == nil || r.Committed || !r.Admitting || r.Generation != 1 {
					t.Fatalf("%+v %v", r, err)
				}
				if outer.rows[uint32(0)] != old || len(epochs.rows) != 1 || p.pending != nil || c.phase.State != OwnerIdle {
					t.Fatal("last good changed")
				}
			})
		}
	}
}

func TestPublicationPostcommitResume(t *testing.T) {
	for _, op := range []uint32{OwnerPublicationCommitted, OwnerValidate, OwnerPhaseClear} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/after=%t", op, after), func(t *testing.T) {
				p, c, _, _ := publicationFixture(t)
				// Fail Validate only in COMMITTED, not the precommit validation.
				c.hook = func(cmd ControlCommand) {
					if cmd.Operation == op && (op != OwnerValidate || c.phase.State == OwnerCommitted) {
						c.fail = op
						c.after = after
					}
				}
				r, err := p.Publish(t.Context(), slotProgram(t, p.slot, 1, "uid"))
				if err == nil || !r.Committed || r.Admitting || r.Generation != 1 || p.pending == nil {
					t.Fatalf("%+v %v", r, err)
				}
				if err = p.Abort(t.Context()); err == nil {
					t.Fatal("postcommit rollback accepted")
				}
				c.hook = nil
				c.fail = 0
				r, err = p.Resume(t.Context())
				if err != nil || !r.Committed || !r.Admitting || p.pending != nil {
					t.Fatalf("resume %+v %v", r, err)
				}
			})
		}
	}
}

func TestPublicationHistoryFailureIsCommittedAndResumable(t *testing.T) {
	p, _, _, epochs := publicationFixture(t)
	epochs.putErr = errSlotFailure
	r, err := p.Publish(t.Context(), slotProgram(t, p.slot, 1, "uid"))
	if err == nil || !r.Committed || r.Admitting || p.pending == nil {
		t.Fatalf("%+v %v", r, err)
	}
	epochs.putErr = nil
	r, err = p.Resume(t.Context())
	if err != nil || !r.Committed || !r.Admitting {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestPublicationAbortFailureRetainsClosedLease(t *testing.T) {
	p, c, _, _ := publicationFixture(t)
	c.hook = func(cmd ControlCommand) {
		if cmd.Operation == OwnerBootstrapB || cmd.Operation == OwnerBootstrapAbort {
			c.fail = cmd.Operation
		}
	}
	r, err := p.Publish(t.Context(), slotProgram(t, p.slot, 1, "uid"))
	if err == nil || r.Committed || r.Admitting || p.pending == nil {
		t.Fatalf("%+v %v", r, err)
	}
	requireState(t, p.slot.gate, true, 0)
	c.hook = nil
	c.fail = 0
	if err = p.Abort(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireState(t, p.slot.gate, false, 0)
}

func TestPublicationRetirePendingCommit(t *testing.T) {
	p, c, _, epochs := publicationFixture(t)
	epochs.putErr = errSlotFailure
	if _, err := p.Publish(t.Context(), slotProgram(t, p.slot, 1, "uid")); err == nil {
		t.Fatal("expected failure")
	}
	c.fail = OwnerRetire
	if err := p.Retire(t.Context()); err == nil {
		t.Fatal("expected retire command failure")
	}
	requireState(t, p.slot.gate, true, 0)
	if _, err := p.Resume(t.Context()); !errors.Is(err, ErrGateRetired) {
		t.Fatal(err)
	}
	c.fail = 0
	if err := p.Retire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if c.health.Retired != 1 {
		t.Fatal("token not invalidated")
	}
}

func TestPublicationFaultScopeAndIdentity(t *testing.T) {
	for _, post := range []bool{false, true} {
		t.Run(fmt.Sprint(post), func(t *testing.T) {
			p, c, _, _ := publicationFixture(t)
			if post {
				c.hook = func(cmd ControlCommand) {
					if cmd.Operation == OwnerPublicationCommitted {
						c.fault = 4
					}
				}
			} else {
				c.fault = 4
			}
			r, err := p.Publish(t.Context(), slotProgram(t, p.slot, 1, "uid"))
			if err == nil || r.Committed != post || r.Admitting == post {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
	p, c, _, _ := publicationFixture(t)
	calls := 0
	p.verify = func(context.Context) error {
		calls++
		if calls >= 3 {
			return errors.New("lease changed")
		}
		return nil
	}
	r, err := p.Publish(t.Context(), slotProgram(t, p.slot, 1, "uid"))
	if err == nil || r.Committed || !r.Admitting || c.phase.State != OwnerIdle {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestPublicationActiveSwapRefusalAndCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			p, c, outer, _ := publicationFixture(t)
			if _, err := p.Publish(t.Context(), slotProgram(t, p.slot, 1, "old")); err != nil {
				t.Fatal(err)
			}
			old := outer.rows[uint32(0)]
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if cancelled {
				c.hook = func(cmd ControlCommand) {
					if cmd.Operation == OwnerPublicationBegin {
						cancel()
					}
				}
			} else {
				outer.putErr = errSlotFailure
				outer.failKey = uint32(0)
			}
			r, err := p.Publish(ctx, slotProgram(t, p.slot, 2, "new"))
			if err == nil || r.Committed || !r.Admitting || r.Generation != 1 || p.pending != nil || outer.rows[uint32(0)] != old {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}

func TestPublisherRequiresPreparedFirstStartup(t *testing.T) {
	p, _, _, _ := publicationFixture(t)
	if _, err := NewPublisher(p.slot, &OwnerControl{}, p.verify, nil); err == nil {
		t.Fatal("startup activation gap accepted")
	}
	u, err := p.slot.Begin(t.Context(), slotProgram(t, p.slot, 1, "uid"))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewPublisher(p.slot, &OwnerControl{}, p.verify, u)
	if err != nil || owner.pending == nil {
		t.Fatal(err)
	}
	other, _, _, _ := publicationFixture(t)
	if _, err = NewPublisher(other.slot, &OwnerControl{}, p.verify, u); err == nil {
		t.Fatal("foreign preparation accepted")
	}
	if err = u.Abort(); err != nil {
		t.Fatal(err)
	}
}
