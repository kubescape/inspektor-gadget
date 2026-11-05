// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
)

// This models only the transport fault boundary. It does not attest candidate
// activation, accepted history, or actual BPF command semantics.
type sharedCommandFaultTransport struct {
	afterRun                  func()
	command                   sharedCommandWire
	receipt                   sharedReceiptWire
	writes, runs, reads       int
	writeErr, runErr, readErr error
	result                    uint32
	refuse                    bool
}

func (f *sharedCommandFaultTransport) writeSharedCommand(c sharedCommandWire) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	f.command = c
	return nil
}

func (f *sharedCommandFaultTransport) runSharedCommand() (uint32, error) {
	f.runs++
	f.receipt = sharedReceiptWire{NodeCookie: f.command.NodeCookie, Sequence: f.command.Sequence, Operation: f.command.Operation, Serial: 19, Value: 1}
	if f.refuse {
		f.receipt.Status = 1
	}
	if f.afterRun != nil {
		f.afterRun()
	}
	return f.result, f.runErr
}

func (f *sharedCommandFaultTransport) readSharedReceipt() (sharedReceiptWire, error) {
	f.reads++
	return f.receipt, f.readErr
}

func TestSharedCandidateTransportLostAcknowledgement(t *testing.T) {
	for _, operation := range []uint32{8, 9, 10, 11, 12, 13} {
		t.Run(fmt.Sprint(operation), func(t *testing.T) {
			c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
			f := &sharedCommandFaultTransport{readErr: errors.New("lost receipt")}
			request := sharedCommandWire{Operation: operation, Binding: 1, Record: 1, Scope: 7, Serial: 18}
			if _, err := c.callCommand(request, f); err == nil {
				t.Fatal("lost receipt accepted")
			}
			if f.runs != 1 || c.pending == nil {
				t.Fatal("unknown execution lost ownership")
			}
			other := request
			other.Serial++
			if _, err := c.callCommand(other, f); err == nil {
				t.Fatal("different command overwrote unresolved receipt")
			}
			if f.writes != 1 || f.runs != 1 {
				t.Fatal("pending command replayed or overwritten")
			}
			f.readErr = nil
			receipt, err := c.callCommand(request, f)
			if err != nil || receipt.Serial != 19 || c.pending != nil {
				t.Fatalf("reconciliation: %+v %v", receipt, err)
			}
			if f.writes != 1 || f.runs != 1 || c.sequence != 1 {
				t.Fatal("reconciliation re-executed non-idempotent command")
			}
		})
	}
}

func TestSharedCandidateTransportRunFailureKeepsReceipt(t *testing.T) {
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
	f := &sharedCommandFaultTransport{runErr: errors.New("run result unavailable")}
	request := sharedCommandWire{Operation: 8, Scope: 7, Serial: 18}
	if _, err := c.callCommand(request, f); err == nil || c.pending == nil {
		t.Fatal("run failure discarded")
	}
	if _, err := c.callCommand(request, f); err != nil {
		t.Fatal(err)
	}
	if f.runs != 1 || f.writes != 1 || c.pending != nil {
		t.Fatal("successful receipt replayed")
	}
}

func TestSharedCandidateTransportRefusalAndIdentity(t *testing.T) {
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
	f := &sharedCommandFaultTransport{readErr: errors.New("read unavailable"), refuse: true, result: 1}
	request := sharedCommandWire{Operation: 11, Scope: 7, Serial: 18}
	if _, err := c.callCommand(request, f); err == nil {
		t.Fatal("missing receipt accepted")
	}
	f.readErr = nil
	saved := f.receipt
	for _, mutate := range []func(*sharedReceiptWire){
		func(r *sharedReceiptWire) { r.Sequence++ }, func(r *sharedReceiptWire) { r.NodeCookie++ },
		func(r *sharedReceiptWire) { r.Operation++ }, func(r *sharedReceiptWire) { r.Reserved = 1 },
		func(r *sharedReceiptWire) { r.Status = 2 },
	} {
		f.receipt = saved
		mutate(&f.receipt)
		if _, err := c.callCommand(request, f); err == nil || c.pending == nil {
			t.Fatal("foreign/malformed receipt resolved ownership")
		}
	}
	f.receipt = saved
	if _, err := c.callCommand(request, f); err == nil || c.pending != nil {
		t.Fatal("known refusal not resolved")
	}
	if f.runs != 1 || f.writes != 1 {
		t.Fatal("refused command repeated")
	}
}

func TestSharedCandidateTransportWriteFailureNeverRan(t *testing.T) {
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
	f := &sharedCommandFaultTransport{writeErr: errors.New("write failed")}
	if _, err := c.callCommand(sharedCommandWire{Operation: 8}, f); err == nil {
		t.Fatal("write failure ignored")
	}
	if c.pending != nil || f.runs != 0 {
		t.Fatal("unexecuted command marked as unknown execution")
	}
}

func TestSharedCandidateTransportContradictionRemainsPending(t *testing.T) {
	for _, result := range []uint32{1, 2} {
		c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
		f := &sharedCommandFaultTransport{result: result}
		request := sharedCommandWire{Operation: 8, Scope: 7, Serial: 18}
		if _, err := c.callCommand(request, f); err == nil || c.pending == nil {
			t.Fatal("contradictory result accepted")
		}
		if _, err := c.callCommand(request, f); err == nil || f.runs != 1 {
			t.Fatal("contradictory result retried or forgotten")
		}
	}
}

func TestSharedCandidateTransportBindingScopeAndSequenceBoundary(t *testing.T) {
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}, sequence: math.MaxUint64 - 2}
	f := &sharedCommandFaultTransport{readErr: errors.New("read failed")}
	request := sharedCommandWire{Operation: sharedBindingOpen, CgroupIdentity: 42}
	if _, err := c.callCommand(request, f); err == nil {
		t.Fatal("missing receipt accepted")
	}
	if f.command.Scope != math.MaxUint64-1 || f.command.Scope != f.command.Sequence || f.command.NodeCookie != 11 || f.command.Nonce != 22 {
		t.Fatal("transport identity not derived from frozen node/sequence")
	}
	f.readErr = nil
	if _, err := c.callCommand(request, f); err != nil {
		t.Fatalf("exhausted sequence prevented reconciliation: %v", err)
	}
	if _, err := c.callCommand(request, f); err == nil || f.runs != 1 {
		t.Fatal("exhausted sequence executed")
	}
}

func TestSharedCandidateCanceledCallRetainsCompletedReceipt(t *testing.T) {
	thread, err := startControlThread(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}, thread: thread}
	t.Cleanup(func() {
		if err := c.close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := &sharedCommandFaultTransport{afterRun: cancel}
	request := sharedCommandWire{Operation: 8, Binding: 1, Record: 1, Scope: 7, Serial: 18}
	receipt, err := c.callWithTransport(ctx, request, f)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not reported: %v", err)
	}
	if receipt.NodeCookie != 11 || receipt.Sequence != 1 || receipt.Operation != request.Operation || receipt.Status != 0 || receipt.Serial != 19 || receipt.Reserved != 0 {
		t.Fatalf("completed receipt lost on canceled joined call: %+v", receipt)
	}
	if c.pending != nil || f.runs != 1 || f.writes != 1 {
		t.Fatal("completed command replayed or left ambiguous")
	}
	// Do not retry on err: the receipt proves this operation completed. A fresh
	// call after pending cleared would be a NEW command, not reconciliation.
}
