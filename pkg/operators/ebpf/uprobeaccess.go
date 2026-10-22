// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpfoperator

import (
	"maps"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/uprobetracer"
)

// This file is the read-only window an embedder (node-agent) needs onto a
// running gadget's uprobe tracers, so it can hand one to
// container-hook.ContainerNotifier.SetExecHoldHooks as the ExecHoldCrediter.
// It creates nothing, closes nothing and re-keys nothing: every lifetime here
// is the one Start/Close already own.
//
// IDENTITY: the handle is the gadget's operators.GadgetContext -- the very key
// this operator already uses for gadgetObjs, and the object the embedder itself
// constructed to run the gadget (gadgetcontext.New(...)). No new identity
// scheme, no name lookup, no global "the uprobe tracer" singleton that would be
// wrong the moment two uprobe gadgets run at once.
//
// WHY NOT gadgetCtx.GetVar("ebpfInstance"): init() does publish the instance
// there, and it is tempting because it needs no new state at all. It is however
// NOT safe from another goroutine: GadgetContext.vars is a plain, unsynchronised
// map, and Start writes into it (operators.MapPrefix+name for every map) while
// the embedder would be reading. That is a genuine data race, not a theoretical
// one. The operator-lock path below has no such problem.
//
// CONCURRENCY: the gadgetObjs entry is published and removed under
// ebpfOp.mu, so these accessors never race with a concurrent Start/Close of this
// or any other gadget. i.uprobeTracers itself is written only in init(), before
// the instance is reachable by anyone, and is never mutated afterwards -- Close
// closes the tracers in place but leaves the map alone -- so reading it here
// needs no additional lock, and the returned snapshot cannot tear.
//
// TEARDOWN WINDOW (deliberate, documented): Close() closes the tracers before
// removing the gadgetObjs entry, so a caller can observe a tracer that is
// already closed. That is safe rather than merely tolerable: every entry point
// on a closed tracer, CreditIfAttached included, takes t.mu, sees t.closed and
// returns an error instead of touching freed state. Reordering Close purely to
// shrink this window would change existing teardown behaviour for no
// correctness gain, so it is left alone.

// UprobeTracersForGadget returns a snapshot of the live uprobe tracers of the
// gadget instance identified by gadgetCtx, keyed by eBPF program name -- the
// same key i.uprobeTracers uses, which is the program name from the gadget
// image (e.g. "uprobe_gotls_write"), NOT the gadget name.
//
// A gotls-style gadget normally has SEVERAL uprobe programs and therefore
// several tracers, one per program: there is no single "the tracer" for a
// gadget, and this returns all of them rather than silently picking one. Which
// one (or ones) to wire as an ExecHoldCrediter is the caller's policy decision.
//
// ok=false means "not available", and is the routine answer, not an error: the
// gadget has not reached the end of Start yet (nothing is attached, so there is
// nothing to credit), or it has already been closed, or gadgetCtx never
// belonged to an ebpf gadget at all. A caller wiring this up at startup is
// expected to poll or retry rather than treat it as a failure. The three cases
// are deliberately not distinguished: they call for the same reaction.
//
// ok=true with an empty map means the gadget IS running but has no uprobe
// programs at all.
//
// The returned map is a copy; mutating it affects nothing. The tracers it
// points at are the live ones, owned by the gadget instance: the caller must
// not Close them.
func UprobeTracersForGadget(gadgetCtx operators.GadgetContext) (map[string]*uprobetracer.Tracer[api.GadgetData], bool) {
	ebpfOp.mu.Lock()
	objs, ok := ebpfOp.gadgetObjs[gadgetCtx]
	ebpfOp.mu.Unlock()

	if !ok || objs.instance == nil {
		return nil, false
	}
	return maps.Clone(objs.instance.uprobeTracers), true
}

// UprobeTracerForGadget returns the live uprobe tracer of a single eBPF program
// of a running gadget instance.
//
// ok=false carries the same "not available, try again later" meaning as
// UprobeTracersForGadget, extended to cover "this gadget is running but has no
// uprobe program by that name" -- a caller that guessed the program name wrong
// gets a clean false, never a nil tracer with ok=true.
func UprobeTracerForGadget(gadgetCtx operators.GadgetContext, progName string) (*uprobetracer.Tracer[api.GadgetData], bool) {
	tracers, ok := UprobeTracersForGadget(gadgetCtx)
	if !ok {
		return nil, false
	}
	tracer, ok := tracers[progName]
	if !ok || tracer == nil {
		return nil, false
	}
	return tracer, true
}
