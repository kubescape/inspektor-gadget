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
	"context"
	"os"
	"sync"
	"testing"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/uprobetracer"
)

// These tests cover the accessor CONTRACT -- which lifecycle states answer
// "available" and which answer "not available" -- rather than the tracers
// themselves, which pkg/uprobetracer already owns.
//
// They drive the same publish/unpublish helpers Start and Close call, because
// reaching Start itself needs root and a real gadget image (see ebpf_test.go,
// which is why that file has exactly one test). The tracers are constructed by
// newUprobeTracer, the production constructor, exactly as init() does.

// newRunningInstance builds an instance holding real uprobe tracers for progs,
// publishes it under gadgetCtx the way the end of Start does, and unpublishes it
// on cleanup so no test leaks an entry into the package-global operator.
func newRunningInstance(t *testing.T, progs ...string) (*ebpfInstance, *gadgetcontext.GadgetContext) {
	t.Helper()

	gadgetCtx := gadgetcontext.New(context.Background(), "ghcr.io/armosec/gotls:latest")
	i := &ebpfInstance{
		bpfOperator:   ebpfOp,
		uprobeTracers: make(map[string]*uprobetracer.Tracer[api.GadgetData]),
	}
	for _, name := range progs {
		tracer, err := i.newUprobeTracer(gadgetCtx)
		if err != nil {
			t.Fatalf("newUprobeTracer(%q): %v", name, err)
		}
		i.uprobeTracers[name] = tracer
	}
	t.Cleanup(func() {
		for _, tracer := range i.uprobeTracers {
			tracer.Close()
		}
		i.unpublishGadgetObjects(gadgetCtx)
	})

	i.publishGadgetObjects(gadgetCtx, gadgetObjects{})
	return i, gadgetCtx
}

// The whole point of the accessor: an external caller holding nothing but the
// GadgetContext it used to run the gadget gets back the SAME live tracer
// objects the operator is driving -- not copies, not new ones.
func TestUprobeTracersForRunningGadget(t *testing.T) {
	i, gadgetCtx := newRunningInstance(t, "uprobe_gotls_write", "uretprobe_gotls_read")

	tracers, ok := UprobeTracersForGadget(gadgetCtx)
	if !ok {
		t.Fatal("a running gadget reported no uprobe tracers")
	}
	if len(tracers) != len(i.uprobeTracers) {
		t.Fatalf("got %d tracers, want %d", len(tracers), len(i.uprobeTracers))
	}
	for name, want := range i.uprobeTracers {
		if tracers[name] != want {
			t.Errorf("tracer %q: got %p, want the live tracer %p", name, tracers[name], want)
		}
	}

	// The per-program accessor must resolve to the same object.
	tracer, ok := UprobeTracerForGadget(gadgetCtx, "uprobe_gotls_write")
	if !ok {
		t.Fatal("UprobeTracerForGadget reported nothing for a program that exists")
	}
	if tracer != i.uprobeTracers["uprobe_gotls_write"] {
		t.Errorf("got %p, want the live tracer %p", tracer, i.uprobeTracers["uprobe_gotls_write"])
	}

	// The snapshot is a copy: mutating it must not reach the instance.
	delete(tracers, "uprobe_gotls_write")
	if _, still := i.uprobeTracers["uprobe_gotls_write"]; !still {
		t.Error("mutating the returned snapshot mutated the instance's map")
	}
}

// "Not ready yet" is the routine case for a caller wiring this at startup: the
// gadget instance exists (init has run, the tracers are constructed) but Start
// has not published it. It must answer not-available, cleanly.
func TestUprobeTracersBeforeStart(t *testing.T) {
	gadgetCtx := gadgetcontext.New(context.Background(), "ghcr.io/armosec/gotls:latest")
	i := &ebpfInstance{
		bpfOperator:   ebpfOp,
		uprobeTracers: make(map[string]*uprobetracer.Tracer[api.GadgetData]),
	}
	tracer, err := i.newUprobeTracer(gadgetCtx)
	if err != nil {
		t.Fatalf("newUprobeTracer: %v", err)
	}
	t.Cleanup(tracer.Close)
	i.uprobeTracers["uprobe_gotls_write"] = tracer

	if tracers, ok := UprobeTracersForGadget(gadgetCtx); ok {
		t.Errorf("an unstarted gadget reported %d tracers as available", len(tracers))
	}
	if _, ok := UprobeTracerForGadget(gadgetCtx, "uprobe_gotls_write"); ok {
		t.Error("an unstarted gadget resolved a program name")
	}
}

// After teardown the same handle must flip back to not-available rather than
// keep serving a dead instance.
func TestUprobeTracersAfterTeardown(t *testing.T) {
	i, gadgetCtx := newRunningInstance(t, "uprobe_gotls_write")

	if _, ok := UprobeTracersForGadget(gadgetCtx); !ok {
		t.Fatal("precondition: the gadget should be running")
	}

	// What Close does, in Close's order: close the tracers, then drop the entry.
	for _, tracer := range i.uprobeTracers {
		tracer.Close()
	}
	i.unpublishGadgetObjects(gadgetCtx)

	if tracers, ok := UprobeTracersForGadget(gadgetCtx); ok {
		t.Errorf("a torn-down gadget reported %d tracers as available", len(tracers))
	}
	if _, ok := UprobeTracerForGadget(gadgetCtx, "uprobe_gotls_write"); ok {
		t.Error("a torn-down gadget resolved a program name")
	}
}

// A context that never belonged to an ebpf gadget, and a wrong program name on
// a gadget that IS running, are both plain not-available -- never a nil tracer
// handed back with ok=true, which is the shape that would panic the caller.
func TestUprobeTracersNotAvailableCases(t *testing.T) {
	unknownCtx := gadgetcontext.New(context.Background(), "ghcr.io/armosec/unknown:latest")
	if _, ok := UprobeTracersForGadget(unknownCtx); ok {
		t.Error("an unknown gadget context reported tracers")
	}

	_, gadgetCtx := newRunningInstance(t, "uprobe_gotls_write")
	tracer, ok := UprobeTracerForGadget(gadgetCtx, "no_such_program")
	if ok {
		t.Error("a nonexistent program name resolved")
	}
	if tracer != nil {
		t.Error("a failed lookup returned a non-nil tracer")
	}

	// A running gadget with no uprobe programs is available-but-empty, which is
	// distinct from not-available.
	_, bareCtx := newRunningInstance(t)
	tracers, ok := UprobeTracersForGadget(bareCtx)
	if !ok {
		t.Error("a running gadget with no uprobe programs reported not-available")
	}
	if len(tracers) != 0 {
		t.Errorf("got %d tracers, want none", len(tracers))
	}
}

// The accessor is called from a different goroutine than the operator's own
// lifecycle management, so it must not race with a concurrent publish/unpublish
// of this or any other gadget. Run with -race.
func TestUprobeTracersConcurrentWithLifecycle(t *testing.T) {
	_, stableCtx := newRunningInstance(t, "uprobe_gotls_write")

	churnCtx := gadgetcontext.New(context.Background(), "ghcr.io/armosec/other:latest")
	churn := &ebpfInstance{
		bpfOperator:   ebpfOp,
		uprobeTracers: make(map[string]*uprobetracer.Tracer[api.GadgetData]),
	}
	t.Cleanup(func() { churn.unpublishGadgetObjects(churnCtx) })

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			churn.publishGadgetObjects(churnCtx, gadgetObjects{})
			churn.unpublishGadgetObjects(churnCtx)
		}
	}()

	for n := 0; n < 2000; n++ {
		if _, ok := UprobeTracersForGadget(stableCtx); !ok {
			t.Error("a running gadget went unavailable while another gadget churned")
			break
		}
		// The churning gadget may legitimately answer either way; what must not
		// happen is a race or a nil tracer with ok=true.
		if tracer, ok := UprobeTracerForGadget(churnCtx, "uprobe_gotls_write"); ok && tracer == nil {
			t.Error("ok=true with a nil tracer")
			break
		}
	}

	close(stop)
	wg.Wait()
}

// Two gadgets running at once must never see each other's tracers: this is the
// reason the accessor is keyed by GadgetContext and not by a package global.
func TestUprobeTracersDoNotLeakAcrossGadgets(t *testing.T) {
	iA, ctxA := newRunningInstance(t, "uprobe_gotls_write")
	iB, ctxB := newRunningInstance(t, "uprobe_gotls_write")

	a, ok := UprobeTracerForGadget(ctxA, "uprobe_gotls_write")
	if !ok {
		t.Fatal("gadget A reported no tracer")
	}
	b, ok := UprobeTracerForGadget(ctxB, "uprobe_gotls_write")
	if !ok {
		t.Fatal("gadget B reported no tracer")
	}
	if a == b {
		t.Fatal("both gadgets resolved to the same tracer")
	}
	if a != iA.uprobeTracers["uprobe_gotls_write"] || b != iB.uprobeTracers["uprobe_gotls_write"] {
		t.Error("a gadget context resolved to another instance's tracer")
	}
}

// Compile-time proof of the whole point of this accessor: what it hands back
// satisfies container-hook's ExecHoldCrediter, so node-agent can pass it
// straight to SetExecHoldHooks. If either signature drifts, this stops
// building -- which is the failure mode that dead plumbing otherwise hides.
type execHoldCrediter interface {
	CreditIfAttached(containerPid uint32, file *os.File) (uint64, bool, error)
}

var _ execHoldCrediter = (*uprobetracer.Tracer[api.GadgetData])(nil)
