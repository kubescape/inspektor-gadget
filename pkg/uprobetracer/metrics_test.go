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

package uprobetracer

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/metrics"
)

// withTestMeterProvider registers a real SDK MeterProvider (backed by a
// ManualReader, so a test can pull collected values on demand instead of
// waiting out an export interval) with the package's metrics.Proxy singleton,
// and unregisters it on cleanup. This is what lets the package-level
// reattachDurationHistogram/attachTimeoutCounter/redundantAttachCounter vars
// -- created once at package init, before any provider exists, exactly like
// pkg/gadget-context/run.go's udCtrRunningGadgets -- actually persist
// observable values for the duration of one test: Proxy.RegisterProvider
// replays every metric's creation against each newly registered provider (see
// pkg/metrics/metrics.go's registeredMetrics), so this needs no changes to
// uprobetracer itself to become observable.
func withTestMeterProvider(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	if err := metrics.RegisterProvider(provider); err != nil {
		t.Fatalf("RegisterProvider: %v", err)
	}
	t.Cleanup(func() { metrics.UnregisterProvider(provider) })
	return reader
}

// collectMetric pulls every currently-collected data point for the named
// instrument from reader.
func collectMetric(t *testing.T, reader *sdkmetric.ManualReader, name string) []metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var found []metricdata.Metrics
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				found = append(found, m)
			}
		}
	}
	return found
}

// counterValue returns the cumulative value of the named int64 counter for
// the given prog_name label, or 0 if no such series has been recorded yet.
func counterValue(t *testing.T, reader *sdkmetric.ManualReader, name, progName string) int64 {
	t.Helper()
	for _, m := range collectMetric(t, reader, name) {
		sum, ok := m.Data.(metricdata.Sum[int64])
		if !ok {
			t.Fatalf("metric %q is not a Sum[int64]: %T", name, m.Data)
		}
		for _, dp := range sum.DataPoints {
			if v, ok := dp.Attributes.Value(attribute.Key("prog_name")); ok && v.AsString() == progName {
				return dp.Value
			}
		}
	}
	return 0
}

// histogramCount returns the Count of the named float64 histogram's data
// point for the given prog_name label, or 0 if no such series has been
// recorded yet.
func histogramCount(t *testing.T, reader *sdkmetric.ManualReader, name, progName string) uint64 {
	t.Helper()
	for _, m := range collectMetric(t, reader, name) {
		hist, ok := m.Data.(metricdata.Histogram[float64])
		if !ok {
			t.Fatalf("metric %q is not a Histogram[float64]: %T", name, m.Data)
		}
		for _, dp := range hist.DataPoints {
			if v, ok := dp.Attributes.Value(attribute.Key("prog_name")); ok && v.AsString() == progName {
				return dp.Count
			}
		}
	}
	return 0
}

// TestReattachDurationHistogramRecordsOncePerCall proves
// ig_uprobetracer_reattach_duration_seconds fires exactly once per
// ReattachContainerExecPid call that actually runs Phase-1 I/O -- even though
// a single such call can open MULTIPLE candidate paths internally (here: the
// settled /proc/<pid>/exe target AND the ld-cache/absolute attachFilePath
// fallback, exactly like TestAttachContainerSettledTriesProcExeFirst). A
// histogram keyed per internal open, rather than per call, would silently
// inflate this signal.
func TestReattachDurationHistogramRecordsOncePerCall(t *testing.T) {
	reader := withTestMeterProvider(t)
	procRoot := withFakeProcRoot(t)
	tr, st := newTestTracer(t)
	const trackedPid = fakePid
	tr.containerPid2Inodes[trackedPid] = nil

	// Two DISTINCT exe targets, one per call: reusing the same target would
	// hit the fast-path cache on the second call (no Phase-1, no observation),
	// which would not exercise "once per call" at all.
	execPidA := fakePid + 1
	fakeExeProc(t, procRoot, execPidA, "/opt/hist-a/bin")
	st.currentInode = 111
	if err := tr.ReattachContainerExecPid(trackedPid, execPidA); err != nil {
		t.Fatalf("ReattachContainerExecPid (1st): %v", err)
	}
	if got := len(st.openedPaths); got != 2 {
		t.Fatalf("openedPaths = %v, want 2 entries (settled exe + attachFilePath), precondition for this test not met", st.openedPaths)
	}
	if got := histogramCount(t, reader, "ig_uprobetracer_reattach_duration_seconds", tr.progName); got != 1 {
		t.Errorf("histogram count = %d after 1 call (which opened 2 paths), want 1 -- must record once per CALL, not once per internal open", got)
	}

	// A second call, for a different binary (new exec, new exe target, new
	// inode), must add exactly one more observation.
	execPidB := fakePid + 2
	fakeExeProc(t, procRoot, execPidB, "/opt/hist-b/bin")
	st.currentInode = 222
	if err := tr.ReattachContainerExecPid(trackedPid, execPidB); err != nil {
		t.Fatalf("ReattachContainerExecPid (2nd): %v", err)
	}
	if got := histogramCount(t, reader, "ig_uprobetracer_reattach_duration_seconds", tr.progName); got != 2 {
		t.Errorf("histogram count = %d after 2 calls, want 2", got)
	}
}

// TestAttachTimeoutCounterFiresOnlyOnRealTimeout proves
// ig_uprobetracer_attach_timeout_total increments for the right reason (the
// attachIOTimeout deadline actually firing, per the existing
// TestReattachContainerPidTimesOutOnStuckOpen regression scenario in
// attachtimeout_test.go) and does NOT increment for an ordinary call that
// completes well inside the deadline.
func TestAttachTimeoutCounterFiresOnlyOnRealTimeout(t *testing.T) {
	reader := withTestMeterProvider(t)
	withShortAttachIOTimeout(t, 30*time.Millisecond)
	tr, st := newTestTracer(t)
	tr.containerPid2Inodes[fakePid] = nil

	release := make(chan struct{}) // never closed: the open is permanently stuck
	tr.openInContainer = stuckOpener(release)

	runWithSafetyNet(t, 5*time.Second, func() {
		if err := tr.ReattachContainerPid(fakePid); err != nil {
			t.Errorf("ReattachContainerPid: %v", err)
		}
	})
	if got := counterValue(t, reader, "ig_uprobetracer_attach_timeout_total", tr.progName); got != 1 {
		t.Errorf("ig_uprobetracer_attach_timeout_total = %d after a genuine timeout, want 1", got)
	}
	close(release)

	// Recovery run, well inside the deadline: must NOT bump the counter again.
	tr.openInContainer = st.open
	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid (recovery): %v", err)
	}
	if got := counterValue(t, reader, "ig_uprobetracer_attach_timeout_total", tr.progName); got != 1 {
		t.Errorf("ig_uprobetracer_attach_timeout_total = %d after a normal recovery call, want unchanged at 1", got)
	}
}

// TestRedundantAttachCounterFiresOnConcurrentRace proves
// ig_uprobetracer_redundant_attach_total fires for the specific, documented
// reason: Phase-1 I/O ran for an exe path that turned out, by the time this
// call reached its own commit, to already be resident in the cache --
// deterministically simulated here as a concurrent racer committing the exact
// same path while this call is still parked inside its own Phase-1 open (a
// controlled stand-in for two concurrent execs of the same not-yet-cached
// binary), rather than relying on actual goroutine-scheduling luck.
func TestRedundantAttachCounterFiresOnConcurrentRace(t *testing.T) {
	reader := withTestMeterProvider(t)
	procRoot := withFakeProcRoot(t)
	tr, st := newTestTracer(t)
	const trackedPid = fakePid
	tr.containerPid2Inodes[trackedPid] = nil

	execPid := fakePid + 1
	target := "/opt/race/bin"
	fakeExeProc(t, procRoot, execPid, target)
	st.currentInode = 4242

	var openCount int32
	calledOnce := make(chan struct{})
	release := make(chan struct{})
	tr.openInContainer = func(ctx context.Context, pid uint32, filePath string) (*os.File, error) {
		if atomic.AddInt32(&openCount, 1) == 1 {
			close(calledOnce)
			<-release // park: Phase-1 is now provably in flight
		}
		return st.open(ctx, pid, filePath)
	}

	done := make(chan error, 1)
	go func() { done <- tr.ReattachContainerExecPid(trackedPid, execPid) }()
	<-calledOnce

	// Simulate a concurrent racer that committed this exact exe path for this
	// container while the call above is still doing its own Phase-1 I/O.
	tr.mu.Lock()
	cache := tr.containerPid2ExeTargets[trackedPid]
	if cache == nil {
		cache = newExeLRUCache(exeLRUCap)
		tr.containerPid2ExeTargets[trackedPid] = cache
	}
	cache.add(target)
	tr.mu.Unlock()

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("ReattachContainerExecPid: %v", err)
	}

	if got := counterValue(t, reader, "ig_uprobetracer_redundant_attach_total", tr.progName); got != 1 {
		t.Errorf("ig_uprobetracer_redundant_attach_total = %d after the simulated race, want 1", got)
	}

	// An ordinary, non-racing miss (a brand new binary) must NOT bump it.
	otherExecPid := fakePid + 2
	fakeExeProc(t, procRoot, otherExecPid, "/opt/normal/bin")
	st.currentInode = 5252
	if err := tr.ReattachContainerExecPid(trackedPid, otherExecPid); err != nil {
		t.Fatalf("ReattachContainerExecPid (normal miss): %v", err)
	}
	if got := counterValue(t, reader, "ig_uprobetracer_redundant_attach_total", tr.progName); got != 1 {
		t.Errorf("ig_uprobetracer_redundant_attach_total = %d after an ordinary (non-racing) miss, want unchanged at 1", got)
	}
}
