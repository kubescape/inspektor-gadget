// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package wasm_test

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Only these test-fixture markers are swallowed. In particular, the ten INFO
// writes and the existing pre-Pause read warning retain the normal logger path.
// Nothing collected here is printed until the guest has returned.
type perfDiagnosticLogger struct {
	logger.Logger
	ctx   *gadgetcontext.GadgetContext
	lines []string
}

func (d *perfDiagnosticLogger) Info(args ...any) {
	switch fmt.Sprint(args...) {
	case "perf diagnostic configure":
		d.configure()
	case "perf diagnostic created", "perf diagnostic before-pause":
		d.snapshot(fmt.Sprint(args...))
	default:
		d.Logger.Info(args...)
	}
}

func (d *perfDiagnosticLogger) record(format string, args ...any) {
	d.lines = append(d.lines, fmt.Sprintf(format, args...))
}

func (d *perfDiagnosticLogger) getMap(name string) *ebpf.Map {
	value, _ := d.ctx.GetVar(operators.MapPrefix + name)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		d.record("map %s unavailable", name)
	}
	return m
}

func (d *perfDiagnosticLogger) configure() {
	d.record("scope=1 test TGID=%d; scope=0 other TGIDs (parallel tests share the test TGID)", os.Getpid())
	if m := d.getMap("diag_tgid"); m != nil {
		if err := m.Update(uint32(0), uint32(os.Getpid()), ebpf.UpdateAny); err != nil {
			d.record("configure TGID: %v", err)
		}
	}
	// Enumerate before reader creation, not during the ten-write interval.
	m := d.getMap("events")
	if m == nil {
		return
	}
	info, err := m.Info()
	if err != nil {
		d.record("events info: %v", err)
		return
	}
	mapID, ok := info.ID()
	d.record("reader input events map id=%d idAvailable=%t fd=%d maxEntries=%d", mapID, ok, m.FD(), info.MaxEntries)
	if !ok {
		return
	}
	found := false
	for id := ebpf.ProgramID(0); ; {
		id, err = ebpf.ProgramGetNextID(id)
		if err != nil {
			d.record("program enumeration ended: %v", err)
			break
		}
		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			d.record("open program %d: %v", id, err)
			continue
		}
		pi, err := p.Info()
		p.Close()
		if err != nil {
			d.record("program %d info: %v", id, err)
			continue
		}
		ids, available := pi.MapIDs()
		if available && slices.Contains(ids, mapID) {
			found = true
			d.record("producer program id=%d name=%s mapIDs=%v", id, pi.Name, ids)
		}
	}
	if !found {
		d.record("producer program mapIDs unavailable: no matching program found")
	}
}

type perfDiagCounts struct{ Entered, Unrecorded uint64 }
type perfDiagResult struct {
	Result     int64
	Scope, Pad uint32
}

func (d *perfDiagnosticLogger) snapshot(stage string) {
	d.record("snapshot %s (cumulative, per-CPU; compare created vs before-pause)", stage)
	if m := d.getMap("diag_entries"); m != nil {
		for scope := uint32(0); scope < 2; scope++ {
			var values []perfDiagCounts
			if err := m.Lookup(scope, &values); err != nil {
				d.record("entries scope=%d: %v", scope, err)
				continue
			}
			for cpu, v := range values {
				if v.Entered != 0 || v.Unrecorded != 0 {
					d.record("entries scope=%d cpu=%d entered=%d unrecorded=%d", scope, cpu, v.Entered, v.Unrecorded)
				}
			}
		}
	}
	if m := d.getMap("diag_results"); m != nil {
		it := m.Iterate()
		var key perfDiagResult
		var values []uint64
		for it.Next(&key, &values) {
			for cpu, count := range values {
				if count != 0 {
					d.record("output scope=%d cpu=%d signedReturn=%d count=%d", key.Scope, cpu, key.Result, count)
				}
			}
		}
		if err := it.Err(); err != nil {
			d.record("results iteration: %v", err)
		}
	}
	for _, name := range []string{"possible", "online"} {
		data, err := os.ReadFile("/sys/devices/system/cpu/" + name)
		d.record("CPU %s=%q error=%v", name, strings.TrimSpace(string(data)), err)
	}
}

// Children only collect frozen copies. Only the common parent's cleanup emits,
// using the parent's logger and an explicit child name, never a completed child T.
type perfDiagnosticReports struct {
	mu        sync.Mutex
	snapshots []perfDiagnosticReport
}

type perfDiagnosticReport struct {
	child string
	lines []string
}

func newPerfDiagnosticReports(parent *testing.T, emit func(child, line string)) *perfDiagnosticReports {
	reports := &perfDiagnosticReports{}
	parent.Cleanup(func() {
		reports.mu.Lock()
		snapshots := slices.Clone(reports.snapshots)
		reports.mu.Unlock()
		for _, snapshot := range snapshots {
			for _, line := range snapshot.lines {
				emit(snapshot.child, line)
			}
			emit(snapshot.child, "actual CPU↔perfFD↔arraykey mapping unavailable through public reader/test-context APIs; no dependency introspection or inferred mapping")
		}
	})
	return reports
}

func (r *perfDiagnosticReports) collect(child string, lines []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshots = append(r.snapshots, perfDiagnosticReport{child: child, lines: slices.Clone(lines)})
}

func TestPerfDiagnosticReportingBarrier(t *testing.T) {
	var finished, emitted atomic.Int32
	seen := make(map[string]bool)
	t.Run("parent", func(parent *testing.T) {
		reports := newPerfDiagnosticReports(parent, func(child, line string) {
			if finished.Load() != 2 {
				t.Errorf("report before all children finished: %d", finished.Load())
			}
			if line == "mutated after collection" {
				t.Error("report retained mutable child snapshot")
			}
			seen[child] = true
			emitted.Add(1)
		})
		for _, language := range []string{"go", "rust"} {
			parent.Run(language, func(child *testing.T) {
				child.Parallel()
				childName := child.Name()
				child.Cleanup(func() {
					lines := []string{"frozen snapshot"}
					reports.collect(childName, lines)
					lines[0] = "mutated after collection"
					if emitted.Load() != 0 {
						child.Error("diagnostics emitted during child cleanup")
					}
					finished.Add(1)
				})
			})
		}
	})
	if emitted.Load() != 4 || len(seen) != 2 {
		t.Fatalf("got %d lines for %d child names, want 4 lines for 2", emitted.Load(), len(seen))
	}
}

// No BPF load: verify diagnostic failures remain silent and ordinary INFO
// messages still reach the underlying logger exactly once.
func TestPerfDiagnosticMarkersAreSilent(t *testing.T) {
	sink := &perfDiagnosticSink{}
	d := &perfDiagnosticLogger{Logger: sink, ctx: gadgetcontext.New(t.Context(), "diagnostic-test")}
	for _, marker := range []string{"perf diagnostic configure", "perf diagnostic created", "perf diagnostic before-pause"} {
		d.Info(marker)
	}
	if len(sink.messages) != 0 {
		t.Fatalf("markers reached underlying logger: %v", sink.messages)
	}
	if !strings.Contains(strings.Join(d.lines, "\n"), "map diag_tgid unavailable") {
		t.Fatal("missing configuration failure diagnostic")
	}
	for range 10 {
		d.Info("testing perf array")
	}
	if len(sink.messages) != 10 {
		t.Fatalf("forwarded %d INFO writes, want 10", len(sink.messages))
	}
	for _, message := range sink.messages {
		if message != "testing perf array" {
			t.Fatalf("changed INFO message %q", message)
		}
	}
}

type perfDiagnosticSink struct {
	logger.Logger
	messages []string
}

func (s *perfDiagnosticSink) Info(args ...any) { s.messages = append(s.messages, fmt.Sprint(args...)) }
