// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package wasm_test

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Only these test-fixture markers are swallowed. In particular, the ten INFO
// writes and the existing pre-Pause read warning retain the normal logger path.
// Nothing collected here is printed until the guest has returned.
type perfDiagnosticLogger struct {
	logger.Logger
	ctx         *gadgetcontext.GadgetContext
	lines       []string
	producerIDs []ebpf.ProgramID
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
		if err := p.Close(); err != nil {
			d.record("close program %d: %v", id, err)
		}
		if err != nil {
			d.record("program %d info: %v", id, err)
			continue
		}
		ids, available := pi.MapIDs()
		if available && slices.Contains(ids, mapID) {
			found = true
			d.producerIDs = append(d.producerIDs, id)
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
	// Counters first: metadata reads must not precede the measured snapshot.
	d.snapshotLogger()
	for _, name := range []string{"events", "diag_tgid", "diag_entries", "diag_results"} {
		if m := d.getMap(name); m != nil {
			info, err := m.Info()
			if err != nil {
				d.record("snapshot map %s info unavailable: %v", name, err)
				continue
			}
			id, available := info.ID()
			d.record("snapshot map %s id=%d idAvailable=%t fd=%d maxEntries=%d", name, id, available, m.FD(), info.MaxEntries)
		}
	}
	d.snapshotLinks()
	for _, name := range []string{"possible", "online"} {
		data, err := os.ReadFile("/sys/devices/system/cpu/" + name)
		d.record("CPU %s=%q error=%v", name, strings.TrimSpace(string(data)), err)
	}
}

// Out has no public synchronized getter. This read is restricted to this test
// binary, whose code has no concurrent SetOutput/Out assignments. Setters in
// other packages' _test.go files run in separate binaries. Do not mutate the
// writer or install hooks to inspect it; revisit this assumption if tests add a setter.
func (d *perfDiagnosticLogger) snapshotLogger() {
	d.record("logger embeddedType=%T", d.Logger)
	l, ok := d.Logger.(*logrus.Logger)
	if !ok || l == nil {
		d.record("logrus output unavailable: embedded logger is not *logrus.Logger")
		return
	}
	out := l.Out
	d.record("logrus Out type=%T", out)
	file, ok := out.(*os.File)
	if !ok || file == nil {
		d.record("logrus output file metadata unavailable: Out is not *os.File")
		return
	}
	// Fd() can switch a pollable file to blocking mode and disable deadlines.
	// Control observes the descriptor while keeping the file alive, without that mutation.
	conn, err := file.SyscallConn()
	if err != nil {
		d.record("logrus output file syscall connection unavailable: %v", err)
		return
	}
	if err := conn.Control(func(fd uintptr) {
		target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		d.record("logrus output file fd=%d name=%q target=%q error=%v", fd, file.Name(), target, err)
	}); err != nil {
		d.record("logrus output file descriptor control unavailable: %v", err)
	}
}

func (d *perfDiagnosticLogger) snapshotLinks() {
	if len(d.producerIDs) == 0 {
		d.record("producer links unavailable: no saved producer IDs; enumeration skipped")
		return
	}
	it := &link.Iterator{}
	defer it.Close()
	found := false
	for it.Next() {
		// Take explicitly transfers this query handle; inspectLink closes it before
		// returning, including failed Info calls. Never retain a live attachment ref.
		if d.inspectLink(it.ID, it.Take()) {
			found = true
		}
	}
	if err := it.Err(); err != nil {
		d.record("producer link enumeration unavailable: %v", err)
	}
	if !found {
		d.record("producer links unavailable: no matching enumerable link; legacy perf-event ioctl attachments are not enumerable (not proof of no attachment)")
	}
}

// The narrow interface permits pure lifetime/error tests without loading BPF.
func (d *perfDiagnosticLogger) inspectLink(id link.ID, query interface {
	Info() (*link.Info, error)
	Close() error
}) bool {
	defer func() {
		if err := query.Close(); err != nil {
			d.record("close link query %d: %v", id, err)
		}
	}()
	info, err := query.Info()
	if err != nil {
		d.record("link query %d info unavailable: %v", id, err)
		return false
	}
	if info == nil {
		d.record("link query %d info unavailable: nil info", id)
		return false
	}
	if !slices.Contains(d.producerIDs, info.Program) {
		return false
	}
	d.record("producer link id=%d type=%d program=%d", info.ID, info.Type, info.Program)
	if perf := info.PerfEvent(); perf != nil {
		d.record("producer link id=%d perfEventType=%d", info.ID, perf.Type)
		if tp := perf.Tracepoint(); tp != nil {
			d.record("producer link id=%d tracepoint=%q cookie=%d", info.ID, tp.Tracepoint, tp.Cookie)
		} else {
			d.record("producer link id=%d tracepoint detail unavailable", info.ID)
		}
	} else {
		d.record("producer link id=%d perf-event detail unavailable", info.ID)
	}
	return true
}

func TestPerfDiagnosticLinkQueryReleased(t *testing.T) {
	for _, test := range []struct {
		name  string
		info  *link.Info
		err   error
		match bool
	}{
		{"matching", &link.Info{ID: 9, Type: link.PerfEventType, Program: 42}, nil, true},
		{"other", &link.Info{Program: 43}, nil, false},
		{"failed", nil, errors.New("query failed"), false},
		{"nil", nil, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := &perfDiagnosticLogger{producerIDs: []ebpf.ProgramID{42}}
			query := &perfDiagnosticLinkQuery{info: test.info, err: test.err}
			if got := d.inspectLink(9, query); got != test.match {
				t.Fatalf("match=%t, want %t", got, test.match)
			}
			if query.closed != 1 {
				t.Fatalf("query closed %d times before return, want 1", query.closed)
			}
			lines := strings.Join(d.lines, "\n")
			if !strings.Contains(lines, "close link query 9: close failed") {
				t.Fatal("close error not captured")
			}
			if test.match && !strings.Contains(lines, fmt.Sprintf("producer link id=9 type=%d program=42", link.PerfEventType)) {
				t.Fatalf("missing link identity: %s", lines)
			}
		})
	}
}

type perfDiagnosticLinkQuery struct {
	info   *link.Info
	err    error
	closed int
}

func (q *perfDiagnosticLinkQuery) Info() (*link.Info, error) { return q.info, q.err }
func (q *perfDiagnosticLinkQuery) Close() error              { q.closed++; return errors.New("close failed") }

func TestPerfDiagnosticLoggerMetadata(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "logger")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	l := logrus.New()
	l.SetOutput(file) // Local logger configured before the snapshot; never global.
	d := &perfDiagnosticLogger{Logger: l}
	d.snapshotLogger()
	lines := strings.Join(d.lines, "\n")
	for _, want := range []string{"logger embeddedType=*logrus.Logger", "logrus Out type=*os.File", fmt.Sprintf("name=%q", file.Name()), fmt.Sprintf("target=%q", file.Name())} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q in %s", want, lines)
		}
	}
	if stat, err := file.Stat(); err != nil || stat.Size() != 0 {
		t.Fatalf("metadata inspection wrote to/closed logger output: stat=%v error=%v", stat, err)
	}
}

func TestPerfDiagnosticLoggerPreservesNonblockingPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	flags := func() int {
		t.Helper()
		conn, err := reader.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var value int
		var flagErr error
		if err := conn.Control(func(fd uintptr) { value, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil {
			t.Fatal(err)
		}
		if flagErr != nil {
			t.Fatal(flagErr)
		}
		return value
	}
	before := flags()
	if before&unix.O_NONBLOCK == 0 {
		t.Fatal("test pipe must start nonblocking")
	}
	// A past deadline avoids sleeps and verifies existing deadline behavior, not
	// just the ability to install a new deadline after inspection.
	if err := reader.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := reader.Read(buf[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("baseline deadline: %v", err)
	}
	l := logrus.New()
	l.SetOutput(reader)
	d := &perfDiagnosticLogger{Logger: l}
	d.snapshotLogger()
	if after := flags(); after != before {
		t.Fatalf("pipe flags changed: before=%#x after=%#x", before, after)
	}
	if _, err := reader.Read(buf[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("existing deadline changed: %v", err)
	}
	if err := reader.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing deadline: %v", err)
	}
	lines := strings.Join(d.lines, "\n")
	if !strings.Contains(lines, "logrus output file fd=") || !strings.Contains(lines, `target="pipe:[`) {
		t.Fatalf("missing pipe descriptor metadata: %s", lines)
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
