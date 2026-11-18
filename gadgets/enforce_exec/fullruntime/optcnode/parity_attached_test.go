// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package optcnode

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/admission"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/optcengine"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/parity"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/selfqual"
)

// TestG004OptcParity (G004 qualification, verdict parity): the parity
// scenario table through the option C node (StartNode, Bind, Publish), one
// node per scenario with a Strict and an Audit binding, each a command-pipe
// init in its own cgroup. The node is admitted by the shipped exact pins
// (DefaultAdmission, pins.go), which must hold this kernel
// under qualification (its release and BTF sha256, with the product
// object's sha256).
//
// The init is bound before it execs its shell (a runtime binds at its
// exec.fifo point, before the entrypoint exec): option C captures the root
// anchor at the seeded init's first exec after adoption.
//
//	IG_G004_OPTC_PARITY=1
func TestG004OptcParity(t *testing.T) {
	if os.Getenv("IG_G004_OPTC_PARITY") == "" || os.Geteuid() != 0 {
		t.Skip("set IG_G004_OPTC_PARITY=1, as root, on an isolated VM")
	}
	if err := parity.Setup(); err != nil {
		t.Fatal(err)
	}
	host, err := hostNode()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(optcengine.ProductObject())
	pin := admission.Pin{Release: host.Release, BTFSHA256: host.BTFSHA256, ObjectSHA256: hex.EncodeToString(sum[:])}
	t.Logf("PIN release=%s btf=%s object=%s", pin.Release, pin.BTFSHA256, pin.ObjectSHA256)
	// The node is admitted by the shipped pins (pins.go, DefaultAdmission):
	// this kernel and the embedded object must be one of them.
	if !slices.Contains(QualifiedPins, pin) {
		t.Fatalf("this node %+v is not in QualifiedPins", pin)
	}
	root := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ig15-g004-optc-parity-%d", os.Getpid()))
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	for _, sc := range parity.Scenarios() {
		t.Run(sc.Name, func(t *testing.T) { optcParityScenario(t, pin, root, sc) })
	}
}

type parityEvents struct {
	mu sync.Mutex
	ds []optcengine.Detail
}

func (p *parityEvents) add(d optcengine.Detail) {
	p.mu.Lock()
	p.ds = append(p.ds, d)
	p.mu.Unlock()
}

func (p *parityEvents) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ds)
}

func (p *parityEvents) since(from int, cgroup uint64) []optcengine.Detail {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []optcengine.Detail
	for _, d := range p.ds[from:] {
		if d.Cgroup == cgroup {
			out = append(out, d)
		}
	}
	return out
}

func optcParityScenario(t *testing.T, pin admission.Pin, root string, sc parity.Scenario) {
	ev := &parityEvents{}
	ctx := context.Background()
	rt := newFakeRuntime(t)
	n, err := StartNode(ctx, Config{Admission: DefaultAdmission(), OnEvent: ev.add, Runtime: rt.config()})
	if err != nil {
		t.Fatalf("StartNode: %v", err)
	}
	if d := n.Admission(); d.Level != "exact" {
		t.Fatalf("admission %+v, want exact", d)
	}
	// Driven through the contract interfaces (as the product node is).
	var node Enforcer = n
	defer func() {
		if err := node.Ready(nil); err != nil {
			t.Errorf("Ready after the scenario: %v", err)
		}
		if err := node.StopNode(ctx); err != nil {
			t.Errorf("StopNode: %v", err)
		}
	}()
	for _, mode := range parity.Modes {
		name := sc.Name + "-" + string(mode)
		cgroup := filepath.Join(root, strings.ReplaceAll(name, "_", "-"))
		if err := os.MkdirAll(cgroup, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(cgroup) })
		p := startHeldPipeInit(t, rt, cgroup, name)
		session, err := n.Bind(ctx, fullruntime.SharedBindingConfig{CgroupID: p.ino, InitHostPID: uint32(p.cmd.Process.Pid), ContainerID: name})
		if err != nil {
			t.Fatalf("%s: Bind: %v", name, err)
		}
		var s Binding = session
		policies := sc.Policies(mode)
		publish := func(i int) error {
			_, err := s.Publish(ctx, fullruntime.SharedBindingPolicy{Source: &policies[i], Container: parity.Container})
			return err
		}
		verdicts := func(from int) []parity.Verdict {
			// The events are drained asynchronously: wait until none
			// arrive for 300 ms.
			for n, quiet := ev.count(), time.Now(); time.Since(quiet) < 300*time.Millisecond; time.Sleep(20 * time.Millisecond) {
				if m := ev.count(); m != n {
					n, quiet = m, time.Now()
				}
			}
			var vs []parity.Verdict
			for _, d := range ev.since(from, p.ino) {
				var v parity.Verdict
				switch d.Kind {
				case selfqual.EventDecision:
					v = parity.Verdict{Path: d.Path, Deny: d.Deny, Blocked: d.Blocked, Unknown: d.Error != 0 || d.AuditUnknown != 0}
				case selfqual.EventFault:
					v = parity.Verdict{Path: d.Path, Deny: true, Blocked: d.Blocked, Unknown: true}
				default:
					continue
				}
				if parity.Keep(v) {
					vs = append(vs, v)
				}
			}
			return vs
		}
		if err := publish(0); err != nil {
			t.Logf("%s: publish refused: %v", name, err)
			t.Log(parity.Refused("optc", sc.Name, mode))
			_ = s.Remove(ctx, 0)
			continue
		}
		// The init execs its shell under the published policy (the root
		// anchor is captured there).
		from := ev.count()
		code := 0
		if err := p.release(); err != nil {
			t.Logf("%s: init after its exec: %v", name, err)
			code = -1
		}
		t.Log(parity.Line("optc", sc.Name, mode, "init_exec", code, verdicts(from)))
		if code != 0 {
			_ = s.Remove(ctx, 0)
			continue
		}
		if st := s.Inspect(); !st.RootAuthorized {
			t.Fatalf("%s: no root anchor after the init's exec: %+v", name, st)
		}
		for _, step := range sc.Steps {
			if step.Publish > 0 {
				if err := publish(step.Publish); err != nil {
					t.Fatalf("%s: publish revision %d: %v", name, step.Publish, err)
				}
			}
			from := ev.count()
			code, err := p.run(step.Cmd)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, step.Label, err)
			}
			t.Log(parity.Line("optc", sc.Name, mode, step.Label, code, verdicts(from)))
		}
		if err := s.Remove(ctx, 0); err != nil {
			t.Errorf("%s: Remove: %v", name, err)
		}
	}
}

// heldPipeInit is the product's command-pipe init, held before its shell
// exec until the binding is published.
type heldPipeInit struct {
	cmd      *exec.Cmd
	in       io.WriteCloser
	out      *bufio.Reader
	ino      uint64
	fifo, id string
}

const heldPipeInitScript = `while IFS= read -r line; do /bin/sh -c "$line"; echo "@@done $?"; done`

func startHeldPipeInit(t *testing.T, rt *fakeRuntime, cgroup, id string) *heldPipeInit {
	t.Helper()
	// The init is a runtime-like init (review R3-C1): a memfd copy of the
	// runtime binary, blocked on THIS container's exec.fifo; released, it
	// execs the command-pipe shell (the "entrypoint"). Bind proves exactly
	// that state; the shell's exec captures the anchor.
	fifo := rt.fifo(t, id)
	bin, err := os.ReadFile(rt.bin)
	if err != nil {
		t.Fatal(err)
	}
	cmd := rt.command(t, cgroup, fifo, bin, "/usr/bin/bash", "-c", heldPipeInitScript)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	waitBlocked(t, cmd.Process.Pid)
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	return &heldPipeInit{cmd: cmd, in: in, out: bufio.NewReader(out), ino: st.Ino, fifo: fifo, id: id}
}

// release lets the init exec its shell (runc start) and waits until it
// answers.
func (p *heldPipeInit) release() error {
	if err := release(p.fifo); err != nil {
		return err
	}
	if code, err := p.run("true"); err != nil || code != 0 {
		return fmt.Errorf("code %d: %v", code, err)
	}
	return nil
}

func (p *heldPipeInit) run(line string) (int, error) {
	_, code, err := p.output(line, 30*time.Second)
	return code, err
}

// output runs line and returns its stdout and exit status.
func (p *heldPipeInit) output(line string, timeout time.Duration) (string, int, error) {
	if _, err := io.WriteString(p.in, line+"\n"); err != nil {
		return "", 0, err
	}
	type result struct {
		out  string
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		var out strings.Builder
		for {
			l, err := p.out.ReadString('\n')
			if err != nil {
				done <- result{out.String(), 0, err}
				return
			}
			var code int
			if _, err := fmt.Sscanf(l, "@@done %d", &code); err == nil {
				done <- result{out.String(), code, nil}
				return
			}
			out.WriteString(l)
		}
	}()
	select {
	case r := <-done:
		return r.out, r.code, r.err
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		return "", 0, fmt.Errorf("init did not answer %q", line)
	}
}

// TestG004OptcBench (G004 E6): S1's bench workloads (parity.Workloads) in a
// cgroup bound Strict to S1's bench policy through the option C node, or
// (IG_G004_BENCH=none) in the same kind of cgroup with no engine. Samples:
// "BENCH metric=<m> rep=<i> value=<v>".
//
//	IG_G004_BENCH        optc | none
//	IG_G004_BENCH_HELPER S1's static d1-helper
//	IG_G004_BENCH_REPS   repetitions (default 3)
func TestG004OptcBench(t *testing.T) {
	cfg, helper := os.Getenv("IG_G004_BENCH"), os.Getenv("IG_G004_BENCH_HELPER")
	if (cfg != "optc" && cfg != "none") || helper == "" || os.Geteuid() != 0 {
		t.Skip("set IG_G004_BENCH=optc|none and IG_G004_BENCH_HELPER, as root")
	}
	reps, _ := strconv.Atoi(os.Getenv("IG_G004_BENCH_REPS"))
	if reps <= 0 {
		reps = 3
	}
	cgroup := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ig15-g004-bench-%d", os.Getpid()))
	if err := os.MkdirAll(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroup) })
	rt := newFakeRuntime(t)
	p := startHeldPipeInit(t, rt, cgroup, "bench")
	if cfg == "optc" {
		ctx := context.Background()
		node, err := StartNode(ctx, Config{Admission: DefaultAdmission(), Runtime: rt.config()})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := node.Ready(nil); err != nil {
				t.Errorf("Ready after the bench: %v", err)
			}
			_ = node.StopNode(ctx)
		}()
		s, err := node.Bind(ctx, fullruntime.SharedBindingConfig{CgroupID: p.ino, InitHostPID: uint32(p.cmd.Process.Pid), ContainerID: "bench"})
		if err != nil {
			t.Fatal(err)
		}
		bp := parity.BenchPolicy()
		if _, err := s.Publish(ctx, fullruntime.SharedBindingPolicy{Source: &bp, Container: "bench"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.release(); err != nil {
		t.Fatalf("init after its exec: %v", err)
	}
	run := func(line string) string {
		out, code, err := p.output(line, 10*time.Minute)
		if err != nil || code != 0 {
			t.Fatalf("%q: %q code %d: %v", line, out, code, err)
		}
		return out
	}
	ws := parity.Workloads(helper)
	_ = run(ws[len(ws)-1].Line) // warm the page cache
	for rep := 0; rep < reps; rep++ {
		for _, w := range ws {
			v, err := parity.Value(run(w.Line), w.Key)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("BENCH metric=%s rep=%d value=%d", w.Metric, rep, v)
		}
	}
}
