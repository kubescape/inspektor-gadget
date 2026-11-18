// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/parity"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// TestG004ProductParity (G004 qualification, verdict parity): the parity
// scenario table (optcnode/parity) through today's product node, one node
// per scenario with binding A Strict (Enforce) and B Audit, each a
// command-pipe init in its own cgroup. Every step prints one PARITY line;
// optcnode's TestG004OptcParity prints the same lines for the option C node.
//
//	IG_G004_PRODUCT_OBJECT   the pinned product object of this kernel
func TestG004ProductParity(t *testing.T) {
	object := os.Getenv("IG_G004_PRODUCT_OBJECT")
	if object == "" || os.Geteuid() != 0 {
		t.Skip("set IG_G004_PRODUCT_OBJECT, as root, on an isolated exact-kernel VM")
	}
	if err := parity.Setup(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ig15-g004-parity-%d", os.Getpid()))
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	for _, sc := range parity.Scenarios() {
		t.Run(sc.Name, func(t *testing.T) { productParityScenario(t, object, root, sc) })
	}
}

// parityEnforcer and parityBinding are optcnode.Enforcer and
// optcnode.Binding (same method sets; this package cannot import optcnode):
// the parity harness drives the product node through them, as optcnode's
// harness drives the option C node.
type parityEnforcer interface {
	Ready(operators.GadgetContext) error
	Degraded(operators.GadgetContext) error
	BeforeStop(context.Context) error
	StopNode(context.Context) error
	KernelEventCounters() (KernelEventCounters, error)
	CapsuleHealth() (SharedCapsuleHealth, error)
	FactHealth() (SharedFactHealth, error)
	BirthParkHealth() (SharedBirthParkHealth, error)
	FailClosedHealth() (SharedFailClosedHealth, error)
	AdoptionReport() ([]SharedAdoptionStatus, map[string]uint64, error)
}

type parityBinding interface {
	Publish(context.Context, SharedBindingPolicy) (SharedRouteState, error)
	Inspect() SharedBindingStatus
	Remove(context.Context, uint64) error
}

func productParityScenario(t *testing.T, object, root string, sc parity.Scenario) {
	c := &sharedVerdictCollector{}
	n, _, ctx := startSharedVerdictNode(t, object, c)
	var node parityEnforcer = n
	defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
	for _, mode := range parity.Modes {
		name := sc.Name + "-" + string(mode)
		cgroup := filepath.Join(root, strings.ReplaceAll(name, "_", "-"))
		if err := os.MkdirAll(cgroup, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(cgroup) })
		p := startHeldProductInit(t, cgroup)
		t.Cleanup(p.stop)
		session, err := n.Bind(ctx, SharedBindingConfig{CgroupID: p.ino, InitHostPID: uint32(p.cmd.Process.Pid), Acquire: p.acquire})
		if err != nil {
			t.Fatalf("%s: Bind: %v", name, err)
		}
		var s parityBinding = session
		policies := sc.Policies(mode)
		publish := func(i int) error {
			for attempt := 0; ; attempt++ {
				_, err := s.Publish(ctx, SharedBindingPolicy{Source: &policies[i], Container: parity.Container})
				if err == nil || attempt == 100 || !strings.Contains(err.Error(), "retryable") {
					return err
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		verdicts := func(from int) []parity.Verdict {
			// Every submitted verdict read (the ring is drained) first.
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
				if k, err := node.KernelEventCounters(); err == nil && uint64(c.count()) == k.Submitted {
					break
				}
			}
			var vs []parity.Verdict
			for _, e := range c.since(from, p.ino) {
				// facts_unknown is a diagnostic mask; an UNKNOWN that
				// decided is an error (enforced) or uncertain (audit).
				v := parity.Verdict{Path: e.path, Deny: e.deny == 1, Blocked: e.deny == 1 && e.mode == 2, Unknown: e.errorCode != 0 || e.uncertain != 0}
				if parity.Keep(v) {
					vs = append(vs, v)
				}
			}
			return vs
		}
		if err := publish(0); err != nil {
			t.Logf("%s: publish refused: %v", name, err)
			t.Log(parity.Refused("product", sc.Name, mode))
			continue
		}
		// The init execs its shell under the published policy.
		from := c.count()
		_, _ = io.WriteString(p.in, "go\n")
		code := 0
		if _, rc, err := p.run(ctx, "true"); err != nil || rc != 0 {
			t.Logf("%s: init after its exec: rc %d: %v", name, rc, err)
			code = -1
		}
		t.Log(parity.Line("product", sc.Name, mode, "init_exec", code, verdicts(from)))
		if code != 0 {
			continue
		}
		for _, step := range sc.Steps {
			if step.Publish > 0 {
				if err := publish(step.Publish); err != nil {
					t.Fatalf("%s: publish revision %d: %v", name, step.Publish, err)
				}
			}
			from := c.count()
			_, code, err := p.run(ctx, step.Cmd)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, step.Label, err)
			}
			t.Log(parity.Line("product", sc.Name, mode, step.Label, code, verdicts(from)))
		}
	}
}

// startHeldProductInit is startSharedPipeInitShell's init, held before its
// shell exec (as optcnode's parity test holds it): bound and published
// first, both engines then decide the init's own exec.
func startHeldProductInit(t *testing.T, cgroup string) *sharedPipeInit {
	t.Helper()
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	cmd := exec.Command("/bin/sh", "-c", `echo ready; read -r go; exec /usr/bin/bash -c "$1"`, "ig15-g004-parity-init", sharedPipeInitScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	p := &sharedPipeInit{cmd: cmd, in: in, out: bufio.NewReader(out), path: cgroup, ino: st.Ino}
	// As in optcnode's harness: bind only once the init's exec completed.
	if l, err := p.out.ReadString('\n'); err != nil || l != "ready\n" {
		t.Fatalf("held init: %q %v", l, err)
	}
	return p
}

// TestG004ProductBench (G004 E6): parity.Workloads in a cgroup bound Strict
// to S1's bench policy through today's product node (S1's bench, with the
// fork-only workload added). Samples: "BENCH metric=<m> rep=<i> value=<v>".
//
//	IG_G004_PRODUCT_OBJECT  the pinned product object of this kernel
//	IG_G004_BENCH_HELPER    S1's static d1-helper
//	IG_G004_BENCH_REPS      repetitions (default 3)
func TestG004ProductBench(t *testing.T) {
	object, helper := os.Getenv("IG_G004_PRODUCT_OBJECT"), os.Getenv("IG_G004_BENCH_HELPER")
	if object == "" || helper == "" || os.Geteuid() != 0 {
		t.Skip("set IG_G004_PRODUCT_OBJECT and IG_G004_BENCH_HELPER, as root")
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
	c := &sharedVerdictCollector{}
	node, _, ctx := startSharedVerdictNode(t, object, c)
	defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
	p := startSharedPipeInitShell(t, cgroup, "ig15-g004-bench-init", "/usr/bin/bash")
	defer p.stop()
	s, err := node.Bind(ctx, SharedBindingConfig{CgroupID: p.ino, InitHostPID: uint32(p.cmd.Process.Pid), Acquire: p.acquire})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	bp := parity.BenchPolicy()
	cp, err := s.Compile(SharedBindingPolicy{Source: &bp, Container: "bench"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for attempt := 0; ; attempt++ {
		_, err = s.PublishCompiled(ctx, cp)
		if err == nil || attempt == 100 || !strings.Contains(err.Error(), "retryable") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	run := func(line string) string {
		out, code, err := p.run(ctx, line)
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
