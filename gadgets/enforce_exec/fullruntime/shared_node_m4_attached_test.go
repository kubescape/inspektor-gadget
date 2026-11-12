// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedPipeInit is a container-like init that runs commands it reads from
// a pipe (like a runtime's init before the entrypoint exec): a shell cloned
// directly into the cgroup with its own mount namespace. Every command it
// runs is forked and executed by the adopted init itself, so its verdicts
// are the bound route's (unlike a shell joining the cgroup from the host,
// which has no TASK).
type sharedPipeInit struct {
	cmd  *exec.Cmd
	mu   sync.Mutex
	in   io.WriteCloser
	out  *bufio.Reader
	path string
	ino  uint64
}

const sharedPipeInitScript = `while IFS= read -r line; do /bin/sh -c "$line"; echo "@@done $?"; done`

func startSharedPipeInit(t *testing.T, cgroup, name string) *sharedPipeInit {
	t.Helper()
	return startSharedPipeInitShell(t, cgroup, name, "/bin/sh")
}

// startSharedPipeInitShell is startSharedPipeInit with an explicit shell
// (bash survives a refused fork; dash exits on it).
func startSharedPipeInitShell(t *testing.T, cgroup, name, shell string) *sharedPipeInit {
	t.Helper()
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	cmd := exec.Command(shell, "-c", sharedPipeInitScript)
	cmd.Args[0] = name
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
		t.Fatalf("start %s in %s: %v", name, cgroup, err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	return &sharedPipeInit{cmd: cmd, in: in, out: bufio.NewReader(out), path: cgroup, ino: st.Ino}
}

// run executes line inside the init and returns its stdout and exit status.
// It gives up when ctx ends (the init is killed at cleanup).
func (p *sharedPipeInit) run(ctx context.Context, line string) (string, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	type result struct {
		out  string
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		if _, err := io.WriteString(p.in, line+"\n"); err != nil {
			done <- result{err: err}
			return
		}
		var out strings.Builder
		for {
			l, err := p.out.ReadString('\n')
			if err != nil {
				done <- result{out: out.String(), err: fmt.Errorf("init output: %w", err)}
				return
			}
			var code int
			if _, scanErr := fmt.Sscanf(l, "@@done %d", &code); scanErr == nil {
				done <- result{out: strings.TrimSpace(out.String()), code: code}
				return
			}
			out.WriteString(l)
		}
	}()
	select {
	case r := <-done:
		return r.out, r.code, r.err
	case <-ctx.Done():
	}
	// Canceled: never leave a reader behind on the shared output (a later
	// run would read this command's "@@done"). Still holding p.mu, wait for
	// the command to finish; if it does not, kill the init so the reader
	// ends at EOF.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
	}
	return "", 0, ctx.Err()
}

// smoke returns the cgroup's verdicts for one exec as euid 0 and one as
// euid 1000, both forked and executed by the adopted init.
func (p *sharedPipeInit) smoke(t *testing.T, ctx context.Context) string {
	t.Helper()
	out, err := p.smokeE(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// smokeE is smoke returning its failure, so a caller can log diagnostics
// before failing.
func (p *sharedPipeInit) smokeE(ctx context.Context) (string, error) {
	out, code, err := p.run(ctx, `/bin/true; a=$?; setpriv --reuid=1000 --regid=1000 --clear-groups /bin/true; b=$?; echo "r0=$a r1000=$b"`)
	if err != nil || code != 0 {
		return out, fmt.Errorf("smoke in %s: %q code %d: %w", p.path, out, code, err)
	}
	return out, nil
}

// stop ends the init: its stdin closes (the read loop ends), then it is
// killed and reaped, so its TASK settles.
func (p *sharedPipeInit) stop() {
	_ = p.in.Close()
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

// sharedM4Witness is one snapshot of the product fail-closed witness
// (opaque_real_fail_closed_rates, 12 cells) and opaque_real_attempts.
type sharedM4Witness struct {
	rates    [FailClosedRateCounters]uint64
	attempts [FailClosedRateAttempts]uint64
}

func sharedM4ReadWitness(t *testing.T, gc *gadgetcontext.GadgetContext) sharedM4Witness {
	t.Helper()
	var w sharedM4Witness
	for name, cells := range map[string][]uint64{"opaque_real_fail_closed_rates": w.rates[:], "opaque_real_attempts": w.attempts[:]} {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, _ := value.(*ebpf.Map)
		if m == nil {
			t.Fatalf("witness %s not published: a missing witness is unknown, never zero", name)
		}
		for i := range cells {
			if err := m.Lookup(uint32(i), &cells[i]); err != nil {
				t.Fatalf("%s[%d]: %v", name, i, err)
			}
		}
	}
	return w
}

// sharedM4RequireCounted runs fn and requires the witness to have counted
// it as managed (attempts up) with no fail-closed refusal (Total, ENTRY and
// ADMISSION unchanged): verdicts from adopted tasks evaluated by the graph,
// not admission faults (an Audit route allows those, now counted).
func sharedM4RequireCounted(t *testing.T, gc *gadgetcontext.GadgetContext, step string, fn func()) {
	t.Helper()
	sharedM4RequireCountedE(t, gc, step, nil, func() error { fn(); return nil })
}

// sharedM4RequireCountedE is sharedM4RequireCounted over a step that
// returns its failure: on any failure (the step's or the witness's) it logs
// the diagnostic dump (sharedM4Diagnose, with the commander when given),
// then fails the test. The diagnostics never mask a failure.
func sharedM4RequireCountedE(t *testing.T, gc *gadgetcontext.GadgetContext, step string, cmd *productCommander, fn func() error) {
	t.Helper()
	before := sharedM4ReadWitness(t, gc)
	stepErr := fn()
	after := sharedM4ReadWitness(t, gc)
	v, err := FailClosedProductRate(before.rates, after.rates, before.attempts, after.attempts, 0)
	attempts := (after.attempts[0] - before.attempts[0]) + (after.attempts[1] - before.attempts[1])
	if stepErr != nil || err != nil || attempts == 0 || v.Total != 0 || v.Entry != 0 || v.Admission != 0 {
		t.Logf("%s: witness before %v attempts %v; after %v attempts %v", step, before.rates, before.attempts, after.rates, after.attempts)
		sharedM4Diagnose(t, gc, cmd)
		t.Fatalf("%s: step %v; witness %+v attempts +%d (%v): want the step to pass with managed attempts, no fail-closed refusal, no ENTRY and no ADMISSION fault", step, stepErr, v, attempts, err)
	}
}

// sharedM4Diagnose logs (test-only) what the product path recorded: the
// verdict progress and evaluation-WORK witnesses the object carries, the
// adopt state and route of each product slot, and the staged policy cells
// (header, policy prefix, first rule) of each published slot's object.
func sharedM4Diagnose(t *testing.T, gc *gadgetcontext.GadgetContext, cmd *productCommander) {
	t.Helper()
	mapOf := func(name string) *ebpf.Map {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, _ := value.(*ebpf.Map)
		return m
	}
	for _, name := range []string{
		"opaque_real_owner_policy_witness", "opaque_real_owner_rule_progress", "opaque_real_eval_work_outcomes",
		"opaque_real_exec_exclusions", "opaque_real_owner_rule_windows", "opaque_real_rule_windows",
		"opaque_real_policy_witness", "opaque_real_eval_work_witness",
		// The exec-capsule store's stats (SE_CAP_STAT_*, 15 u64: [13] FAULT
		// counts a degraded admission, e.g. a capsule the store could not
		// create; [14] DEATH_RETIRED a capsule retired at task_free).
		"se_exec_capsule_stats",
	} {
		m := mapOf(name)
		if m == nil {
			continue
		}
		switch m.Type() {
		case ebpf.Array:
			for i := uint32(0); i < min(m.MaxEntries(), 16); i++ {
				raw, err := m.LookupBytes(i)
				t.Logf("diag %s[%d] = %x (%v)", name, i, raw, err)
			}
		case ebpf.Hash:
			it := m.Iterate()
			var key, value []byte
			for n := 0; n < 16 && it.Next(&key, &value); n++ {
				t.Logf("diag %s[%x] = %x", name, key, value)
			}
		default:
			t.Logf("diag %s: %s, not dumped", name, m.Type())
		}
	}
	if cmd == nil {
		return
	}
	cmd.mu.Lock()
	slots := maps.Clone(cmd.slots)
	cmd.mu.Unlock()
	arena := mapOf("se_arena")
	for slot, record := range slots {
		state, err := cmd.slotState(slot)
		t.Logf("diag slot %d adopt state %+v (%v)", slot, state, err)
		route, err := cmd.productRoute(slot)
		t.Logf("diag slot %d route %+v (%v); object %d", slot, route, err, record.object)
		object, err := cmd.object(record.object)
		t.Logf("diag object %d %+v (%v)", record.object, object, err)
		if arena == nil {
			continue
		}
		base := record.object * 256 // class-0 objects (the qualification profile's 2 x 256 cells)
		cell := func(index uint32) fullpolicy.Blob {
			var b fullpolicy.Blob
			raw, err := arena.LookupBytes(base + index)
			if err != nil {
				t.Logf("diag arena[%d]: %v", base+index, err)
			}
			copy(b[:], raw)
			return b
		}
		header, _ := fullpolicy.Decode[fullpolicy.KernelHeader](cell(0))
		policy, _ := fullpolicy.Decode[fullpolicy.KernelPolicy](cell(fullpolicy.KernelPolicyBase))
		rule, _ := fullpolicy.Decode[fullpolicy.KernelRule](cell(fullpolicy.KernelRuleBase))
		t.Logf("diag object %d header %+v", record.object, header)
		t.Logf("diag object %d policy uid %d role %d default %d mode %d epoch %d", record.object, policy.UID, policy.RootRole, policy.Default, policy.Mode, policy.RootEpoch)
		t.Logf("diag object %d rule[0] %+v", record.object, rule)
	}
}

// sharedM4RequireAdopted requires the slot's adoption to have counted
// exactly the one init task (adopted == iterated == 1).
func sharedM4RequireAdopted(t *testing.T, gc *gadgetcontext.GadgetContext, slot uint32) {
	t.Helper()
	value, _ := gc.GetVar(operators.MapPrefix + "opaque_real_adopt_state")
	m, _ := value.(*ebpf.Map)
	if m == nil {
		t.Fatal("opaque_real_adopt_state not published")
	}
	raw, err := m.LookupBytes(slot)
	if err != nil {
		t.Fatal(err)
	}
	st, err := decodeSharedProductAdoptState(raw)
	if err != nil || st.Adopted != 1 || st.Iterated != 1 || st.Adopting != 0 {
		t.Fatalf("slot %d adoption state %+v %v: want adopted == iterated == 1, finished", slot, st, err)
	}
}

func (p *sharedPipeInit) acquire(context.Context) (BindingLease, error) {
	pid := p.cmd.Process.Pid
	l := &sharedM2Lease{}
	var err error
	open := func(path string, flags int) *os.File {
		f, e := os.OpenFile(path, flags, 0)
		err = errors.Join(err, e)
		return f
	}
	l.proc = open(fmt.Sprintf("/proc/%d", pid), unix.O_DIRECTORY|unix.O_RDONLY)
	l.cgroup = open(p.path, unix.O_DIRECTORY|unix.O_RDONLY)
	l.mount = open(fmt.Sprintf("/proc/%d/ns/mnt", pid), unix.O_RDONLY)
	l.hostMount = open("/proc/self/ns/mnt", unix.O_RDONLY)
	return l, err
}

// sharedM4Policy is the M2/M3 test policy as an authored fullpolicy.Policy:
// root role "app", fallback deny, one rule allowing euid 0 (M3's Strict A),
// or fallback allow.
func sharedM4Policy(id, revision string, mode fullpolicy.Mode, fallback fullpolicy.Action) *fullpolicy.Policy {
	return &fullpolicy.Policy{
		ID: id, Revision: revision, Mode: mode, RootRole: "app", Default: fallback,
		Rules: []fullpolicy.Rule{{Name: "root", Action: fullpolicy.Allow, Actor: fullpolicy.Actor{UID: []int64{0}}}},
	}
}

// TestSharedNodeM4ProductAttached (G019 M4, G6): two bindings on one
// StartNode collection through the node's own PRODUCT publisher (G1; no
// bootstrap programs): Source-compiled policies staged into shared objects,
// published with root-task adoption of a command-pipe init in each cgroup.
// A is Strict (fallback deny, euid 0 allowed), B Audit. Then A is revised
// (fallback allow) under exec churn in B, a revision changing the policy
// UID is refused (terminal), A is removed (withdraw, then recycle frees its
// slot) and B never changes. StopNode leaves nothing. Isolated exact-kernel
// VM only, with a non-recovery product-publisher object (IG_SHARED_M4_OBJECT;
// a recovery twin has no se_admin and is refused).
func TestSharedNodeM4ProductAttached(t *testing.T) {
	object := os.Getenv("IG_SHARED_M4_OBJECT")
	if object == "" {
		t.Skip("set IG_SHARED_M4_OBJECT on an isolated exact-kernel VM")
	}
	cgroupA, cgroupB := os.Getenv("IG_SHARED_M4_CGROUP_A"), os.Getenv("IG_SHARED_M4_CGROUP_B")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(cgroupA), "ig15-g019-m4-") || !strings.HasPrefix(filepath.Base(cgroupB), "ig15-g019-m4-") || cgroupA == cgroupB {
		t.Fatal("root and two dedicated ig15-g019-m4-* cgroups required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	node, gc, ctx := startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	stopped := false
	defer func() {
		if !stopped {
			_ = node.StopNode(context.WithoutCancel(ctx))
		}
	}()
	publisher, err := node.livePublisher(false)
	live, product := publisher.(*sharedLiveProductPublisher)
	if err != nil || !product {
		t.Fatalf("node publisher %T (%v), want the product publisher (G1)", publisher, err)
	}
	if cmd, ok := live.cmd.(*productCommander); !ok {
		t.Fatalf("product commander %T", live.cmd)
	} else {
		sharedM4RequireArmed(t, gc, cmd.control)
	}
	var expected []sharedM3Link
	for name, r := range node.host.live.receipts {
		expected = append(expected, sharedM3Link{name, r.LinkID, r.ProgramID})
	}

	ia, ib := startSharedPipeInit(t, cgroupA, "ig15-g019-m4-init-a"), startSharedPipeInit(t, cgroupB, "ig15-g019-m4-init-b")
	a, err := node.Bind(ctx, SharedBindingConfig{CgroupID: ia.ino, InitHostPID: uint32(ia.cmd.Process.Pid), Acquire: ia.acquire})
	if err != nil {
		t.Fatalf("Bind A: %v", err)
	}
	b, err := node.Bind(ctx, SharedBindingConfig{CgroupID: ib.ino, InitHostPID: uint32(ib.cmd.Process.Pid), Acquire: ib.acquire})
	if err != nil {
		t.Fatalf("Bind B: %v", err)
	}
	strict := sharedM4Policy("m4-a", "1", fullpolicy.Enforce, fullpolicy.Deny)
	if _, err := a.Publish(ctx, SharedBindingPolicy{Source: strict, Container: "a"}); err != nil {
		t.Fatalf("publish A (adoption): %v", err)
	}
	if _, err := b.Publish(ctx, SharedBindingPolicy{Source: sharedM4Policy("m4-b", "1", fullpolicy.Audit, fullpolicy.Deny), Container: "b"}); err != nil {
		t.Fatalf("publish B (adoption): %v", err)
	}
	for name, s := range map[string]*BindingSession{"A": a, "B": b} {
		if st := s.Inspect(); st.Fault != nil || !st.RoutePublished || st.Adoption != nil || st.Generation != 1 {
			t.Fatalf("%s after adoption: %+v adoption %+v", name, st, st.Adoption)
		}
	}
	sharedM4RequireAdopted(t, gc, a.Inspect().RouteSlot)
	sharedM4RequireAdopted(t, gc, b.Inspect().RouteSlot)
	bStatus, bRoute := b.Inspect(), mustRoute(t, publisher, b.Inspect().RouteSlot)
	var aVerdict, bVerdict string
	// A's denial is a policy verdict (126: setpriv's exec refused), never a
	// fail-closed refusal; both cgroups' execs are managed (adopted).
	aCmd := live.cmd.(*productCommander)
	sharedM4RequireCountedE(t, gc, "A smoke", aCmd, func() error {
		var err error
		aVerdict, err = ia.smokeE(ctx)
		return err
	})
	sharedM4RequireCountedE(t, gc, "B smoke", aCmd, func() error {
		var err error
		bVerdict, err = ib.smokeE(ctx)
		return err
	})
	t.Logf("M4: A(Strict) %s, B(Audit) %s", aVerdict, bVerdict)
	if aVerdict != "r0=0 r1000=126" || bVerdict != "r0=0 r1000=0" {
		t.Fatalf("adopted verdicts: A %q (want r0=0 r1000=126), B %q (want Audit nonblocking)", aVerdict, bVerdict)
	}
	requireB := func(step string) {
		t.Helper()
		st := b.Inspect()
		if route := mustRoute(t, publisher, st.RouteSlot); st.Fault != nil || !st.RoutePublished || st.Removed || st.Generation != bStatus.Generation || route != bRoute {
			t.Fatalf("%s: B changed: %+v route=%+v (want %+v)", step, st, route, bRoute)
		}
		sharedM4RequireCounted(t, gc, step+": B smoke", func() {
			if v := ib.smoke(t, ctx); v != bVerdict {
				t.Fatalf("%s: B verdicts %q, want %q", step, v, bVerdict)
			}
		})
		if err := node.Ready(gc); !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(err.Error(), "adoption refused") {
			t.Fatalf("%s: Ready %v", step, err)
		}
	}
	requireB("published")

	// Revision of A (fallback allow) under exec churn in B.
	reaperBefore, err := node.host.live.reaper.reaper.Stats()
	if err != nil {
		t.Fatalf("product reaper stats before the churn: %v", err)
	}
	churnCtx, stopChurn := context.WithCancel(ctx)
	var churn sync.WaitGroup
	var churnMu sync.Mutex
	var churnBad []string
	churnN, churnStarted := 0, 0
	churnCount := func() int { churnMu.Lock(); defer churnMu.Unlock(); return churnN }
	churnStarts := func() int { churnMu.Lock(); defer churnMu.Unlock(); return churnStarted }
	churn.Add(1)
	go func() {
		defer churn.Done()
		for churnCtx.Err() == nil {
			churnMu.Lock()
			churnStarted++
			churnMu.Unlock()
			out, code, err := ib.run(churnCtx, "/bin/true")
			if churnCtx.Err() != nil {
				return
			}
			churnMu.Lock()
			churnN++
			if err != nil || code != 0 {
				churnBad = append(churnBad, fmt.Sprintf("%q %d %v", out, code, err))
			}
			churnMu.Unlock()
		}
	}()
	for warm := time.Now().Add(10 * time.Second); churnCount() < 3; time.Sleep(5 * time.Millisecond) {
		if churnCtx.Err() != nil || time.Now().After(warm) {
			stopChurn()
			churn.Wait()
			t.Fatalf("B churn did not start: %d execs, bad %v", churnN, churnBad)
		}
	}
	revised := sharedM4Policy("m4-a", "2", fullpolicy.Enforce, fullpolicy.Allow)
	var state SharedRouteState
	var churnBefore, churnAfter int
	for attempt := 0; ; attempt++ {
		// The overlap is measured around this attempt: the final, successful
		// one is the revision that committed.
		// An exec overlapped this Publish iff one was in flight when it began
		// or one started before it ended: started(end) > finished(begin).
		churnBefore = churnCount()
		state, err = a.Publish(ctx, SharedBindingPolicy{Source: revised, Container: "a"})
		churnAfter = churnStarts()
		// Only the retryable refusal (in-flight claims or pins) is retried;
		// a terminal one fails at once.
		if err == nil || attempt == 50 || !strings.Contains(err.Error(), "retryable") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stopChurn()
	churn.Wait()
	if err != nil {
		t.Fatalf("revise A: %v", err)
	}
	if churnAfter <= churnBefore {
		t.Fatalf("B churn did not overlap A's committing revision (%d finished before, %d started by its end)", churnBefore, churnAfter)
	}
	if v := ia.smoke(t, ctx); v != "r0=0 r1000=0" {
		t.Fatalf("A revision gen %d not enforced: %s", state.Generation, v)
	}
	if len(churnBad) != 0 {
		t.Fatalf("B churn during A's revision: %d runs, bad %v", churnN, churnBad)
	}
	// B's churn ran in its adopted init: every exec forked a TASK-charged
	// child whose credit returns through the product reaper, from wakeups
	// (event reaps) or, with credit at exit, as FREED witnesses.
	reaper := node.host.live.reaper
	if reaper == nil {
		t.Fatal("StartNode runs no product reaper")
	}
	if err := reaper.fault(); err != nil {
		t.Fatalf("product reaper during churn: %v", err)
	}
	returned := func(s ReaperStats) uint64 { return s.EventReaps + s.Freed }
	stats, err := reaper.reaper.Stats()
	for deadline := time.Now().Add(5 * time.Second); err == nil && returned(stats) <= returned(reaperBefore) && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		stats, err = reaper.reaper.Stats()
	}
	if err != nil || returned(stats) <= returned(reaperBefore) {
		t.Fatalf("product reaper returned no credit after %d adopted churn execs: %s (%v)", churnN, stats, err)
	}
	t.Logf("M4: product reaper %s", stats)
	requireB("A revised")

	// A revision changing the policy UID is refused (G019 limit, terminal)
	// and keeps A's last-good.
	aBefore := a.Inspect()
	aRoute := mustRoute(t, publisher, aBefore.RouteSlot)
	if _, err := a.Publish(ctx, SharedBindingPolicy{Source: sharedM4Policy("m4-other", "1", fullpolicy.Enforce, fullpolicy.Deny), Container: "a"}); err == nil || !strings.Contains(err.Error(), "policy UID") {
		t.Fatalf("UID-changing revision: %v", err)
	}
	if st, route := a.Inspect(), mustRoute(t, publisher, aBefore.RouteSlot); st.Fault != nil || st.Generation != aBefore.Generation || route != aRoute {
		t.Fatalf("A after a refused revision: %+v route %+v (last-good %+v route %+v)", st, route, aBefore, aRoute)
	}
	if v := ia.smoke(t, ctx); v != "r0=0 r1000=0" {
		t.Fatalf("A after a refused revision: %s, want the revised verdicts", v)
	}
	requireB("A revision refused")

	// Removal of A: withdraw, then the background recycle. The slot stays
	// occupied while A's adopted init holds its TASK charge (recycle
	// contended); once the init is gone, the recycle frees it.
	slotA := aBefore.RouteSlot
	if err := a.Remove(ctx, aBefore.Generation); err != nil {
		t.Fatalf("Remove A: %v", err)
	}
	for held := time.Now().Add(3 * time.Second); time.Now().Before(held); time.Sleep(100 * time.Millisecond) {
		node.mu.Lock()
		occupied := node.host.scopeSlots[slotA] != nil
		node.mu.Unlock()
		if !occupied {
			t.Fatalf("A's slot %d recycled while its adopted init still holds a TASK", slotA)
		}
	}
	ia.stop()
	deadline := time.Now().Add(30 * time.Second)
	for {
		node.mu.Lock()
		free := node.host.scopeSlots[slotA] == nil
		node.mu.Unlock()
		if free {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("A's slot %d not recycled: %v", slotA, node.liveHealthFault())
		}
		time.Sleep(50 * time.Millisecond)
	}
	requireB("A removed and recycled")
	if _, counts, err := node.AdoptionReport(); err != nil || len(counts) != 0 {
		t.Fatalf("adoption counters %v %v, want none", counts, err)
	}

	if err := node.StopNode(context.WithoutCancel(ctx)); err != nil {
		t.Fatalf("StopNode: %v", err)
	}
	stopped = true
	deadline = time.Now().Add(10 * time.Second)
	for _, e := range expected {
		for {
			p, err := ebpf.NewProgramFromID(ebpf.ProgramID(e.program))
			if err != nil {
				break
			}
			p.Close()
			if time.Now().After(deadline) {
				t.Errorf("program %d (%s, link %d) survived StopNode", e.program, e.name, e.link)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Log("PASS: M4 product publisher: adoption, Strict/Audit verdicts by the adopted inits, revision under churn, UID change refused, withdraw + recycle, B unchanged, full cleanup")
}

func mustRoute(t *testing.T, p SharedRoutePublisher, slot uint32) SharedRouteState {
	t.Helper()
	r, err := p.Route(slot)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestSharedPipeInitCanceledRun (host, no VM): a canceled run never leaves
// a reader on the shared output, so the next run reads its own result, not
// the canceled command's "@@done".
func TestSharedPipeInitCanceledRun(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", sharedPipeInitScript)
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
	p := &sharedPipeInit{cmd: cmd, in: in, out: bufio.NewReader(out)}
	defer p.stop()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := p.run(ctx, "sleep 0.3; echo stale; exit 3"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled run: %v", err)
	}
	next, cancelNext := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelNext()
	if got, code, err := p.run(next, "echo fresh"); err != nil || got != "fresh" || code != 0 {
		t.Fatalf("run after a canceled one: %q %d %v, want its own result", got, code, err)
	}
}

// sharedM4RequireArmed: after StartNode the product object's hooks are
// armed (G019 chain14): the configuration gate holds (se_configuration is
// exactly the product control's frozen configuration, so se_profile_matches
// arms every hook; no userspace test gate exists), and every tail-call slot
// holds exactly its target, installed by the eBPF operator before attach.
func sharedM4RequireArmed(t *testing.T, gc *gadgetcontext.GadgetContext, control *sharedProductControl) {
	t.Helper()
	if control == nil || !control.installed {
		t.Fatal("product control not installed")
	}
	mapOf := func(name string) *ebpf.Map {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, _ := value.(*ebpf.Map)
		return m
	}
	for _, name := range sharedProductTestGateMaps {
		if mapOf(name) != nil {
			t.Fatalf("product object carries the test gate %s", name)
		}
	}
	configuration := mapOf("se_configuration")
	if configuration == nil {
		t.Fatal("se_configuration not published")
	}
	var installed sharedNodeWire
	if err := configuration.Lookup(uint32(0), &installed); err != nil || installed != control.config || installed.NodeCookie == 0 || installed.Nonce == 0 {
		t.Fatalf("se_configuration %+v (%v), want the control's %+v: the configuration gate is not armed", installed, err, control.config)
	}
	// The exec-capsule store is per-task storage (design 13.19), so every
	// tgid has its capsule.
	for name := range sharedProductCapsuleMaps {
		if m := mapOf(name); m == nil || m.Type() != ebpf.TaskStorage {
			t.Fatalf("exec-capsule map %s is not per-task storage: %v", name, m)
		}
	}
	for _, c := range sharedProductTailCalls {
		array := mapOf(c.Map)
		if array == nil {
			t.Fatalf("tail call map %s not published", c.Map)
		}
		var program *ebpf.Program
		if err := array.Lookup(c.Index, &program); err != nil || program == nil {
			t.Fatalf("tail call %s[%d] empty: %v", c.Map, c.Index, err)
		}
		info, err := program.Info()
		program.Close()
		// cilium/ebpf reports the program's BTF function name (the full
		// name) when available, else the kernel's 15-character object name.
		truncated := c.Program
		if len(truncated) > 15 { // BPF_OBJ_NAME_LEN - 1
			truncated = truncated[:15]
		}
		if err != nil || (info.Name != c.Program && info.Name != truncated) {
			t.Fatalf("tail call %s[%d] holds %q (%v), want %s", c.Map, c.Index, info.Name, err, c.Program)
		}
	}
}
