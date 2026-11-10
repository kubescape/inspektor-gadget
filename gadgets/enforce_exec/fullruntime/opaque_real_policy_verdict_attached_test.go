// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Verdict-class graphs installed by the loader (one static class each).
var opaqueVerdictGraphs = map[string]string{
	"opaque_real_policy_audit":   "opaque_real_owner_policy_audit",
	"opaque_real_policy_strict":  "opaque_real_owner_policy_strict",
	"opaque_real_prepare_audit":  "opaque_real_owner_prepare_audit",
	"opaque_real_prepare_strict": "opaque_real_owner_prepare_strict",
	"opaque_real_stage_audit":    "opaque_real_owner_stage_audit",
	"opaque_real_stage_strict":   "opaque_real_owner_stage_strict",
	"opaque_real_rule_audit":     "opaque_real_owner_rule_audit",
	"opaque_real_rule_strict":    "opaque_real_owner_rule_strict",
	"opaque_real_finish_audit":   "opaque_real_owner_finish_audit",
	"opaque_real_finish_strict":  "opaque_real_owner_finish_strict",
}

// Capsule hooks in the mandatory attach order (terminal first).
var opaqueVerdictCapsuleOrder = []string{
	"real_owner_capsule_terminal",
	"real_owner_capsule_entry",
	"real_owner_capsule_begin",
}

// TestOpaqueRealPolicyVerdictAttached is a disposable, isolated exact-kernel
// diagnostic for the real-policy verdict build with source-capsule admission.
// It seeds synthetic test authority (never product admission) and checks:
// Strict allow when the effective-UID-0 rule matches, policy-caused and
// recoverable EPERM for euid 1000 under a Strict deny fallback, a nonblocking
// Audit known deny, preserved prior LSM denial, and that the qualified parent
// is never quarantined. It is not product enforcement or Ready.
func TestOpaqueRealPolicyVerdictAttached(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_VERDICT_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_REAL_VERDICT_OBJECT on an isolated exact-kernel VM")
	}
	cgroup := os.Getenv("IG_OPAQUE_REAL_LIVE_BOOTSTRAP_CGROUP")
	helper := os.Getenv("IG_OPAQUE_REAL_LIVE_BOOTSTRAP_HELPER")
	class, err := strconv.Atoi(os.Getenv("IG_OPAQUE_REAL_VERDICT_CLASS"))
	if err != nil || class < 1 || class > 2 {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_CLASS must be 1 (Audit) or 2 (Strict)")
	}
	fallback, err := strconv.Atoi(os.Getenv("IG_OPAQUE_REAL_VERDICT_FALLBACK"))
	if err != nil || fallback < 0 || fallback > 2 {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_FALLBACK must be 0, 1 or 2")
	}
	rules := 1
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_RULES"); raw != "" {
		if rules, err = strconv.Atoi(raw); err != nil || rules < 1 || rules > 256 {
			t.Fatalf("invalid rule count %q", raw)
		}
	}
	setRole := 0
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_SET_ROLE"); raw != "" {
		if setRole, err = strconv.Atoi(raw); err != nil || setRole < 0 || setRole > 7 {
			t.Fatalf("invalid set role %q", raw)
		}
	}
	births := 0
	if raw := os.Getenv("IG_OPAQUE_REAL_LIVE_CHURN"); raw != "" {
		if births, err = strconv.Atoi(raw); err != nil || births < 0 || births > 8192 {
			t.Fatalf("invalid churn %q", raw)
		}
	}
	// Thread churn: pthread births in the qualified parent, in batches that
	// fit the WORK quota, reaped between batches.
	threadChurn := 0
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_THREAD_CHURN"); raw != "" {
		if threadChurn, err = strconv.Atoi(raw); err != nil || threadChurn < 1 || threadChurn > 65536 {
			t.Fatalf("invalid thread churn %q", raw)
		}
	}
	// Failed birth: pids.max refuses a fork in cgroup_can_fork, after
	// security_task_alloc already charged the child.
	failedBirth := os.Getenv("IG_OPAQUE_REAL_VERDICT_FAILED_BIRTH") == "1"
	// Decoupled reclamation: racing births while an independent reaper
	// goroutine returns DONE WORK and DEAD TASK credits.
	concurrent := 0
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_CONCURRENT"); raw != "" {
		if concurrent, err = strconv.Atoi(raw); err != nil || concurrent < 1 || concurrent > 65536 {
			t.Fatalf("invalid concurrent births %q", raw)
		}
	}
	// Concurrent-mode faults (G025). ABORT_EVERY=N makes every Nth child
	// constructor take the exact semantic abort (object built with
	// ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC). EXHAUST=1 drops
	// the WORK backpressure so CONCURRENT_STREAMS racing children (1-8)
	// can exhaust evaluation WORK, which must fail closed.
	concurrentOpts := opaqueConcurrentOptions{streams: 3}
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_ABORT_EVERY"); raw != "" {
		if concurrentOpts.abortEvery, err = strconv.Atoi(raw); err != nil || concurrentOpts.abortEvery < 0 || concurrentOpts.abortEvery > 1<<20 {
			t.Fatalf("invalid abort selector %q", raw)
		}
	}
	concurrentOpts.exhaust = os.Getenv("IG_OPAQUE_REAL_VERDICT_EXHAUST") == "1"
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_CONCURRENT_STREAMS"); raw != "" {
		if concurrentOpts.streams, err = strconv.Atoi(raw); err != nil || concurrentOpts.streams < 1 || concurrentOpts.streams > 8 {
			t.Fatalf("invalid concurrent streams %q (1-8)", raw)
		}
	}
	// CONCURRENT_FAILED_BIRTHS=N: N rounds add one fork that fails in
	// cgroup_can_fork (pids.max) after security_task_alloc, while that
	// round's children are still unreaped. SMALL_STORAGE=1: the object was
	// built with SE_TEST_DEFERRED_STORAGE_ENTRIES (receipt/frame HASHes
	// shrunk). TERMINAL_CONTENDER=1: a late TC completion contender races the
	// real terminals of live verdict children.
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_CONCURRENT_FAILED_BIRTHS"); raw != "" {
		if concurrentOpts.failedBirths, err = strconv.Atoi(raw); err != nil || concurrentOpts.failedBirths < 0 || concurrentOpts.failedBirths > 8192 {
			t.Fatalf("invalid concurrent failed births %q", raw)
		}
	}
	// SMALL_STORAGE=terminal (G025 step 4b): the object shrinks only the
	// terminal receipts (SE_TEST_TERMINAL_RECEIPT_ENTRIES) while birth
	// receipts and failure frames stay full size, so the terminal receipt
	// insert refusal must be reached.
	switch raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_SMALL_STORAGE"); raw {
	case "", "0":
	case "1":
		concurrentOpts.smallStorage = true
	case "terminal":
		concurrentOpts.smallStorage, concurrentOpts.terminalStorage = true, true
	default:
		t.Fatalf("invalid small storage mode %q (1 or terminal)", raw)
	}
	concurrentOpts.contender = os.Getenv("IG_OPAQUE_REAL_VERDICT_TERMINAL_CONTENDER") == "1"
	// REAPER_TICK=<duration> (G025 batch D): the test reaper's period, so
	// the refusal rate can be measured against reaper latency.
	concurrentOpts.reaperTick = 2 * time.Millisecond
	reaperTick := os.Getenv("IG_OPAQUE_REAL_VERDICT_REAPER_TICK")
	if reaperTick != "" {
		if concurrentOpts.reaperTick, err = time.ParseDuration(reaperTick); err != nil ||
			concurrentOpts.reaperTick < 100*time.Microsecond || concurrentOpts.reaperTick > time.Second {
			t.Fatalf("invalid reaper tick %q (100us-1s)", reaperTick)
		}
	}
	// BIRTH_RATE=<births/sec> (G025 batch E): births paced open loop on a
	// fixed per-birth schedule (helper FORKP) with at most CONCURRENT_STREAMS
	// live children. Pacing never waits on account state, so it implies
	// EXHAUST semantics (no WORK backpressure).
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_BIRTH_RATE"); raw != "" {
		if concurrentOpts.birthRate, err = strconv.Atoi(raw); err != nil || concurrentOpts.birthRate < 1 || concurrentOpts.birthRate > 100000 {
			t.Fatalf("invalid birth rate %q (1-100000 births/sec)", raw)
		}
		if threadChurn > 0 || concurrentOpts.failedBirths > 0 {
			t.Fatal("IG_OPAQUE_REAL_VERDICT_BIRTH_RATE is exclusive with _THREAD_CHURN and _CONCURRENT_FAILED_BIRTHS")
		}
		concurrentOpts.exhaust = true
	}
	// REQUIRE_NO_REUSE_FAILURES=1 (G025 batch F): with the final-free
	// directory withdrawal, no constructor may lose to a DEAD predecessor
	// at its task address: birth outcomes STALE and CONTENDED and every
	// replacement-failure site must stay 0 (the paced sweep enforces it).
	concurrentOpts.requireNoReuseFailures = os.Getenv("IG_OPAQUE_REAL_VERDICT_REQUIRE_NO_REUSE_FAILURES") == "1"
	// REQUIRE_ZERO_FAIL_CLOSED=1 (G025 steady-state gate): the run must
	// leave the fail-closed rate witness unmoved in every class and every
	// forked child evaluated: 0 Strict fail-closed refusals, 0 Audit
	// unevaluated children. A missing witness is unknown, never zero.
	concurrentOpts.requireZeroFailClosed = os.Getenv("IG_OPAQUE_REAL_VERDICT_REQUIRE_ZERO_FAIL_CLOSED") == "1"
	if concurrent == 0 && (concurrentOpts.abortEvery > 0 || concurrentOpts.exhaust ||
		concurrentOpts.failedBirths > 0 || concurrentOpts.smallStorage || concurrentOpts.contender || reaperTick != "" ||
		concurrentOpts.requireNoReuseFailures || concurrentOpts.requireZeroFailClosed) {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_ABORT_EVERY, _EXHAUST, _CONCURRENT_FAILED_BIRTHS, _SMALL_STORAGE, _TERMINAL_CONTENDER, _REAPER_TICK, _BIRTH_RATE, _REQUIRE_NO_REUSE_FAILURES and _REQUIRE_ZERO_FAIL_CLOSED need IG_OPAQUE_REAL_VERDICT_CONCURRENT")
	}
	if concurrentOpts.requireZeroFailClosed && (concurrentOpts.abortEvery > 0 || concurrentOpts.failedBirths > 0 ||
		concurrentOpts.smallStorage || concurrentOpts.contender) {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_REQUIRE_ZERO_FAIL_CLOSED is exclusive with the fault injectors (_ABORT_EVERY, _CONCURRENT_FAILED_BIRTHS, _SMALL_STORAGE, _TERMINAL_CONTENDER)")
	}
	// REUSE_RACE=1 (G025 batch F): deterministic physical-address reuse of
	// a DEAD predecessor whose directory withdrawal the reaper has not
	// finished, on one pinned CPU (REUSE_CPU, default 0), plus the
	// reader-hold fallback to the reaper path. The fix (the final-free
	// directory withdrawal) is in every object; the witnesses need
	// ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE and
	// ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC (witness, hold).
	reuseRace := os.Getenv("IG_OPAQUE_REAL_VERDICT_REUSE_RACE") == "1"
	reuseCPU := 0
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_REUSE_CPU"); raw != "" {
		if reuseCPU, err = strconv.Atoi(raw); err != nil || reuseCPU < 0 || reuseCPU > 1023 {
			t.Fatalf("invalid reuse CPU %q (0-1023)", raw)
		}
	}
	// MIGRATE=1 (G025 step 7): a second route of the opposite class on a
	// sibling cgroup; children move to it mid-birth, between fork and exec
	// and mid-exec. RELOAD=1|fault (step 8): test-only generation advance
	// during churn; "fault" also injects a mid-publication failure.
	migrate := os.Getenv("IG_OPAQUE_REAL_VERDICT_MIGRATE") == "1"
	reload := os.Getenv("IG_OPAQUE_REAL_VERDICT_RELOAD")
	if reload != "" && reload != "1" && reload != "fault" {
		t.Fatalf("invalid reload mode %q (1 or fault)", reload)
	}
	reloadRounds := 64
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_RELOAD_ROUNDS"); raw != "" {
		if reloadRounds, err = strconv.Atoi(raw); err != nil || reloadRounds < 2 || reloadRounds > 4096 {
			t.Fatalf("invalid reload rounds %q (2-4096)", raw)
		}
	}
	if (migrate || reload != "") && (concurrent > 0 || (migrate && reload != "")) {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_MIGRATE and _RELOAD are exclusive with each other and with _CONCURRENT")
	}
	// The advance maps record r to fixed object r, and the reload policy
	// differs only in its fallback, which must be a known allow or deny.
	if reload != "" && (fallback == 0 || rules+11 > 256) {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_RELOAD needs FALLBACK 1 or 2 and at most 245 rules")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-reallive-") ||
		!filepath.IsAbs(helper) {
		t.Fatal("root, dedicated ig15-g005-reallive-* cgroup and absolute helper required")
	}
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil || st.Ino == 0 {
		t.Fatalf("isolated cgroup: %v", err)
	}
	var migration opaqueMigration
	if migrate {
		migration = newOpaqueMigration(t, cgroup)
	}
	if failedBirth || concurrentOpts.failedBirths > 0 {
		pidsMax := filepath.Join(cgroup, "pids.max")
		original, err := os.ReadFile(pidsMax)
		if err != nil {
			t.Fatalf("failed birth needs the pids controller on %s (+pids in the parent's cgroup.subtree_control): %v", cgroup, err)
		}
		// The helper restores pids.max itself; this covers a helper that
		// died inside its failing-fork window.
		t.Cleanup(func() {
			if err := os.WriteFile(pidsMax, original, 0); err != nil {
				t.Errorf("restore %s: %v", pidsMax, err)
			}
		})
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	pidMaxRaw, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		t.Fatal(err)
	}
	pidMax, err := strconv.ParseUint(strings.TrimSpace(string(pidMaxRaw)), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	// Size to PID_MAX_LIMIT (64-bit): a TGID can never fall outside the
	// capsule ARRAY even if kernel.pid_max is raised after load.
	const pidMaxLimit = 1 << 22
	if pidMax > pidMaxLimit {
		t.Fatalf("pid_max %d exceeds PID_MAX_LIMIT", pidMax)
	}
	for _, name := range []string{"se_exec_capsules", "se_exec_markers"} {
		m := spec.Maps[name]
		if m == nil || m.Type != ebpf.Array {
			t.Fatalf("verdict object lacks capsule ARRAY %s", name)
		}
		m.MaxEntries = pidMaxLimit
	}
	selected := map[string]*ebpf.ProgramSpec{}
	need := []string{
		"opaque_real_live_bootstrap_control", "opaque_real_live_bootstrap_birth",
		"opaque_real_live_bootstrap_qualify", "opaque_real_owner_child_source_candidate",
		"opaque_real_owner_child_target_candidate", "opaque_real_owner_child_final_free_candidate",
		"opaque_real_owner_reader_begin_probe", "opaque_real_owner_reader_success_probe",
		"opaque_real_owner_failure_outer_enter", "opaque_real_owner_failure_handler_enter",
		"opaque_real_owner_failure_handler_exit", "opaque_real_owner_failure_outer_exit",
		"opaque_real_live_reap_work", "opaque_real_live_reap_task",
		"opaque_real_owner_policy_seed_diagnostic",
		// Failure terminal: publishes FAILURE and completes the exact WORK.
		"opaque_real_owner_failure_fexit_probe",
		// Controller completion entrypoint (load coverage; terminals now
		// complete into the evaluation WORK and are not quota-deferred).
		"opaque_real_owner_work_completion_probe",
	}
	if concurrentOpts.contender {
		need = append(need, "opaque_real_owner_terminal_race_complete")
	}
	if concurrentOpts.smallStorage {
		// Only the deferred receipt/frame HASHes are shrunk, and the
		// insert-refusal witness must be present.
		tasks := spec.Maps["se_opaque_charges"]
		if spec.Maps["opaque_real_deferred_storage_refusals"] == nil || tasks == nil {
			t.Fatal("small storage needs an object built with ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC")
		}
		for _, name := range []string{"se_exec_terminal_receipts", "se_failure_outer_frames",
			"se_failure_handler_frames", "opaque_birth_receipts"} {
			m := spec.Maps[name]
			if m == nil {
				t.Fatalf("verdict object lacks %s", name)
			}
			// Terminal-only: exactly the terminal receipts are shrunk.
			shrunk := !concurrentOpts.terminalStorage || name == "se_exec_terminal_receipts"
			if shrunk && m.MaxEntries >= tasks.MaxEntries {
				t.Fatalf("small storage needs an object built with SE_TEST_DEFERRED_STORAGE_ENTRIES or SE_TEST_TERMINAL_RECEIPT_ENTRIES < %d (%s)", tasks.MaxEntries, name)
			}
			if !shrunk && m.MaxEntries != tasks.MaxEntries {
				t.Fatalf("terminal-only small storage needs full-size %s (%d, want %d)", name, m.MaxEntries, tasks.MaxEntries)
			}
		}
	}
	if migrate {
		need = append(need, "opaque_real_live_bootstrap_second_route", "opaque_real_owner_second_policy_seed")
	}
	if reuseRace {
		for _, name := range []string{"opaque_real_fail_closed_rates", "opaque_real_replace_failures",
			"opaque_real_reuse_hold_request"} {
			if spec.Maps[name] == nil {
				t.Fatalf("reuse race needs an object built with ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE and ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC (missing %s)", name)
			}
		}
		need = append(need, "opaque_real_reuse_hold")
	}
	if reload != "" {
		need = append(need, "opaque_real_live_bootstrap_advance", "opaque_real_owner_second_policy_seed")
	}
	need = append(need, opaqueVerdictCapsuleOrder...)
	for _, program := range opaqueVerdictGraphs {
		need = append(need, program)
	}
	for _, name := range need {
		if spec.Programs[name] == nil {
			t.Fatalf("verdict object lacks %s", name)
		}
		selected[name] = spec.Programs[name]
	}
	if err := selectOpaqueNormalChurnBirthPrograms(spec, selected); err != nil {
		t.Fatal(err)
	}
	spec.Programs = selected
	kernelTypes, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20, KernelTypes: kernelTypes},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer c.Close()
	var links []link.Link
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			_ = links[i].Close()
		}
	}()
	gate := struct {
		Cgroup, Scope           uint64
		Enabled, ExecutionClass uint32
	}{st.Ino, 10, 1, uint32(class)}
	mustUpdate := func(name string, key, value any) {
		t.Helper()
		if err := c.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	mustFreeze := func(name string) {
		t.Helper()
		if err := c.Maps[name].Freeze(); err != nil {
			t.Fatalf("freeze %s: %v", name, err)
		}
	}
	mustUpdate("opaque_real_live_bootstrap_gate", uint32(0), gate)
	mustUpdate("opaque_real_owner_child_gate", uint32(0), uint32(1))
	// Node config must equal the compiled profile: 2x256 cells, optionally
	// one 1024-cell object (needed for more than 245 seeded rules).
	wire := sharedNodeWire{NodeCookie: 11, Nonce: 22, ABI: 3, ProfileVersion: 1,
		Bindings: 2, Objects: 2, Cells: 512, Slots: [4]uint32{2}}
	if c.Maps["se_arena"] != nil {
		if info, err := c.Maps["se_arena"].Info(); err == nil && info.MaxEntries == 1536 {
			wire.Objects, wire.Cells, wire.Slots = 3, 1536, [4]uint32{2, 1}
		}
	}
	if rules+11 > 256 && wire.Slots[1] == 0 {
		t.Fatal("more than 245 rules need an object built with SE_PROFILE_SLOTS_1024=1")
	}
	mustUpdate("se_configuration", uint32(0), wire)
	mustUpdate("opaque_real_policy_verdict_fallback", uint32(0), uint32(fallback))
	mustUpdate("opaque_real_owner_rule_uid_expect", uint32(0), uint32(0))
	mustUpdate("opaque_real_policy_verdict_rules", uint32(0), uint32(rules))
	mustUpdate("opaque_real_policy_verdict_set_role", uint32(0), uint32(setRole))
	frozen := []string{"se_configuration", "opaque_real_live_bootstrap_gate",
		"opaque_real_owner_child_gate", "se_opaque_payload_zero", "se_opaque_work_zero",
		"opaque_real_policy_verdict_fallback", "opaque_real_owner_rule_uid_expect",
		"opaque_real_policy_verdict_rules", "opaque_real_policy_verdict_set_role"}
	// Second policy (object 1): the migration route's opposite-class policy
	// (binding 1), or the reload policy of the same class whose fallback
	// is flipped (binding 0, unpinned until the generation advance).
	type secondPolicy struct{ ExecutionClass, Fallback, Binding, Enabled uint32 }
	reloadFallback := [2]int{fallback, 3 - fallback}
	if migrate {
		mustUpdate("opaque_real_live_second_route_gate", uint32(0), struct {
			Cgroup, Scope           uint64
			Enabled, ExecutionClass uint32
		}{migration.ino, 11, 1, uint32(3 - class)})
		mustUpdate("opaque_real_second_policy", uint32(0), secondPolicy{uint32(3 - class), uint32(fallback), 1, 1})
		frozen = append(frozen, "opaque_real_live_second_route_gate", "opaque_real_second_policy")
	}
	if reload != "" {
		mustUpdate("opaque_real_second_policy", uint32(0), secondPolicy{uint32(class), uint32(reloadFallback[1]), 0, 1})
		frozen = append(frozen, "opaque_real_second_policy")
	}
	for _, name := range frozen {
		mustFreeze(name)
	}
	if code, _, err := c.Programs["opaque_real_live_bootstrap_control"].Test(make([]byte, 64)); err != nil || code != 0 {
		t.Fatalf("test-only control seed: code=%d err=%v", code, err)
	}
	if migrate {
		if code, _, err := c.Programs["opaque_real_live_bootstrap_second_route"].Test(make([]byte, 64)); err != nil || code != 0 {
			t.Fatalf("test-only second route seed: code=%d err=%v", code, err)
		}
	}
	if code, _, err := c.Programs["opaque_real_owner_policy_seed_diagnostic"].Test(make([]byte, 64)); err != nil || code != 0 {
		t.Fatalf("test-only %s policy seed: code=%d err=%v", map[int]string{1: "Audit", 2: "Strict"}[class], code, err)
	}
	if migrate || reload != "" {
		if code, _, err := c.Programs["opaque_real_owner_second_policy_seed"].Test(make([]byte, 64)); err != nil || code != 0 {
			t.Fatalf("test-only second policy seed: code=%d err=%v", code, err)
		}
	}
	for graph, program := range opaqueVerdictGraphs {
		mustUpdate(graph, uint32(0), c.Programs[program])
		mustFreeze(graph)
	}
	var locator uint64
	if err := c.Maps["se_route_index"].Lookup(st.Ino, &locator); err != nil || locator != uint64(1)<<32 {
		t.Fatalf("test-only route index: locator=%#x err=%v", locator, err)
	}
	if migrate {
		if err := c.Maps["se_route_index"].Lookup(migration.ino, &locator); err != nil || locator != uint64(1)<<32|1 {
			t.Fatalf("test-only second route index: locator=%#x err=%v", locator, err)
		}
	}
	attachLSM := func(name string) link.Link {
		t.Helper()
		l, err := link.AttachLSM(link.LSMOptions{Program: c.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		links = append(links, l)
		return l
	}
	attachLSM("opaque_real_owner_child_final_free_candidate")
	qualifyLink := attachLSM("opaque_real_live_bootstrap_qualify")
	birthLink := attachLSM("opaque_real_live_bootstrap_birth")
	timeout := 2 * time.Minute
	if births > 1 || threadChurn > 0 || concurrent > 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c",
		"echo $$ > \"$1/cgroup.procs\" || exit 97; \"$2\" <&0 & child=$!; wait \"$child\"",
		"ig15-real-verdict-launcher", cgroup, helper)
	invalid := filepath.Join(t.TempDir(), "invalid-executable")
	if err := os.WriteFile(invalid, []byte("invalid executable image\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), "IG_OPAQUE_FAIL_EXEC_PATH="+invalid, "IG_OPAQUE_PIDS_CGROUP="+cgroup)
	if migrate {
		cmd.Env = append(cmd.Env, "IG_OPAQUE_MIGRATE_CGROUP="+migration.path,
			"IG_OPAQUE_MIGRATE_SCRIPT="+migration.script, "IG_OPAQUE_MIGRATE_INTERP="+migration.interp)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatalf("seeded parent: line=%q err=%v stderr=%q", line, err, stderr.String())
	}
	if err := birthLink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := qualifyLink.Close(); err != nil {
		t.Fatal(err)
	}
	var physical, taskLocator uint64
	keys := c.Maps["se_opaque_keys"].Iterate()
	if !keys.Next(&physical, &taskLocator) || keys.Err() != nil || physical == 0 ||
		taskLocator == 0 || keys.Next(&physical, &taskLocator) {
		t.Fatalf("expected one real opaque TASK: err=%v", keys.Err())
	}
	kallsyms, err := os.Open("/proc/kallsyms")
	if err != nil {
		t.Fatal(err)
	}
	outer, err := opaqueDiagnosticExecOuterSymbol(kallsyms)
	if err == nil {
		_, err = kallsyms.Seek(0, io.SeekStart)
	}
	var handler string
	if err == nil {
		handler, err = opaqueDiagnosticExecHandlerSymbol(kallsyms, os.Getenv("IG_OPAQUE_REAL_LIVE_HANDLER_SYMBOL"))
	}
	kallsyms.Close()
	if err != nil {
		t.Fatalf("resolve diagnostic exec frames: %v", err)
	}
	attachKprobe := func(symbol, name string, ret bool) {
		t.Helper()
		var l link.Link
		var err error
		if ret {
			l, err = link.Kretprobe(symbol, c.Programs[name], nil)
		} else {
			l, err = link.Kprobe(symbol, c.Programs[name], nil)
		}
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		links = append(links, l)
	}
	attachKprobe(outer, "opaque_real_owner_failure_outer_exit", true)
	attachKprobe(handler, "opaque_real_owner_failure_handler_exit", true)
	attachKprobe(handler, "opaque_real_owner_failure_handler_enter", false)
	attachKprobe(outer, "opaque_real_owner_failure_outer_enter", false)
	for _, name := range append([]string{"opaque_real_owner_reader_success_probe",
		"opaque_real_owner_failure_fexit_probe"}, opaqueVerdictCapsuleOrder...) {
		l, err := link.AttachTracing(link.TracingOptions{Program: c.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		links = append(links, l)
	}
	attachLSM("opaque_real_owner_reader_begin_probe")

	v := &opaqueVerdictRun{t: t, c: c, spec: spec, stdin: stdin, stdout: reader,
		stderr: &stderr, parent: physical, parentLocator: taskLocator, class: class,
		fallback: fallback, cgroup: st.Ino, rules: rules, setRole: setRole}
	v.init()
	if _, err := stdin.Write([]byte("EXEC\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "AFTER\n" {
		v.dump("parent exec")
		_ = cmd.Wait()
		t.Fatalf("parent exec under class %d: line=%q err=%v exit=%v stderr=%q", class, line, err, cmd.ProcessState, stderr.String())
	}
	v.parentQualified("parent after its own verdict exec")
	// UID history: the bootstrap parent holds role 1 for policy uid 1. Its
	// allowed exec commits the matching rule's proposed role; every child
	// then carries it through birth projection.
	v.wantRole = 1
	if setRole != 0 {
		v.wantRole = uint64(setRole)
	}
	v.expectRole("parent after allowed exec", v.parent, v.parentLocator)
	v.settleRound("parent exec", 0)
	v.attachChildSource(attachLSM)

	strictDeny := class == 2 && fallback == 2
	v.child("euid 0 rule match", "FORK\n", 0, true)
	wantU := 0
	if strictDeny {
		wantU = 77
	}
	v.child("euid 1000 fallback", "FORKU\n", wantU, false)
	v.child("euid 0 after fallback (recoverable)", "FORK\n", 0, true)
	prior := attachOpaqueBirthPriorDenial(t, st.Ino)
	// The independent prior LSM returns -EACCES; the helper child exits 79
	// only for EACCES, so the preserved errno itself is asserted.
	v.child("prior LSM denial", "FORK\n", 79, false)
	if err := prior.Close(); err != nil {
		t.Fatal(err)
	}
	v.child("euid 0 after prior denial", "FORK\n", 0, true)
	v.child("allowed policy, failed exec (ENOEXEC)", "FORKF\n", 78, true)
	if os.Getenv("IG_OPAQUE_REAL_VERDICT_RACING") == "1" {
		// Previously RED (v4-6.12-racing-retry.log): racing births
		// exhausted the 8-credit WORK account. Birth now retries a lost
		// CONTENDED charge and the terminal completes into the evaluation
		// WORK (2 per child), so two racing children peak at 2+2*2 < 8.
		v.children("two racing births", "FORK2\n", 2, 0, true)
	}
	if reuseRace {
		v.reuseRace(reuseCPU)
	}
	for i := 0; i < births; i++ {
		v.child(fmt.Sprintf("churn %d", i), "FORK\n", 0, true)
		if i == 0 || (i+1)%512 == 0 || i == births-1 {
			t.Logf("ordinary selected-policy churn %d/%d: reuses=%d", i+1, births, v.reuses)
		}
	}
	if births > 4096 && v.reuses == 0 {
		t.Fatal("churn beyond 4096 births did not reuse a physical task address")
	}
	if threadChurn > 0 {
		// Each thread holds one birth WORK until reaped; the parent keeps
		// its retained WORKs, so a batch must fit the remaining quota.
		batch := min(4, int(v.workQuota)-len(v.parentWorks))
		if batch < 1 {
			t.Fatalf("parent retains %d of %d WORK credits: no room for a thread batch", len(v.parentWorks), v.workQuota)
		}
		reuses := v.reuses
		for done := 0; done < threadChurn; {
			n := min(batch, threadChurn-done)
			v.threads(fmt.Sprintf("thread churn %d", done), n)
			done += n
			if done == n || (done-n)/512 != done/512 || done == threadChurn {
				t.Logf("thread churn %d/%d: reuses=%d", done, threadChurn, v.reuses-reuses)
			}
		}
		if threadChurn > 4096 && v.reuses == reuses {
			t.Fatal("thread churn beyond 4096 births did not reuse a physical task address")
		}
		t.Logf("thread churn: %d pthread births in batches of %d, each exactly 1 TASK + 1 birth WORK, no evaluation or terminal, all refunded; %d physical reuses",
			threadChurn, batch, v.reuses-reuses)
	}
	if failedBirth {
		v.failedBirth(cgroup)
		v.child("euid 0 after failed birth", "FORK\n", 0, true)
	}
	if migrate {
		v.migrate(migration)
	}
	if reload != "" {
		v.reload(reloadRounds, reload == "fault", reloadFallback)
	}
	if concurrent > 0 {
		threadsPerRound := 0
		if threadChurn > 0 {
			threadsPerRound = 2
		}
		concurrentOpts.threadsPerRound = threadsPerRound
		v.concurrent(concurrent, concurrentOpts)
	}
	v.capsuleBalanced()
	t.Logf("child terminal outcomes resumed_completed=%d resumed_failed=%d fallback_charged=%d fallback_refused=%d",
		v.outcomes[0], v.outcomes[1], v.outcomes[2], v.outcomes[3])
	if _, err := stdin.Write([]byte("DONE\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v stderr=%q", err, stderr.String())
	}
	t.Logf("verdict class=%d fallback=%d rules=%d: %d children (+5 controls), %d physical reuses, WORK per outcome %v, parent never quarantined; synthetic test authority, not product Ready",
		class, fallback, rules, births, v.reuses, v.worksPerKind)
}

type opaqueVerdictRun struct {
	t                     *testing.T
	c                     *ebpf.Collection
	spec                  *ebpf.CollectionSpec
	stdin                 io.Writer
	stdout                *bufio.Reader
	stderr                *bytes.Buffer
	parent, parentLocator uint64
	class, fallback       int
	cgroup                uint64
	rules                 int
	setRole               int
	wantRole              uint64
	worksPerKind          map[string]int
	lastDeny              int
	taskType, metaType    *btf.Struct
	invocationType        *btf.Struct
	parentCookie          uint64
	parentWorks           map[uint32]uint64
	seen                  map[uint64]uint64
	reuses                int
	evals, matches        uint64
	outcomes              [4]uint64
	taskQuota, workQuota  uint32
}

type opaqueVerdictRefund struct {
	slot   uint32
	cookie uint64
}

func (v *opaqueVerdictRun) init() {
	if err := v.spec.Types.TypeByName("se_task_state", &v.taskType); err != nil {
		v.t.Fatal(err)
	}
	if err := v.spec.Types.TypeByName("se_ol_meta", &v.metaType); err != nil {
		v.t.Fatal(err)
	}
	if err := v.spec.Types.TypeByName("se_invocation", &v.invocationType); err != nil {
		v.t.Fatal(err)
	}
	// Per-account quotas (SE_PROFILE_TASK_QUOTA, SE_PROFILE_SCRATCH_QUOTA).
	for _, q := range []struct {
		charges, accounts string
		quota             *uint32
	}{{"se_opaque_charges", "se_opaque_accounts", &v.taskQuota},
		{"se_opaque_work_charges", "se_opaque_work_accounts", &v.workQuota}} {
		charges, accounts := v.spec.Maps[q.charges], v.spec.Maps[q.accounts]
		if charges == nil || accounts == nil || accounts.MaxEntries == 0 ||
			charges.MaxEntries%accounts.MaxEntries != 0 {
			v.t.Fatalf("verdict object lacks exact %s/%s geometry", q.charges, q.accounts)
		}
		*q.quota = charges.MaxEntries / accounts.MaxEntries
	}
	v.worksPerKind = map[string]int{}
	v.seen = map[uint64]uint64{}
	if err := v.c.Maps["opaque_birth_receipt_zero"].Freeze(); err != nil {
		v.t.Fatalf("freeze birth receipt zero template: %v", err)
	}
}

func (v *opaqueVerdictRun) field(root *btf.Struct, raw []byte, path ...string) uint64 {
	v.t.Helper()
	offset, size := opaqueSourceField(v.t, root, path)
	if offset+size > len(raw) {
		v.t.Fatalf("field %v outside value", path)
	}
	if size == 4 {
		return uint64(binary.LittleEndian.Uint32(raw[offset : offset+size]))
	}
	return binary.LittleEndian.Uint64(raw[offset : offset+size])
}

func (v *opaqueVerdictRun) charge(name string, slot uint32) uint64 {
	v.t.Helper()
	raw, err := v.c.Maps[name].LookupBytes(slot)
	if err != nil || len(raw) < 8 {
		v.t.Fatalf("%s slot %d: %v", name, slot, err)
	}
	return binary.LittleEndian.Uint64(raw[:8])
}

// task returns flags, cookie and whether reader/exec/receipt are settled.
func (v *opaqueVerdictRun) task(physical, locator uint64) (flags, cookie uint64, settled bool) {
	v.t.Helper()
	slot := uint32(locator & ((1 << 14) - 1))
	raw, err := v.c.Maps["se_opaque_payload"].LookupBytes(slot)
	if err != nil {
		v.t.Fatal(err)
	}
	settled = v.field(v.taskType, raw, "reader", "owned") == 0 &&
		v.field(v.taskType, raw, "exec", "owned") == 0
	var receipt [64]byte
	if err := v.c.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
		settled = false
	}
	return v.field(v.taskType, raw, "flags"), v.field(v.taskType, raw, "physical_cookie"), settled
}

func (v *opaqueVerdictRun) parentQualified(label string) {
	v.t.Helper()
	flags, cookie, settled := v.task(v.parent, v.parentLocator)
	if flags != 5 || !settled || cookie == 0 {
		v.t.Fatalf("%s: parent flags=%d settled=%v cookie=%d (5 = qualified, never quarantined)", label, flags, settled, cookie)
	}
	if v.parentCookie == 0 {
		v.parentCookie = cookie
	} else if cookie != v.parentCookie {
		v.t.Fatalf("%s: parent identity changed", label)
	}
}

func (v *opaqueVerdictRun) reap(kind string, slot uint32, cookie uint64) {
	v.t.Helper()
	request := struct {
		Cookie        uint64
		Slot, Enabled uint32
	}{cookie, slot, 1}
	if err := v.c.Maps["opaque_real_live_"+kind+"_reap_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
		v.t.Fatal(err)
	}
	for step := 0; step < 20; step++ {
		code, _, err := v.c.Programs["opaque_real_live_reap_"+kind].Test(make([]byte, 64))
		if err != nil {
			v.t.Fatal(err)
		}
		if kind == "work" && code == 1 || kind == "task" && code == 2 {
			return
		}
		if kind == "work" && code > 1 || kind == "task" && code >= 4 {
			v.t.Fatalf("exact %s reap rejected: slot=%d cookie=%d code=%d", kind, slot, cookie, code)
		}
	}
	v.t.Fatalf("exact %s credit not returned", kind)
}

// settleRound reaps every non-parent WORK and returns the count reaped.
func (v *opaqueVerdictRun) settleRound(label string, want int) int {
	v.t.Helper()
	works := 0
	for slot := uint32(0); slot < v.spec.Maps["se_opaque_work_charges"].MaxEntries; slot++ {
		cookie := v.charge("se_opaque_work_charges", slot)
		if cookie == 0 {
			continue
		}
		if v.parentWorks == nil {
			continue
		}
		if saved, ok := v.parentWorks[slot]; ok && saved == cookie {
			continue
		}
		works++
		// se_invocation is at payload offset 0 (static-asserted wire).
		if raw, err := v.c.Maps["se_opaque_work_payload"].LookupBytes(slot); err == nil && len(raw) > 0 {
			// A finished evaluation always carries a nonzero decision mode.
			if mode := int(v.field(v.invocationType, raw, "observation", "evaluator", "decision", "mode")); mode != 0 {
				deny := int(v.field(v.invocationType, raw, "observation", "evaluator", "decision", "deny"))
				v.lastDeny = deny*10 + mode
			}
		}
		v.reap("work", slot, cookie)
	}
	if v.parentWorks == nil {
		v.parentWorks = map[uint32]uint64{}
		for slot := uint32(0); slot < v.spec.Maps["se_opaque_work_charges"].MaxEntries; slot++ {
			if cookie := v.charge("se_opaque_work_charges", slot); cookie != 0 {
				v.parentWorks[slot] = cookie
			}
		}
		v.t.Logf("%s: parent retains %d completed WORK", label, len(v.parentWorks))
	} else if want >= 0 && works != want {
		v.t.Logf("%s: reaped %d child WORKs (diagnostic expectation %d)", label, works, want)
	}
	return works
}

func (v *opaqueVerdictRun) attachChildSource(attach func(string) link.Link) {
	v.t.Helper()
	if err := v.c.Maps["opaque_real_owner_child_targets"].Update(uint32(0),
		v.c.Programs["opaque_real_owner_child_target_candidate"], ebpf.UpdateAny); err != nil {
		v.t.Fatal(err)
	}
	if err := v.c.Maps["opaque_real_owner_child_targets"].Freeze(); err != nil {
		v.t.Fatal(err)
	}
	attach("opaque_real_owner_child_source_candidate")
	birth, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "sched_process_fork", Program: v.c.Programs["opaque_real_owner_successful_birth_candidate"],
	})
	if err != nil {
		v.t.Fatal(err)
	}
	v.t.Cleanup(func() { _ = birth.Close() })
	free, err := link.Kprobe("free_task", v.c.Programs["opaque_real_owner_birth_free_task_candidate"], nil)
	if err != nil {
		v.t.Fatal(err)
	}
	v.t.Cleanup(func() { _ = free.Close() })
}

// expectRole checks the committed UID history row for policy uid 1/epoch 1.
func (v *opaqueVerdictRun) expectRole(label string, physical, locator uint64) {
	v.t.Helper()
	slot := uint32(locator & ((1 << 14) - 1))
	raw, err := v.c.Maps["se_opaque_payload"].LookupBytes(slot)
	if err != nil {
		v.t.Fatal(err)
	}
	offset, _ := opaqueSourceField(v.t, v.taskType, []string{"committed", "rows"})
	const rowSize, rows = 32, 16
	found := 0
	for i := 0; i < rows; i++ {
		row := raw[offset+i*rowSize : offset+(i+1)*rowSize]
		uid, epoch := binary.LittleEndian.Uint64(row[0:]), binary.LittleEndian.Uint64(row[8:])
		role, knowledge := binary.LittleEndian.Uint64(row[16:]), binary.LittleEndian.Uint32(row[24:])
		if uid != 1 || epoch != 1 {
			continue
		}
		found++
		if role != v.wantRole || knowledge != 1 {
			v.t.Fatalf("%s: TASK %#x history uid 1 role=%d knowledge=%d, want known role %d", label, physical, role, knowledge, v.wantRole)
		}
	}
	if found != 1 {
		v.t.Fatalf("%s: TASK %#x has %d history rows for uid 1", label, physical, found)
	}
}

func (v *opaqueVerdictRun) windows() uint64 {
	v.t.Helper()
	var n uint64
	if err := v.c.Maps["opaque_real_owner_rule_windows"].Lookup(uint32(0), &n); err != nil {
		v.t.Fatal(err)
	}
	return n
}

func (v *opaqueVerdictRun) progress() (evals, matches uint64) {
	v.t.Helper()
	var p struct {
		StageBegin, RuleEval, Matched, ObservedUID int32
		RuleEvalCount, MatchedCount                uint64
	}
	if err := v.c.Maps["opaque_real_owner_rule_progress"].Lookup(uint32(0), &p); err != nil {
		v.t.Fatal(err)
	}
	return p.RuleEvalCount, p.MatchedCount
}

// child forks one helper child running command; wantExit is its exit code.
// evaluated reports whether the euid-0 rule must have matched.
// terminalOutcomes reads resumed_completed, resumed_failed, fallback_charged
// and fallback_refused from the terminal completion counter.
func (v *opaqueVerdictRun) terminalOutcomes() [4]uint64 {
	v.t.Helper()
	var out [4]uint64
	for i := range out {
		if err := v.c.Maps["opaque_real_terminal_outcomes"].Lookup(uint32(i), &out[i]); err != nil {
			v.t.Fatalf("terminal outcomes[%d]: %v", i, err)
		}
	}
	return out
}

func (v *opaqueVerdictRun) child(label, command string, wantExit int, matched bool) {
	v.t.Helper()
	v.children(label, command, 1, wantExit, matched)
}

// children runs a helper command producing n concurrently born children.
func (v *opaqueVerdictRun) children(label, command string, n, wantExit int, matched bool) {
	v.t.Helper()
	beforeEvals, beforeMatches := v.progress()
	beforeWindows := v.windows()
	beforeOutcomes := v.terminalOutcomes()
	v.lastDeny = -1
	if _, err := v.stdin.Write([]byte(command)); err != nil {
		v.t.Fatal(err)
	}
	for k := 0; k < n; k++ {
		line, err := v.stdout.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "FORKED:") ||
			!strings.HasSuffix(line, ":"+strconv.Itoa(wantExit)+"\n") {
			v.t.Fatalf("%s: line=%q want exit %d err=%v stderr=%q", label, line, wantExit, err, v.stderr.String())
		}
	}
	evals, matches := v.progress()
	windows := v.windows() - beforeWindows
	wantWindows := uint64(n * ((v.rules+15)/16 - 1))
	ruleZeroMatches := matched && v.rules == 1
	switch {
	case wantExit == 79: // earlier EACCES denial short-circuits: no evaluation
		if evals != beforeEvals || windows != 0 {
			v.t.Fatalf("%s: earlier denial still evaluated policy (%d -> %d, windows %d)", label, beforeEvals, evals, windows)
		}
	case windows != wantWindows:
		v.t.Fatalf("%s: rule windows %d, want %d for %d rules", label, windows, wantWindows, v.rules)
	case ruleZeroMatches:
		if evals != beforeEvals+uint64(n) || matches != beforeMatches+uint64(n) {
			v.t.Fatalf("%s: rule evaluation %d->%d matches %d->%d, want one matching evaluation",
				label, beforeEvals, evals, beforeMatches, matches)
		}
	default:
		if evals != beforeEvals+uint64(n) || matches != beforeMatches {
			v.t.Fatalf("%s: rule evaluation %d->%d matches %d->%d, want one non-matching evaluation",
				label, beforeEvals, evals, beforeMatches, matches)
		}
	}
	// Wait for the child's final free, then refund its TASK exactly.
	refunds := v.settleTasks(label, n)
	works := v.settleRound(label, -1)
	if works%n != 0 {
		v.t.Fatalf("%s: %d WORKs not divisible by %d children", label, works, n)
	}
	works /= n
	kind := map[bool]string{true: "allowed", false: "refused"}[wantExit == 0]
	switch wantExit {
	case 79:
		kind = "prior"
	case 78:
		kind = "failed-exec"
	}
	// Exact completed child WORKs per outcome: birth + evaluation, whose WORK
	// the exec terminal (success or failure) completes into instead of
	// charging a third. An earlier denial short-circuits evaluation and has
	// no receipt, so only the birth WORK remains.
	exactWorks := map[string]int{"allowed": 2, "refused": 2, "failed-exec": 2, "prior": 1}
	if works != exactWorks[kind] {
		v.t.Fatalf("%s: %d completed child WORKs for %s outcome, want %d", label, works, kind, exactWorks[kind])
	}
	v.worksPerKind[kind] = works
	// Every evaluated child's terminal must resume its evaluation WORK and
	// complete; an earlier denial has no terminal at all.
	afterOutcomes := v.terminalOutcomes()
	wantOutcomes := [4]uint64{uint64(n), 0, 0, 0}
	if kind == "prior" {
		wantOutcomes[0] = 0
	}
	for i := range afterOutcomes {
		delta := afterOutcomes[i] - beforeOutcomes[i]
		if delta != wantOutcomes[i] {
			v.t.Fatalf("%s: terminal outcome deltas %v -> %v, want %v for %s outcome",
				label, beforeOutcomes, afterOutcomes, wantOutcomes, kind)
		}
		v.outcomes[i] += delta
	}
	// Decision witness (deny*10+mode) from the evaluation WORK before reap;
	// terminal completion rewrites only its history/catalogue, not the
	// evaluator observation.
	switch {
	case wantExit == 79:
		if v.lastDeny != -1 {
			v.t.Fatalf("%s: earlier denial left an evaluation (%d)", label, v.lastDeny)
		}
	case matched || wantExit == 78:
		if v.lastDeny != v.class {
			v.t.Fatalf("%s: matched rule produced decision %d", label, v.lastDeny)
		}
	case v.fallback == 2:
		if v.lastDeny != 10+v.class {
			v.t.Fatalf("%s: fallback decision %d, want deny with mode %d", label, v.lastDeny, v.class)
		}
	case v.fallback == 1:
		if v.lastDeny != v.class {
			v.t.Fatalf("%s: fallback decision %d, want allow with mode %d", label, v.lastDeny, v.class)
		}
	}
	for _, r := range refunds {
		v.reap("task", r.slot, r.cookie)
	}
	v.parentQualified(label)
}

// settleTasks waits for the final free (DEAD, receipt retired) of the n
// non-parent TASKs and checks each is settled, unquarantined and carries the
// expected UID history. It returns their exact TASK refunds.
func (v *opaqueVerdictRun) settleTasks(label string, n int) []opaqueVerdictRefund {
	v.t.Helper()
	children := v.childTasks(label)
	if len(children) != n {
		v.t.Fatalf("%s: expected %d child TASKs, got %d", label, n, len(children))
	}
	var refunds []opaqueVerdictRefund
	for _, entry := range children {
		child, locator, slot := entry.physical, entry.locator, entry.slot
		v.finalFree(label, entry)
		flags, cookie, settled := v.task(child, locator)
		if !settled {
			raw, _ := v.c.Maps["se_opaque_payload"].LookupBytes(slot)
			var receipt [64]byte
			rerr := v.c.Maps["se_exec_terminal_receipts"].Lookup(child, &receipt)
			acct, _ := v.c.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
			v.t.Fatalf("%s: child not settled: flags=%d reader.owned=%d exec.owned=%d receipt=%v phase=%x work-account=%x",
				label, v.field(v.taskType, raw, "flags"), v.field(v.taskType, raw, "reader", "owned"),
				v.field(v.taskType, raw, "exec", "owned"), rerr == nil, receipt[56:64], acct[:min(len(acct), 16)])
		}
		if flags&2 != 0 {
			v.t.Fatalf("%s: child quarantined (flags=%d)", label, flags)
		}
		if old, ok := v.seen[child]; ok {
			v.reuses++
			if cookie <= old {
				v.t.Fatalf("%s: physical reuse kept stale identity", label)
			}
		}
		v.seen[child] = cookie
		v.expectRole(label, child, locator)
		refunds = append(refunds, opaqueVerdictRefund{slot, cookie})
	}
	return refunds
}

// opaqueChildTask is one charged non-parent TASK: its slot, its physical key
// (the slot's archive, wiped only by the reaper) and its locator.
type opaqueChildTask struct {
	slot              uint32
	physical, locator uint64
	cookie            uint64
}

// childTasks lists every charged non-parent TASK from the charges, not from
// se_opaque_keys: with the final-free withdrawal a dead child's directory
// key is already gone when its TASK is settled.
func (v *opaqueVerdictRun) childTasks(label string) []opaqueChildTask {
	v.t.Helper()
	var children []opaqueChildTask
	parentSlot := v.parentSlot()
	for slot := uint32(0); slot < v.spec.Maps["se_opaque_charges"].MaxEntries; slot++ {
		if slot == parentSlot {
			continue
		}
		cookie := v.charge("se_opaque_charges", slot)
		if cookie == 0 {
			continue
		}
		meta, err := v.c.Maps["se_opaque_meta"].LookupBytes(slot)
		if err != nil {
			v.t.Fatalf("%s: TASK meta %d: %v", label, slot, err)
		}
		var physical uint64
		if err := v.c.Maps["se_opaque_archive"].Lookup(slot, &physical); err != nil {
			v.t.Fatalf("%s: TASK archive %d: %v", label, slot, err)
		}
		locator := v.field(v.metaType, meta, "locator")
		// Only the reaper wipes the archive (ARCHIVE_ZEROED, then
		// REFUND_PENDING); a TASK it has not reached keeps its key bytes.
		phase := v.field(v.metaType, meta, "phase")
		wiped := physical == 0 && (phase == 7 || phase == 8)
		if (physical == 0 && !wiped) || uint32(locator&((1<<14)-1)) != slot || v.field(v.metaType, meta, "cookie") != cookie {
			v.t.Fatalf("%s: charged TASK slot %d has archive %#x locator %#x cookie %d (charge %d)",
				label, slot, physical, locator, v.field(v.metaType, meta, "cookie"), cookie)
		}
		children = append(children, opaqueChildTask{slot, physical, locator, cookie})
	}
	return children
}

// finalFree waits until the child's task_free callback has finished: DEAD,
// its death lease released and its terminal receipt retired (no terminal
// retry can run afterwards). The final-free withdrawal (in every object)
// leaves the directory entry exactly in the reaper's DELETED state.
func (v *opaqueVerdictRun) finalFree(label string, child opaqueChildTask) []byte {
	v.t.Helper()
	meta := v.waitFinalFree(label, child)
	v.withdrawn(label, child, meta)
	return meta
}

// waitFinalFree waits for finalFree's condition and returns the metadata.
func (v *opaqueVerdictRun) waitFinalFree(label string, child opaqueChildTask) []byte {
	v.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var receipt [64]byte
	for {
		meta, err := v.c.Maps["se_opaque_meta"].LookupBytes(child.slot)
		if err != nil {
			v.t.Fatal(err)
		}
		if len(meta) == 128 && v.field(v.metaType, meta, "phase") == opaqueTaskPhaseDead &&
			v.field(v.metaType, meta, "active_leases") == 0 &&
			errors.Is(v.c.Maps["se_exec_terminal_receipts"].Lookup(child.physical, &receipt), ebpf.ErrKeyNotExist) {
			return meta
		}
		if time.Now().After(deadline) {
			v.t.Fatalf("%s: child final-free not observed or terminal receipt survived it (phase=%x)",
				label, receipt[56:64])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// se_ol_directory_state (full/shared_pool_opaque_lookup_candidate.h) and
// SE_OL_DIR_DONE.
const (
	opaqueDirectoryPublished = 4
	opaqueDirectoryDeleted   = 7
	opaqueCleanupDirDone     = 16
)

// withdrawn checks the reaper-equivalent state the final free must leave:
// DELETED with DIR_DONE, no exclusive owner, and no directory key.
func (v *opaqueVerdictRun) withdrawn(label string, child opaqueChildTask, meta []byte) {
	v.t.Helper()
	var value uint64
	keyErr := v.c.Maps["se_opaque_keys"].Lookup(child.physical, &value)
	if v.field(v.metaType, meta, "directory_state") != opaqueDirectoryDeleted ||
		v.field(v.metaType, meta, "cleanup_done")&opaqueCleanupDirDone == 0 ||
		v.field(v.metaType, meta, "exclusive") != 0 || v.field(v.metaType, meta, "exclusive_owner") != 0 ||
		v.field(v.metaType, meta, "reader_holds") != 0 || !errors.Is(keyErr, ebpf.ErrKeyNotExist) {
		v.t.Fatalf("%s: final free of TASK %#x (slot %d) left directory_state=%d cleanup_done=%#x exclusive=%d owner=%#x reader_holds=%d key=%v, want DELETED, DIR_DONE, unowned, no key",
			label, child.physical, child.slot, v.field(v.metaType, meta, "directory_state"),
			v.field(v.metaType, meta, "cleanup_done"), v.field(v.metaType, meta, "exclusive"),
			v.field(v.metaType, meta, "exclusive_owner"), v.field(v.metaType, meta, "reader_holds"), keyErr)
	}
}

func (v *opaqueVerdictRun) parentSlot() uint32 {
	return uint32(v.parentLocator & ((1 << 14) - 1))
}

// accounts returns the used TASK and WORK credits of the parent's account;
// a faulted account fails the test.
func (v *opaqueVerdictRun) accounts(label string) (tasks, works uint32) {
	v.t.Helper()
	tasks, works, err := v.usedAccounts()
	if err != nil {
		v.t.Fatalf("%s: %v", label, err)
	}
	return tasks, works
}

// usedAccounts is accounts without failing the test (reaper goroutine).
func (v *opaqueVerdictRun) usedAccounts() (tasks, works uint32, err error) {
	account := v.parentSlot() / v.taskQuota
	for i, name := range []string{"se_opaque_accounts", "se_opaque_work_accounts"} {
		raw, err := v.c.Maps[name].LookupBytes(account)
		if err != nil || len(raw) < 12 {
			return 0, 0, fmt.Errorf("%s[%d]: %v", name, account, err)
		}
		// Layout: lock, used, fault, incarnation (static-asserted wires).
		if fault := binary.LittleEndian.Uint32(raw[8:12]); fault != 0 {
			return 0, 0, fmt.Errorf("%s[%d] faulted", name, account)
		}
		used := binary.LittleEndian.Uint32(raw[4:8])
		if i == 0 {
			tasks = used
		} else {
			works = used
		}
	}
	return tasks, works, nil
}

// threads runs n sequential pthread births in the parent. Each thread birth
// is the same source/target task_alloc as a process birth: exactly one
// charged TASK and one birth WORK (DONE at construction), no exec, so no
// evaluation WORK, rule window or terminal outcome. Final free marks the
// thread TASK DEAD; both credits return only through the exact reapers.
func (v *opaqueVerdictRun) threads(label string, n int) {
	v.t.Helper()
	beforeEvals, beforeMatches := v.progress()
	beforeWindows := v.windows()
	beforeOutcomes := v.terminalOutcomes()
	baseTasks, baseWorks := v.accounts(label)
	if _, err := fmt.Fprintf(v.stdin, "THREADS:%d\n", n); err != nil {
		v.t.Fatal(err)
	}
	if line, err := v.stdout.ReadString('\n'); err != nil || line != fmt.Sprintf("THREADED:%d:0\n", n) {
		v.t.Fatalf("%s: line=%q err=%v stderr=%q", label, line, err, v.stderr.String())
	}
	refunds := v.settleTasks(label, n)
	if tasks, works := v.accounts(label); tasks != baseTasks+uint32(n) || works != baseWorks+uint32(n) {
		v.t.Fatalf("%s: %d thread births charged TASK %d->%d WORK %d->%d, want exactly +1 each per thread",
			label, n, baseTasks, tasks, baseWorks, works)
	}
	v.lastDeny = -1
	if works := v.settleRound(label, -1); works != n {
		v.t.Fatalf("%s: reaped %d WORKs for %d thread births, want one birth WORK each", label, works, n)
	}
	if v.lastDeny != -1 {
		v.t.Fatalf("%s: thread birth WORK carried an evaluation decision %d", label, v.lastDeny)
	}
	evals, matches := v.progress()
	if evals != beforeEvals || matches != beforeMatches || v.windows() != beforeWindows ||
		v.terminalOutcomes() != beforeOutcomes {
		v.t.Fatalf("%s: thread births evaluated policy or produced a terminal outcome", label)
	}
	for _, r := range refunds {
		v.reap("task", r.slot, r.cookie)
	}
	v.parentQualified(label)
	if tasks, works := v.accounts(label); tasks != baseTasks || works != baseWorks {
		v.t.Fatalf("%s: account TASK %d WORK %d after refunds, want baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
	}
}

// failedBirth refuses one fork in cgroup_can_fork (pids.max == pids.current).
// copy_process has already run security_task_alloc, so the source/target
// charged a child TASK and birth WORK; the error path then runs
// security_task_free (final free: DEAD, receipt retired) and free_task.
func (v *opaqueVerdictRun) failedBirth(cgroup string) {
	v.t.Helper()
	label := "failed birth (pids.max)"
	retired := func() [2]uint64 {
		v.t.Helper()
		var out [2]uint64
		m := v.c.Maps["opaque_birth_failed_retired"]
		if m == nil {
			v.t.Fatal("verdict object lacks the opaque_birth_failed_retired witness")
		}
		for i := range out {
			if err := m.Lookup(uint32(i), &out[i]); err != nil {
				v.t.Fatal(err)
			}
		}
		return out
	}
	beforeRetired := retired()
	beforeEvals, beforeMatches := v.progress()
	beforeWindows := v.windows()
	beforeOutcomes := v.terminalOutcomes()
	baseTasks, baseWorks := v.accounts(label)
	pidsMax := filepath.Join(cgroup, "pids.max")
	original, err := os.ReadFile(pidsMax)
	if err != nil {
		v.t.Fatal(err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			if err := os.WriteFile(pidsMax, original, 0); err != nil {
				v.t.Errorf("restore %s: %v", pidsMax, err)
			}
		}
	}
	defer restore()
	current, err := os.ReadFile(filepath.Join(cgroup, "pids.current"))
	if err != nil {
		v.t.Fatal(err)
	}
	if err := os.WriteFile(pidsMax, bytes.TrimSpace(current), 0); err != nil {
		v.t.Fatal(err)
	}
	if _, err := v.stdin.Write([]byte("FORKA\n")); err != nil {
		v.t.Fatal(err)
	}
	line, err := v.stdout.ReadString('\n')
	restore()
	if want := fmt.Sprintf("FORKED:-1:%d\n", int(unix.EAGAIN)); err != nil || line != want {
		v.t.Fatalf("%s: line=%q want %q (pids.max=%q) err=%v stderr=%q",
			label, line, want, bytes.TrimSpace(current), err, v.stderr.String())
	}
	refunds := v.settleTasks(label, 1)
	if tasks, works := v.accounts(label); tasks != baseTasks+1 || works != baseWorks+1 {
		v.t.Fatalf("%s: failed birth charged TASK %d->%d WORK %d->%d, want exactly +1 each",
			label, baseTasks, tasks, baseWorks, works)
	}
	// security_task_free (lsm/task_free) runs before free_task and retires
	// the issued receipt that sched_process_fork never observed.
	if after := retired(); after[0]-beforeRetired[0] != 1 || after[1] != beforeRetired[1] {
		v.t.Fatalf("%s: failed-birth witness %v -> %v, want task_free path +1 and free_task path +0",
			label, beforeRetired, after)
	}
	v.lastDeny = -1
	if works := v.settleRound(label, -1); works != 1 {
		v.t.Fatalf("%s: reaped %d WORKs, want exactly the birth WORK", label, works)
	}
	evals, matches := v.progress()
	if v.lastDeny != -1 || evals != beforeEvals || matches != beforeMatches ||
		v.windows() != beforeWindows || v.terminalOutcomes() != beforeOutcomes {
		v.t.Fatalf("%s: failed birth evaluated policy or produced a terminal outcome", label)
	}
	v.reap("task", refunds[0].slot, refunds[0].cookie)
	v.parentQualified(label)
	if tasks, works := v.accounts(label); tasks != baseTasks || works != baseWorks {
		v.t.Fatalf("%s: account TASK %d WORK %d after refunds, want baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
	}
	v.worksPerKind["failed-birth"] = 1
	v.t.Logf("%s: fork EAGAIN after task_alloc; 1 TASK + 1 birth WORK refunded exactly; receipt retired by task_free", label)
}

// reapStep runs one exact reap visit without failing the test, so the
// independent reaper goroutine can use it.
func (v *opaqueVerdictRun) reapStep(kind string, slot uint32, cookie uint64) (uint32, error) {
	request := struct {
		Cookie        uint64
		Slot, Enabled uint32
	}{cookie, slot, 1}
	if err := v.c.Maps["opaque_real_live_"+kind+"_reap_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
		return 0, err
	}
	code, _, err := v.c.Programs["opaque_real_live_reap_"+kind].Test(make([]byte, 64))
	return code, err
}

type opaqueReaperStats struct {
	tasks, works, abortedWorks, abortedTasks int
	// Child TASKs reaped from DEAD with SE_TASK_QUARANTINED: a reader the
	// abort handoff quarantined after its evaluation WORK was refused.
	quarantinedTasks int
	// Charges whose reap started; later passes continue them regardless of
	// phase. Values are the exact cookies.
	workStarted, taskStarted map[uint32]uint64
	// TASK reaps started from ABORTED, keyed by slot (exact cookie in
	// taskStarted), so a reap continued by a later pass is still counted.
	taskAborted map[uint32]bool
	// Reaper latency (no BPF timestamp of the final free): deadSeen[slot]
	// holds the start of the previous pass (the final free came later) and
	// the moment this pass first saw DEAD. On return, reapLat samples
	// return - first seen DEAD and reapBound return - previous pass start,
	// an upper bound on final free -> credit return.
	deadSeen           map[uint32][2]time.Time
	lastPass           time.Time
	reapLat, reapBound []time.Duration
	taskHigh, workHigh uint32
}

// opaqueConcurrentOptions selects the concurrent-mode faults (G025).
type opaqueConcurrentOptions struct {
	streams, threadsPerRound int
	// abortEvery N > 0: every Nth child constructor takes the exact abort.
	abortEvery int
	// exhaust: no WORK backpressure; evaluation WORK may be refused.
	exhaust bool
	// failedBirths N > 0: N rounds add one fork refused by pids.max after
	// security_task_alloc, spread evenly over the rounds.
	failedBirths int
	// smallStorage: the object shrinks the deferred receipt/frame HASHes;
	// at least one insert must be refused, and each refusal fails closed.
	smallStorage bool
	// terminalStorage: only the terminal receipts are shrunk; a terminal
	// receipt insert must be refused and no other deferred insert.
	terminalStorage bool
	// contender: a TC completion contender races the real terminals.
	contender bool
	// reaperTick: the independent test reaper's period (default 2ms).
	reaperTick time.Duration
	// birthRate > 0: births/sec paced open loop by the helper (FORKP).
	birthRate int
	// requireNoReuseFailures: no constructor may lose to a DEAD
	// predecessor at its address (STALE/CONTENDED, replacement failures).
	requireNoReuseFailures bool
	// requireZeroFailClosed: the fail-closed rate witness must not move and
	// every forked child must be evaluated (the steady-state gate).
	requireZeroFailClosed bool
}

// se_exec_terminal_receipt.phase (offset 56): the real producer published
// SUCCESS or FAILURE and its completion has not yet retired the receipt.
const (
	opaqueReceiptPhaseOffset  = 56
	opaqueReceiptPhaseSuccess = 2
	opaqueReceiptPhaseFailure = 3
)

// opaqueContenderStats counts the late terminal contender's TC calls.
type opaqueContenderStats struct {
	calls, scans int
	err          error
}

// contend runs the test-only late terminal contender until stop closes: for
// every live child receipt whose real producer has published SUCCESS or
// FAILURE (its completion is in flight), it selects that physical key and
// runs opaque_real_owner_terminal_race_complete. Only one receipt can be
// selected at a time, so one goroutine drives it.
func (v *opaqueVerdictRun) contend(stop <-chan struct{}, s *opaqueContenderStats) {
	selector := v.c.Maps["opaque_real_owner_work_completion_selector"]
	program := v.c.Programs["opaque_real_owner_terminal_race_complete"]
	var keys []uint64
	for {
		select {
		case <-stop:
			return
		default:
		}
		s.scans++
		keys = keys[:0]
		var key uint64
		var receipt [64]byte
		it := v.c.Maps["se_exec_terminal_receipts"].Iterate()
		for it.Next(&key, &receipt) {
			phase := binary.LittleEndian.Uint32(receipt[opaqueReceiptPhaseOffset:])
			if key != v.parent && (phase == opaqueReceiptPhaseSuccess || phase == opaqueReceiptPhaseFailure) {
				keys = append(keys, key)
			}
		}
		// A key deleted during iteration only ends this scan early.
		if err := it.Err(); err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
			s.err = err
			return
		}
		for _, key := range keys {
			if err := selector.Update(uint32(0), key, ebpf.UpdateAny); err != nil {
				s.err = err
				return
			}
			if code, _, err := program.Test(make([]byte, 64)); err != nil || code != 0 {
				s.err = fmt.Errorf("contender test-run: code=%d err=%v", code, err)
				return
			}
			s.calls++
		}
	}
}

// se_ol_phase (full/shared_pool_opaque_lookup_candidate.h): DEAD after final
// free; ABORTED after an exact abort of a charged, unpublished constructor.
// A refused task_alloc never reaches task_free, so ABORTED is terminal.
const (
	opaqueTaskPhaseDead    = 2 // SE_OL_DEAD
	opaqueTaskPhaseAborted = 6 // SE_OL_ABORTED
)

// reapPass visits the parent's account once: WORK only from DONE/ABORTED
// (never the parent's retained WORKs), TASK only from DEAD/ABORTED (never
// the parent). A quarantined DEAD child is reaped and counted apart; an
// ABORTED TASK must still hold its charge OWNED. Reaper refusals (PENDING/STALE/ALREADY_RETURNED, or TASK
// EMPTY/PENDING) mean "not yet"; only a fault is an error.
func (v *opaqueVerdictRun) reapPass(s *opaqueReaperStats, flagsOffset, flagsSize int) error {
	account := v.parentSlot() / v.taskQuota
	prevPass := s.lastPass
	s.lastPass = time.Now()
	// High-water sample just before this pass returns anything.
	tasks, works, err := v.usedAccounts()
	if err != nil {
		return err
	}
	s.taskHigh, s.workHigh = max(s.taskHigh, tasks), max(s.workHigh, works)
	for slot := account * v.workQuota; slot < (account+1)*v.workQuota; slot++ {
		raw, err := v.c.Maps["se_opaque_work_charges"].LookupBytes(slot)
		if err != nil || len(raw) < 8 {
			return fmt.Errorf("WORK charge %d: %v", slot, err)
		}
		cookie := binary.LittleEndian.Uint64(raw[:8])
		if cookie == 0 || v.parentWorks[slot] == cookie {
			continue
		}
		aborted := false
		if s.workStarted[slot] != cookie {
			meta, err := v.c.Maps["se_opaque_work_meta"].LookupBytes(slot)
			if err != nil || len(meta) < 16 {
				return fmt.Errorf("WORK meta %d: %v", slot, err)
			}
			// se_owk_meta: lock, phase, cookie. 4 = DONE, 5 = ABORTED.
			phase := binary.LittleEndian.Uint32(meta[4:8])
			if (phase != 4 && phase != 5) || binary.LittleEndian.Uint64(meta[8:16]) != cookie {
				continue
			}
			aborted = phase == 5
			s.workStarted[slot] = cookie
		}
		for step := 0; ; step++ {
			code, err := v.reapStep("work", slot, cookie)
			if err != nil {
				return err
			}
			if code == 1 { // SE_OWK_RETURNED
				s.works++
				if aborted {
					s.abortedWorks++
				}
				delete(s.workStarted, slot)
				break
			}
			if code == 0 && step < 32 { // SE_OWK_PROGRESS
				continue
			}
			if code == 0 || code >= 5 { // SE_OWK_CORRUPT
				return fmt.Errorf("WORK slot %d cookie %d reap code %d", slot, cookie, code)
			}
			break // PENDING, STALE, ALREADY_RETURNED: not yet
		}
	}
	parentSlot := v.parentSlot()
	for slot := account * v.taskQuota; slot < (account+1)*v.taskQuota; slot++ {
		if slot == parentSlot {
			continue
		}
		raw, err := v.c.Maps["se_opaque_charges"].LookupBytes(slot)
		if err != nil || len(raw) < 40 {
			return fmt.Errorf("TASK charge %d: %v", slot, err)
		}
		cookie := binary.LittleEndian.Uint64(raw[:8])
		if cookie == 0 {
			continue
		}
		if s.taskStarted[slot] != cookie {
			meta, err := v.c.Maps["se_opaque_meta"].LookupBytes(slot)
			if err != nil || len(meta) < 24 {
				return fmt.Errorf("TASK meta %d: %v", slot, err)
			}
			// se_ol_meta: lock, phase, locator, cookie.
			phase := binary.LittleEndian.Uint32(meta[4:8])
			if (phase != opaqueTaskPhaseDead && phase != opaqueTaskPhaseAborted) ||
				binary.LittleEndian.Uint64(meta[16:24]) != cookie {
				continue
			}
			s.taskAborted[slot] = phase == opaqueTaskPhaseAborted
			// se_oc_charge: cookie, last_returned, scope, locator,
			// incarnation, state. The exact abort leaves it OWNED (2); a
			// FAULT_HELD charge would mean an inexact abort.
			if state := binary.LittleEndian.Uint32(raw[36:40]); phase == opaqueTaskPhaseAborted && state != 2 {
				return fmt.Errorf("ABORTED TASK slot %d cookie %d charge state %d, want OWNED (2)", slot, cookie, state)
			}
			payload, err := v.c.Maps["se_opaque_payload"].LookupBytes(slot)
			if err != nil || len(payload) < flagsOffset+flagsSize {
				return fmt.Errorf("TASK payload %d: %v", slot, err)
			}
			flags := uint64(binary.LittleEndian.Uint32(payload[flagsOffset:]))
			if flagsSize == 8 {
				flags = binary.LittleEndian.Uint64(payload[flagsOffset:])
			}
			if flags&2 != 0 {
				if phase != opaqueTaskPhaseDead {
					return fmt.Errorf("ABORTED child TASK slot %d cookie %d quarantined (flags=%d)", slot, cookie, flags)
				}
				s.quarantinedTasks++
			}
			s.taskStarted[slot] = cookie
			if phase == opaqueTaskPhaseDead {
				s.deadSeen[slot] = [2]time.Time{prevPass, time.Now()}
			}
		}
		for step := 0; ; step++ {
			code, err := v.reapStep("task", slot, cookie)
			if err != nil {
				return err
			}
			if code == 2 { // SE_OR_RETURNED
				s.tasks++
				if seen, ok := s.deadSeen[slot]; ok {
					now := time.Now()
					s.reapLat = append(s.reapLat, now.Sub(seen[1]))
					if !seen[0].IsZero() {
						s.reapBound = append(s.reapBound, now.Sub(seen[0]))
					}
					delete(s.deadSeen, slot)
				}
				if s.taskAborted[slot] {
					s.abortedTasks++
				}
				delete(s.taskStarted, slot)
				delete(s.taskAborted, slot)
				break
			}
			if code == 1 && step < 32 { // SE_OR_PROGRESS
				continue
			}
			if code == 1 || code >= 4 { // SE_OR_FAULT
				return fmt.Errorf("TASK slot %d cookie %d reap code %d", slot, cookie, code)
			}
			break // EMPTY, PENDING: not yet
		}
	}
	return nil
}

// concurrent runs births racing children (k = streams per round, plus
// threadsPerRound pthread births while they run) with no per-round reaping.
// A reaper goroutine on its own ticker returns credits independently. A
// transiently full WORK account may make a Strict birth or exec fail closed
// (fork EPERM, exit 77); those are counted and reported, never leaked.
// opts.abortEvery injects exact constructor aborts; opts.exhaust drops the
// WORK backpressure so evaluation WORK refusals quarantine their readers.
func (v *opaqueVerdictRun) concurrent(births int, opts opaqueConcurrentOptions) {
	v.t.Helper()
	label := "concurrent"
	streams, threadsPerRound := opts.streams, opts.threadsPerRound
	strict := v.class == 2
	baseTasks, baseWorks := v.accounts(label)
	beforeEvals, beforeMatches := v.progress()
	beforeWindows := v.windows()
	beforeOutcomes := v.terminalOutcomes()
	beforeBirths := v.birthOutcomes(label)
	// Test-only witnesses; absent from objects built without them.
	abortCounts := v.c.Maps["opaque_real_abort_counts"]
	evalWitness := v.c.Maps["opaque_real_eval_work_outcomes"]
	if opts.abortEvery > 0 && abortCounts == nil {
		v.t.Fatalf("%s: abort injection needs an object built with ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC", label)
	}
	if opts.exhaust && evalWitness == nil {
		v.t.Fatalf("%s: WORK exhaustion needs an object built with ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC", label)
	}
	storageWitness := v.c.Maps["opaque_real_deferred_storage_refusals"]
	raceWitness := v.c.Maps["opaque_real_terminal_race_witness"]
	if opts.smallStorage && storageWitness == nil {
		v.t.Fatalf("%s: small storage needs ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC", label)
	}
	if opts.contender && raceWitness == nil {
		v.t.Fatalf("%s: the terminal contender needs ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC", label)
	}
	beforeAborts := v.counters(label, abortCounts, 3)
	beforeEvalWork := v.counters(label, evalWitness, 5)
	beforeStorage := v.counters(label, storageWitness, 5)
	beforeRetired := v.counters(label, v.c.Maps["opaque_birth_failed_retired"], 2)
	replaceWitness := v.c.Maps["opaque_real_replace_failures"]
	if opts.requireNoReuseFailures && replaceWitness == nil {
		v.t.Fatalf("%s: REQUIRE_NO_REUSE_FAILURES needs ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC", label)
	}
	beforeReplace := v.counters(label, replaceWitness, 4)
	// Product-visible fail-closed rate witness (decision 3); absent from
	// objects built without ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE.
	rateWitness := v.c.Maps["opaque_real_fail_closed_rates"]
	if opts.requireZeroFailClosed && rateWitness == nil {
		v.t.Fatalf("%s: REQUIRE_ZERO_FAIL_CLOSED needs ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE: a missing witness is unknown, never zero", label)
	}
	beforeRates := v.counters(label, rateWitness, FailClosedRateCounters)
	// Race witness: attempts, commits, inflight, overlap, authenticated,
	// auth_inflight, auth_overlap (struct of seven u64).
	raceCounters := func() [7]uint64 {
		var out [7]uint64
		if raceWitness != nil {
			raw, err := raceWitness.LookupBytes(uint32(0))
			if err != nil || len(raw) < 56 {
				v.t.Fatalf("%s: terminal race witness: %v", label, err)
			}
			for i := range out {
				out[i] = binary.LittleEndian.Uint64(raw[8*i:])
			}
		}
		return out
	}
	beforeRace := raceCounters()
	setAbortEvery := func(n int) {
		if abortCounts != nil {
			if err := v.c.Maps["opaque_real_abort_every"].Update(uint32(0), uint32(n), ebpf.UpdateAny); err != nil {
				v.t.Fatalf("%s: abort selector: %v", label, err)
			}
		}
	}
	setAbortEvery(opts.abortEvery)
	defer setAbortEvery(0)
	flagsOffset, flagsSize := opaqueSourceField(v.t, v.taskType, []string{"flags"})
	stats := &opaqueReaperStats{workStarted: map[uint32]uint64{}, taskStarted: map[uint32]uint64{},
		taskAborted: map[uint32]bool{}, deadSeen: map[uint32][2]time.Time{}}
	var reaperErr error
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(opts.reaperTick)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
			if err := v.reapPass(stats, flagsOffset, flagsSize); err != nil {
				reaperErr = err
				return
			}
		}
	}()
	stopped := false
	stopReaper := func() {
		if !stopped {
			stopped = true
			close(stop)
			<-done
		}
	}
	defer stopReaper()
	// The late terminal contender runs only while children are born and
	// complete; it is stopped (and disarmed) before quiescence.
	contender := &opaqueContenderStats{}
	contenderStopped := true
	stopContender := func() {}
	if opts.contender {
		if err := v.c.Maps["opaque_real_owner_work_completion_gate"].Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
			v.t.Fatalf("%s: arm contender: %v", label, err)
		}
		cstop, cdone := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(cdone)
			v.contend(cstop, contender)
		}()
		contenderStopped = false
		stopContender = func() {
			if !contenderStopped {
				contenderStopped = true
				close(cstop)
				<-cdone
				if err := v.c.Maps["opaque_real_owner_work_completion_gate"].Update(uint32(0), uint32(0), ebpf.UpdateAny); err != nil {
					v.t.Errorf("%s: disarm contender: %v", label, err)
				}
			}
		}
	}
	defer stopContender()
	exits, forkRefused, threadErrs := map[int]int{}, map[int]int{}, map[int]int{}
	threadsOK, threadsFailed := 0, 0
	// Failed births: errno of each refused fork, and any that unexpectedly
	// succeeded (exit code).
	failedErrno, failedBorn := map[int]int{}, map[int]int{}
	taskHigh, workHigh := baseTasks, baseWorks // sampled used high-water marks
	failing := 0
	if opts.failedBirths > 0 {
		failing = 1
	}
	// Each child needs a birth and an evaluation WORK, each thread and a
	// failed birth a birth WORK. A round must fit the WORK account next to
	// the retained baseline, or a child's evaluation WORK is refused and its
	// exec reader quarantined (fail closed), which this test must never
	// provoke. With opts.exhaust the round is not fitted and no room is
	// awaited: a refused evaluation WORK must quarantine the child.
	perRound := streams
	if !opts.exhaust {
		perRound = min(streams, (int(v.workQuota)-int(baseWorks)-threadsPerRound-failing)/2)
	}
	if perRound < 1 {
		v.t.Fatalf("%s: WORK quota %d cannot fit one child + %d threads + %d failed births next to %d retained WORKs",
			label, v.workQuota, threadsPerRound, failing, baseWorks)
	}
	rounds := (births + perRound - 1) / perRound
	failEvery := 1
	if opts.failedBirths > 0 {
		if opts.failedBirths > rounds {
			v.t.Fatalf("%s: %d failed births need at least as many rounds (%d)", label, opts.failedBirths, rounds)
		}
		failEvery = rounds / opts.failedBirths
	}
	failedSent := 0
	// Birth pacing (opts.birthRate): one FORKP command; the helper forks on
	// its own absolute schedule and reports each child as it is reaped.
	var pacedSpan, pacedMaxLate, pacedSumLate time.Duration
	pacedWaits := 0
	sendStart := time.Now()
	if opts.birthRate > 0 {
		interval := time.Second / time.Duration(opts.birthRate)
		if _, err := fmt.Fprintf(v.stdin, "FORKP:%d:%d:%d\n", births, streams, interval.Nanoseconds()); err != nil {
			v.t.Fatal(err)
		}
		for i := 0; i < births; i++ {
			line, err := v.stdout.ReadString('\n')
			var pid, code int
			if err != nil {
				v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
			}
			if n, _ := fmt.Sscanf(line, "FORKED:%d:%d\n", &pid, &code); n != 2 {
				v.t.Fatalf("%s: line=%q", label, line)
			}
			if pid < 0 {
				forkRefused[code]++
			} else {
				exits[code]++
			}
			tasks, works := v.accounts(label)
			taskHigh, workHigh = max(taskHigh, tasks), max(workHigh, works)
			if (i+1)%512 == 0 || i+1 == births {
				v.t.Logf("%s: %d/%d paced births reported", label, i+1, births)
			}
		}
		line, err := v.stdout.ReadString('\n')
		var span, maxLate, sumLate int64
		if err != nil {
			v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
		}
		if n, _ := fmt.Sscanf(line, "PACED:%d:%d:%d:%d\n", &span, &maxLate, &sumLate, &pacedWaits); n != 4 || span < 0 {
			v.t.Fatalf("%s: line=%q", label, line)
		}
		pacedSpan, pacedMaxLate, pacedSumLate = time.Duration(span), time.Duration(maxLate), time.Duration(sumLate)
	}
	for sent, round := 0, 0; opts.birthRate == 0 && sent < births; round++ {
		k := min(perRound, births-sent)
		f := 0
		if failedSent < opts.failedBirths && round%failEvery == 0 {
			f = 1
		}
		// Backpressure only (read-only): wait for the reaper to make room for
		// this round's 2 WORKs per child and 1 per thread or failed birth.
		roomy := opts.exhaust
		for deadline := time.Now().Add(10 * time.Second); !roomy && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			tasks, works := v.accounts(label)
			taskHigh, workHigh = max(taskHigh, tasks), max(workHigh, works)
			if int(works)+2*k+threadsPerRound+f <= int(v.workQuota) {
				roomy = true
				break
			}
		}
		if !roomy {
			v.t.Fatalf("%s: reaper made no WORK room for a %d-child round in 10s", label, k)
		}
		command := fmt.Sprintf("FORKN:%d:%d\n", k, threadsPerRound)
		if f == 1 {
			command = fmt.Sprintf("FORKN:%d:%d:1\n", k, threadsPerRound)
		}
		if _, err := io.WriteString(v.stdin, command); err != nil {
			v.t.Fatal(err)
		}
		for i := 0; i < k; i++ {
			line, err := v.stdout.ReadString('\n')
			var pid, code int
			if err != nil {
				v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
			}
			if n, _ := fmt.Sscanf(line, "FORKED:%d:%d\n", &pid, &code); n != 2 {
				v.t.Fatalf("%s: line=%q", label, line)
			}
			if pid < 0 {
				forkRefused[code]++
			} else {
				exits[code]++
			}
		}
		if f == 1 {
			line, err := v.stdout.ReadString('\n')
			var pid, code int
			if err != nil {
				v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
			}
			if n, _ := fmt.Sscanf(line, "FAILBIRTH:%d:%d\n", &pid, &code); n != 2 {
				v.t.Fatalf("%s: line=%q", label, line)
			}
			if pid < 0 {
				failedErrno[code]++
			} else {
				failedBorn[code]++
			}
			failedSent++
		}
		line, err := v.stdout.ReadString('\n')
		var created, threadErr int
		if err != nil {
			v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
		}
		if n, _ := fmt.Sscanf(line, "THREADED:%d:%d\n", &created, &threadErr); n != 2 ||
			created < 0 || created > threadsPerRound || (created < threadsPerRound) != (threadErr != 0) {
			v.t.Fatalf("%s: line=%q", label, line)
		}
		if tasks, _ := v.accounts(label); tasks > taskHigh {
			taskHigh = tasks
		}
		threadsOK += created
		threadsFailed += threadsPerRound - created
		if threadErr != 0 {
			threadErrs[threadErr]++
		}
		sent += k
		if (sent-k)/512 != sent/512 || sent == births {
			v.t.Logf("%s: %d/%d births sent", label, sent, births)
		}
	}
	// Achieved birth rate: paced, (births-1) over the helper's first..last
	// fork span; back to back, births over the Go-side send time.
	sendSpan := time.Since(sendStart)
	achieved := float64(births) / sendSpan.Seconds()
	if opts.birthRate > 0 {
		achieved = 0
		if births > 1 && pacedSpan > 0 {
			achieved = float64(births-1) / pacedSpan.Seconds()
		}
		v.t.Logf("%s: paced births: target %d/s achieved %.1f/s over %s; fork start late max %s mean %s; %d births waited for the %d-stream cap",
			label, opts.birthRate, achieved, pacedSpan, pacedMaxLate, pacedSumLate/time.Duration(births), pacedWaits, streams)
	}
	// No constructor may be aborted after the last birth: the injected count
	// below is then final. Every child of the last round has completed, so
	// the late contender has nothing left to race.
	setAbortEvery(0)
	stopContender()
	// Quiesce: the helper is idle; only the reaper may return the credits.
	quiesced := false
	for deadline := time.Now().Add(time.Minute); !quiesced && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		select {
		case <-done:
			deadline = time.Now()
			continue
		default:
		}
		tasks, works := v.accounts(label)
		quiesced = tasks == baseTasks && works == baseWorks
	}
	stopReaper()
	taskHigh, workHigh = max(taskHigh, stats.taskHigh), max(workHigh, stats.workHigh)
	// Every check below reports; the test fails once all were reported, so
	// a quiesce/leak failure never hides a formula failure or vice versa.
	failed := false
	fail := func(format string, args ...any) {
		failed = true
		v.t.Errorf(format, args...)
	}
	if reaperErr != nil {
		fail("%s: reaper: %v", label, reaperErr)
	}
	tasks, works := v.accounts(label)
	evals, matches := v.progress()
	evaluated := evals - beforeEvals
	afterBirths := v.birthOutcomes(label)
	var out [8]uint64
	for i := range out {
		out[i] = afterBirths[i] - beforeBirths[i]
	}
	sourceRefusals, constructOK := out[0], out[1]
	constructFailures := out[2] + out[3] + out[4] + out[5]
	// out[7]: the source could not issue the test-only birth receipt (its
	// HASH is sized to SE_PROFILE_TASKS, and receipts of unconstructed Audit
	// children live until their RCU-deferred free), so it finished the birth
	// WORK without the target: Strict refuses, Audit runs it unconstructed.
	missingTarget := out[7]
	forked, refused := 0, 0
	for _, n := range exits {
		forked += n
	}
	for _, n := range forkRefused {
		refused += n
	}
	failedAttempts, failedBornN := 0, 0
	for _, n := range failedErrno {
		failedAttempts += n
	}
	for _, n := range failedBorn {
		failedBornN += n
	}
	failedAttempts += failedBornN
	// A Strict failed birth refused by our task_alloc (EPERM) never reaches
	// cgroup_can_fork; every EAGAIN passed security_task_alloc.
	eagain, failedEPERM := uint64(failedErrno[int(unix.EAGAIN)]), uint64(failedErrno[int(unix.EPERM)])
	attempts := uint64(forked + refused + threadsOK + threadsFailed + failedAttempts)
	deadTasks := uint64(stats.tasks - stats.abortedTasks)
	// Witness deltas (zero when the object lacks the witness).
	afterAborts := v.counters(label, abortCounts, 3)
	afterEvalWork := v.counters(label, evalWitness, 5)
	afterStorage := v.counters(label, storageWitness, 5)
	afterRetired := v.counters(label, v.c.Maps["opaque_birth_failed_retired"], 2)
	afterReplace := v.counters(label, replaceWitness, 4)
	var replaceFailures [4]uint64
	for i := range replaceFailures {
		replaceFailures[i] = afterReplace[i] - beforeReplace[i]
	}
	afterRace := raceCounters()
	var aborts [3]uint64
	var evalWork, storage [5]uint64
	var retired [2]uint64
	var race [7]uint64
	for i := range aborts {
		aborts[i] = afterAborts[i] - beforeAborts[i]
	}
	for i := range evalWork {
		evalWork[i] = afterEvalWork[i] - beforeEvalWork[i]
		storage[i] = afterStorage[i] - beforeStorage[i]
	}
	for i := range retired {
		retired[i] = afterRetired[i] - beforeRetired[i]
	}
	for i := range race {
		race[i] = afterRace[i] - beforeRace[i]
	}
	// Deferred storage refusals that quarantine a verdict reader (its exec
	// is then never evaluated: Strict 77, Audit unevaluated): a refused
	// terminal receipt [0] and failure frames that were not ready [4].
	storageQuarantined := storage[0] + storage[4]
	outcomeDelta := v.terminalOutcomes()
	for i := range outcomeDelta {
		outcomeDelta[i] -= beforeOutcomes[i]
	}
	// Transient WORKs a late completion charged (FALLBACK_CHARGED): each
	// is DONE at once and reaped like any other.
	fallbackCharged := outcomeDelta[2]
	abortEdges, injected, exactAborts := aborts[0], aborts[1], aborts[2]
	evalEntered, evalRefused := evalWork[0], evalWork[1]
	evalChargedFailed, handoffQuarantined, handoffFailed := evalWork[2], evalWork[3], evalWork[4]
	v.t.Logf("%s: %d births (%d streams, %d threads/round): exits %v, fork refusals by errno %v, threads ok=%d failed=%d errs %v; evaluated=%d; source start_work refusals=%d; construct ok=%d stale=%d contended=%d limit=%d corrupt=%d unattempted=%d unconstructed-done=%d; reaper returned TASK=%d (aborted %d) WORK=%d (aborted %d); TASK used high-water %d/%d (baseline %d)",
		label, births, streams, threadsPerRound, exits, forkRefused, threadsOK, threadsFailed, threadErrs,
		evaluated, sourceRefusals, out[1], out[2], out[3], out[4], out[5], out[6], out[7],
		stats.tasks, stats.abortedTasks, stats.works, stats.abortedWorks, taskHigh, v.taskQuota, baseTasks)
	v.t.Logf("%s: abort injection every %d: %d edges, %d injected, %d exact aborts (%d natural); evaluation WORK: entered=%d refused=%d charged-failed=%d; abort handoff quarantined=%d failed=%d; reaper quarantined DEAD TASKs=%d; exhaust=%v",
		label, opts.abortEvery, abortEdges, injected, exactAborts, exactAborts-min(injected, exactAborts),
		evalEntered, evalRefused, evalChargedFailed, handoffQuarantined, handoffFailed, stats.quarantinedTasks, opts.exhaust)
	v.t.Logf("%s: failed births %d: refused by errno %v, unexpectedly born %v; failed-birth receipts retired task_free=%d free_task=%d; deferred storage refusals: terminal receipt=%d outer frame=%d handler frame=%d birth receipt=%d frames-not-ready quarantine=%d (small=%v)",
		label, failedAttempts, failedErrno, failedBorn, retired[0], retired[1],
		storage[0], storage[1], storage[2], storage[3], storage[4], opts.smallStorage)
	if opts.contender {
		v.t.Logf("%s: terminal contender: %d scans, %d calls; race witness attempts=%d commits=%d overlap=%d authenticated=%d auth_overlap=%d inflight=%d auth_inflight=%d; terminal outcomes %v",
			label, contender.scans, contender.calls, race[0], race[1], race[3], race[4], race[6],
			afterRace[2], afterRace[5], outcomeDelta)
	}
	v.t.Logf("%s: physical reuse: construct stale=%d contended=%d; replacement failures (observe/read/hold/claim) %v (witness=%v)",
		label, out[2], out[3], replaceFailures, replaceWitness != nil)
	if opts.requireNoReuseFailures && (out[2]+out[3] != 0 || replaceFailures != [4]uint64{}) {
		fail("%s: %d STALE + %d CONTENDED constructors and replacement failures %v, want none with the final-free withdrawal",
			label, out[2], out[3], replaceFailures)
	}
	if !quiesced {
		fail("%s: account TASK %d WORK %d never returned to baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
		v.leaks(label)
	}
	for code, n := range exits {
		if code != 0 && !(strict && code == 77) {
			fail("%s: %d children exited %d", label, n, code)
		}
	}
	for errno, n := range forkRefused {
		if !strict || errno != int(unix.EPERM) {
			fail("%s: %d forks refused with errno %d", label, n, errno)
		}
	}
	for errno, n := range threadErrs {
		if !strict || (errno != int(unix.EPERM) && errno != int(unix.EAGAIN)) {
			fail("%s: %d thread rounds failed with %d", label, n, errno)
		}
	}
	if out[6] != 0 {
		fail("%s: %d births never reached the constructor", label, out[6])
	}
	// Each attempted birth charges one source WORK unless start_work refused
	// it uncharged; the target completes it whatever the constructor status.
	// Each evaluation adds one WORK (the terminal completes into it).
	// A refused evaluation start_work charges nothing (witness [1]; a
	// failure after a charge, [2], must not occur), so the formula counts
	// only evaluations that ran: entered == evaluated + refused.
	// A late completion that found the evaluation WORK already consumed
	// charges one transient WORK (FALLBACK_CHARGED), also returned.
	if want := attempts - sourceRefusals + evaluated + fallbackCharged; uint64(stats.works) != want {
		fail("%s: reaper returned %d WORKs, want %d attempts - %d source refusals + %d evaluations + %d transient terminal WORKs = %d",
			label, stats.works, attempts, sourceRefusals, evaluated, fallbackCharged, want)
	}
	// Published children reap from DEAD; a TASK charged by a failed
	// constructor is aborted exactly and reaps from ABORTED.
	if deadTasks != constructOK || uint64(stats.abortedTasks) > constructFailures {
		fail("%s: reaper returned %d DEAD + %d ABORTED TASKs for %d constructed and %d failed constructors",
			label, deadTasks, stats.abortedTasks, constructOK, constructFailures)
	}
	if abortCounts != nil {
		// Exact: every ABORTED reap is one exact semantic abort, which is
		// either injected or a natural replacement loss (natural =
		// exact - injected, logged above). The injector selects exactly
		// every Nth edge, and an injected constructor reports CORRUPT.
		if uint64(stats.abortedTasks) != exactAborts || exactAborts < injected {
			fail("%s: reaper returned %d ABORTED TASKs, want %d exact aborts (%d injected + natural)",
				label, stats.abortedTasks, exactAborts, injected)
		}
		if every := uint64(opts.abortEvery); every > 0 &&
			(injected != afterAborts[0]/every-beforeAborts[0]/every || injected == 0) {
			fail("%s: %d aborts injected for %d fault edges every %d", label, injected, abortEdges, opts.abortEvery)
		}
		if out[5] < injected {
			fail("%s: %d injected aborts but %d CORRUPT constructors", label, injected, out[5])
		}
	}
	// A refused evaluation WORK quarantines the child's reader through the
	// exact abort handoff, which retires the receipt: the child then has no
	// terminal, Strict denies its exec (77) and Audit runs it unevaluated.
	// The quarantined DEAD child is reaped like any other.
	// A refused terminal receipt or unready failure frame quarantines the
	// reader before evaluation (no handoff, no terminal).
	if uint64(stats.quarantinedTasks) != evalRefused+storageQuarantined || handoffQuarantined != evalRefused ||
		evalChargedFailed != 0 || handoffFailed != 0 {
		fail("%s: %d quarantined DEAD TASKs and %d exact abort handoffs (%d failed) for %d evaluation WORK refusals (%d failed after charge) + %d deferred storage quarantines",
			label, stats.quarantinedTasks, handoffQuarantined, handoffFailed, evalRefused, evalChargedFailed, storageQuarantined)
	}
	// Deferred storage: a refused birth receipt makes the source finish the
	// birth WORK without the target (counted in out[7]); unready frames
	// come only from refused frame inserts here. A small-storage run must
	// actually have refused at least one insert.
	if storage[3] > missingTarget || storage[4] > storage[1]+storage[2] {
		fail("%s: deferred storage refusals %v exceed %d missing targets / %d refused frame inserts",
			label, storage, missingTarget, storage[1]+storage[2])
	}
	if opts.smallStorage && storage[0]+storage[1]+storage[2]+storage[3] == 0 {
		fail("%s: small-storage run refused no deferred insert", label)
	}
	// Terminal-only small storage (step 4b): the terminal receipt refusal
	// must be reached and the full-size frames never refuse. Full-size
	// birth receipts can still overflow naturally while TASK is saturated
	// (Audit unconstructed births keep their receipt until free_task); each
	// such refusal must be exactly one missing target (out[7]). Every
	// terminal refusal is a storage quarantine counted exactly in the
	// quarantine, Strict-77 and Audit-unevaluated formulas.
	if opts.terminalStorage && (storage[0] == 0 || storage[1]|storage[2]|storage[4] != 0 || storage[3] != missingTarget) {
		fail("%s: terminal-only small storage refusals %v, want terminal receipt [0] > 0, [1] == [2] == [4] == 0 and birth receipt [3] == %d missing targets",
			label, storage, missingTarget)
	}
	// Failed births: only pids.max EAGAIN, or (Strict only) our own EPERM
	// refusal before cgroup_can_fork; none may be born. Every receipt the
	// task_free path retired unobserved is a failed birth, never free_task.
	for errno, n := range failedErrno {
		if errno != int(unix.EAGAIN) && !(strict && errno == int(unix.EPERM)) {
			fail("%s: %d failed births refused with errno %d", label, n, errno)
		}
	}
	if failedBornN != 0 || failedAttempts != opts.failedBirths {
		fail("%s: %d of %d failed births sent, %d born (%v)", label, failedAttempts, opts.failedBirths, failedBornN, failedBorn)
	}
	if retired[1] != 0 || retired[0] > eagain {
		fail("%s: failed-birth receipts retired task_free=%d free_task=%d for %d EAGAIN births", label, retired[0], retired[1], eagain)
	}
	if evalWitness != nil && evalEntered != evaluated+evalRefused {
		fail("%s: %d evaluations entered, want %d evaluated + %d refused", label, evalEntered, evaluated, evalRefused)
	}
	if !opts.exhaust && uint64(stats.quarantinedTasks) != storageQuarantined {
		fail("%s: backpressure run quarantined %d children, %d by deferred storage", label, stats.quarantinedTasks, storageQuarantined)
	}
	born := uint64(forked + threadsOK)
	if strict {
		// Every allowed Strict child was evaluated exactly once; every exit
		// 77 is a fail-closed refusal that never reached evaluation.
		if uint64(exits[0]) != evaluated {
			fail("%s: %d children allowed but %d evaluated: unexpected Strict denial", label, exits[0], evaluated)
		}
		if uint64(exits[77]) != evalRefused+storageQuarantined {
			fail("%s: %d Strict exits 77, want %d evaluation WORK refusals + %d deferred storage quarantines",
				label, exits[77], evalRefused, storageQuarantined)
		}
		// A Strict source refusal or failed constructor refuses the birth;
		// a failed birth that reached cgroup_can_fork (EAGAIN) was
		// constructed and its unobserved receipt retired by task_free.
		if born+eagain != constructOK {
			fail("%s: %d Strict births (%d forks + %d threads) + %d failed births (EAGAIN) for %d constructed TASKs",
				label, born, forked, threadsOK, eagain, constructOK)
		}
		if retired[0] != eagain {
			fail("%s: %d Strict failed births (EAGAIN) but %d receipts retired by task_free", label, eagain, retired[0])
		}
		if got := uint64(forkRefused[int(unix.EPERM)]+threadsFailed) + failedEPERM; got != constructFailures+sourceRefusals+missingTarget {
			fail("%s: %d EPERM fork refusals + %d thread failures + %d failed births (EPERM), want %d failed constructors + %d source refusals + %d missing targets",
				label, forkRefused[int(unix.EPERM)], threadsFailed, failedEPERM, constructFailures, sourceRefusals, missingTarget)
		}
	} else {
		// Audit never refuses (checked above): a source refusal or failed
		// constructor leaves an unconstructed, unevaluated birth, and a
		// refused evaluation WORK an unevaluated child.
		// Every Audit failed birth reaches cgroup_can_fork (EAGAIN). The
		// constructed ones are exactly those whose unobserved receipt
		// task_free retired; the rest are unconstructed failed births.
		unconstructed := constructFailures + sourceRefusals + missingTarget
		if born+eagain < constructOK || born+eagain-constructOK != unconstructed {
			fail("%s: %d Audit births (%d forks + %d threads) + %d failed births, %d constructed, want %d unconstructed",
				label, born, forked, threadsOK, eagain, constructOK, unconstructed)
		}
		unconstructedFailed := eagain - min(retired[0], eagain)
		quarantined := evalRefused + storageQuarantined
		if evaluated > uint64(exits[0]) || deadTasks > born+eagain || unconstructedFailed > unconstructed {
			fail("%s: Audit evaluated %d of %d children, returned %d DEAD TASKs for %d births + %d failed births (%d unconstructed of %d)",
				label, evaluated, exits[0], deadTasks, born, eagain, unconstructedFailed, unconstructed)
		} else if unevaluated := uint64(exits[0]) - evaluated; (threadsPerRound == 0 && unevaluated != unconstructed-unconstructedFailed+quarantined) ||
			unevaluated > unconstructed-unconstructedFailed+quarantined {
			fail("%s: %d Audit children unevaluated, want %d unconstructed births - %d unconstructed failed births + %d evaluation refusals + %d deferred storage quarantines (%d threads/round)",
				label, unevaluated, unconstructed, unconstructedFailed, evalRefused, storageQuarantined, threadsPerRound)
		}
	}
	if v.rules == 1 && matches-beforeMatches != evaluated {
		fail("%s: %d evaluations but %d euid-0 rule matches", label, evaluated, matches-beforeMatches)
	}
	if windows := v.windows() - beforeWindows; windows != evaluated*uint64((v.rules+15)/16-1) {
		fail("%s: rule windows %d for %d evaluations of %d rules", label, windows, evaluated, v.rules)
	}
	// Only an evaluated child has a terminal: a quarantined child's receipt
	// was retired by its exact handoff (handoffFailed == 0 above), so no
	// fallback WORK is charged or refused for it.
	// Exactly one resumed commit per evaluated receipt, whoever wins it.
	// Without the contender no late completion exists; with it, a loser
	// either charged a transient WORK (counted in the WORK formula above) or
	// was refused before any charge.
	afterOutcomes := v.terminalOutcomes()
	wantOutcomes := [4]uint64{evaluated, 0, 0, 0}
	if opts.contender {
		wantOutcomes[2], wantOutcomes[3] = outcomeDelta[2], outcomeDelta[3]
	}
	for i := range afterOutcomes {
		delta := afterOutcomes[i] - beforeOutcomes[i]
		if delta != wantOutcomes[i] {
			fail("%s: terminal outcome deltas %v -> %v, want %v", label, beforeOutcomes, afterOutcomes, wantOutcomes)
			break
		}
	}
	if opts.contender {
		// Contender calls are exactly the witness attempts; its commits are
		// a subset of the one commit per receipt; nothing is left inside.
		if contender.err != nil {
			fail("%s: contender: %v", label, contender.err)
		}
		if race[0] != uint64(contender.calls) || race[1] > evaluated || race[1] > outcomeDelta[0] ||
			afterRace[2] != 0 || afterRace[5] != 0 {
			fail("%s: race witness attempts=%d commits=%d inflight=%d auth_inflight=%d for %d contender calls and %d evaluated receipts",
				label, race[0], race[1], afterRace[2], afterRace[5], contender.calls, evaluated)
		}
	} else if raceWitness != nil && race[0] != 0 {
		fail("%s: %d contender attempts without a contender", label, race[0])
	}
	for i := range afterOutcomes {
		v.outcomes[i] += afterOutcomes[i] - beforeOutcomes[i]
	}
	// Decision 3 witness: refusal and unevaluated rates at this quota,
	// concurrency and reaper latency.
	pct := func(n, d uint64) float64 {
		if d == 0 {
			return 0
		}
		return 100 * float64(n) / float64(d)
	}
	unconstructedBirths := constructFailures + sourceRefusals + missingTarget
	if strict {
		refusals := uint64(refused+threadsFailed) + uint64(exits[77])
		v.t.Logf("%s: Strict rates: births refused %.1f%% (%d/%d), evaluation WORK refused %.1f%% (%d/%d), total fail-closed refusals %.1f%% (%d/%d)",
			label, pct(uint64(refused+threadsFailed), attempts), refused+threadsFailed, attempts,
			pct(evalRefused, evalEntered), evalRefused, evalEntered, pct(refusals, attempts), refusals, attempts)
	} else {
		unevaluated := uint64(exits[0]) - min(evaluated, uint64(exits[0]))
		v.t.Logf("%s: Audit rates: births unconstructed %.1f%% (%d/%d), evaluation WORK refused %.1f%% (%d/%d), children unevaluated %.1f%% (%d/%d)",
			label, pct(unconstructedBirths, attempts), unconstructedBirths, attempts,
			pct(evalRefused, evalEntered), evalRefused, evalEntered, pct(unevaluated, uint64(exits[0])), unevaluated, exits[0])
	}
	// The product-visible witness must count exactly the fail-closed
	// outcomes the test-only witnesses saw, class by class.
	afterRates := v.counters(label, rateWitness, FailClosedRateCounters)
	var rateBefore, rateAfter [FailClosedRateClasses]uint64
	copy(rateBefore[:], beforeRates)
	copy(rateAfter[:], afterRates)
	retryExhausted := afterRates[FailClosedRateWorkRetry] - beforeRates[FailClosedRateWorkRetry]
	rates, rateErr := FailClosedRate(rateBefore, rateAfter, attempts, 0)
	if rateErr != nil {
		fail("%s: fail-closed rate witness: %v", label, rateErr)
	}
	if rateWitness != nil {
		// The eval-WORK and storage classes have an independent expected
		// value only with their test-only witness; without it the slot
		// prints "na" and is skipped, never derived from the value under
		// test.
		want := [FailClosedRateClasses]uint64{out[4], sourceRefusals, missingTarget,
			evalRefused + evalChargedFailed, storageQuarantined, out[2] + out[3] + out[5] + out[6]}
		known := [FailClosedRateClasses]bool{true, true, true,
			evalWitness != nil, storageWitness != nil, true}
		wantText := make([]string, FailClosedRateClasses)
		match := true
		for i := range want {
			wantText[i] = "na"
			if known[i] {
				wantText[i] = strconv.FormatUint(want[i], 10)
				match = match && rates.Failures[i] == want[i]
			}
		}
		if !match {
			fail("%s: fail-closed rate witness %v, want [LIMIT source missing-target eval-WORK storage construct] %v",
				label, rates.Failures, wantText)
		}
		// Retry-bound exhaustions are refusals already counted as a source
		// or evaluation refusal, or a refused terminal fallback.
		if retryExhausted > rates.Failures[1]+rates.Failures[3]+outcomeDelta[3] {
			fail("%s: %d WORK retry-bound exhaustions exceed %d source + %d evaluation refusals + %d refused fallbacks",
				label, retryExhausted, rates.Failures[1], rates.Failures[3], outcomeDelta[3])
		}
		if rates.Degraded != (rates.Total != 0) {
			fail("%s: fail-closed rate verdict %+v: degraded must follow any nonzero witness delta", label, rates)
		}
	}
	// One machine-greppable line per run for the requalification rate
	// table. refused: Strict births refused, Audit births unconstructed (per
	// attempt). unevaluated: forked children never evaluated (per fork
	// attempt). eval_refused: evaluation WORK refused per entry (na without
	// the witness). witness: the fail-closed rate witness deltas (na without
	// the candidate) and its degraded verdict at threshold 0.
	forkAttempts := uint64(forked + refused)
	refusedBirths := uint64(refused + threadsFailed)
	if !strict {
		refusedBirths = unconstructedBirths
	}
	evalRate, witness := "na", "na"
	if evalWitness != nil {
		evalRate = fmt.Sprintf("%.1f%%", pct(evalRefused, evalEntered))
	}
	if rateWitness != nil {
		witness = fmt.Sprintf("%d/%d/%d/%d/%d/%d retry_exhausted=%d degraded=%v", rates.Failures[0], rates.Failures[1],
			rates.Failures[2], rates.Failures[3], rates.Failures[4], rates.Failures[5], retryExhausted, rates.Degraded)
	}
	// fail_closed: every fail-closed outcome (Strict: refused births + exit
	// 77; Audit: unconstructed births + quarantined readers). rate:
	// target/achieved births/sec (b2b: back to back). task_high/work_high:
	// sampled used high-water marks / quota. reap_lat: reaper first saw
	// DEAD -> TASK credit returned; reap_bound: previous pass start -> TASK
	// credit returned (upper bound on final free -> return); p50/p99/max.
	failClosed := refusedBirths + uint64(exits[77])
	if !strict {
		failClosed = unconstructedBirths + evalRefused + storageQuarantined
	}
	target := "b2b"
	if opts.birthRate > 0 {
		target = strconv.Itoa(opts.birthRate)
	}
	quantiles := func(d []time.Duration) string {
		if len(d) == 0 {
			return "na"
		}
		slices.Sort(d)
		return fmt.Sprintf("%s/%s/%s", d[len(d)/2], d[min(len(d)-1, len(d)*99/100)], d[len(d)-1])
	}
	v.t.Logf("RATE quota=%d/%d streams=%d threads=%d exhaust=%v class=%d refused=%.1f%% unevaluated=%.1f%% eval_refused=%s reaper_tick=%s attempts=%d births=%d evaluated=%d witness=%s rate=%s/%.1f fail_closed=%d task_high=%d/%d work_high=%d/%d reap_lat=%s reap_bound=%s",
		v.taskQuota, v.workQuota, streams, threadsPerRound, opts.exhaust, v.class,
		pct(refusedBirths, attempts), pct(forkAttempts-min(evaluated, forkAttempts), forkAttempts), evalRate,
		opts.reaperTick, attempts, forkAttempts, evaluated, witness, target, achieved, failClosed,
		taskHigh, v.taskQuota, workHigh, v.workQuota, quantiles(stats.reapLat), quantiles(stats.reapBound))
	if opts.requireZeroFailClosed {
		unevaluated := forkAttempts - min(evaluated, forkAttempts)
		if rates.Total != 0 || retryExhausted != 0 || failClosed != 0 || unevaluated != 0 {
			fail("%s: steady-state gate: witness fail_closed=%d (%v, retry_exhausted=%d), test fail_closed=%d, unevaluated=%d of %d forks, want all 0",
				label, rates.Total, rates.Failures, retryExhausted, failClosed, unevaluated, forkAttempts)
		}
		v.t.Logf("%s: steady-state gate: witness fail_closed=0 unevaluated=0 over %d births (%d evaluated)",
			label, forkAttempts, evaluated)
	}
	for slot, cookie := range v.parentWorks {
		if v.charge("se_opaque_work_charges", slot) != cookie {
			fail("%s: parent retained WORK slot %d was reaped", label, slot)
		}
	}
	var key, value uint64
	keys := v.c.Maps["se_opaque_keys"].Iterate()
	for keys.Next(&key, &value) {
		if key != v.parent {
			fail("%s: child TASK %#x survived quiescence", label, key)
		}
	}
	if keys.Err() != nil {
		fail("%s: %v", label, keys.Err())
	}
	var receipt [64]byte
	receipts := v.c.Maps["se_exec_terminal_receipts"].Iterate()
	for receipts.Next(&key, &receipt) {
		if key != v.parent {
			fail("%s: child terminal receipt %#x (phase %d) survived quiescence", label, key,
				binary.LittleEndian.Uint32(receipt[opaqueReceiptPhaseOffset:]))
		}
	}
	if receipts.Err() != nil {
		fail("%s: %v", label, receipts.Err())
	}
	if failed {
		v.dump(label)
		v.t.FailNow()
	}
	v.parentQualified(label)
	v.t.Logf("%s: %d Strict fail-closed exits (77) and %d refused forks under transient WORK exhaustion; %d Audit unevaluated children; every child TASK/WORK refunded exactly",
		label, exits[77], forkRefused[int(unix.EPERM)], uint64(exits[0])-min(evaluated, uint64(exits[0])))
}

// counters reads n uint64 cells of a test-only witness ARRAY; a nil map (an
// object built without that witness) reads as zeros.
func (v *opaqueVerdictRun) counters(label string, m *ebpf.Map, n int) []uint64 {
	v.t.Helper()
	out := make([]uint64, n)
	if m == nil {
		return out
	}
	for i := range out {
		if err := m.Lookup(uint32(i), &out[i]); err != nil {
			v.t.Fatalf("%s: witness %d: %v", label, i, err)
		}
	}
	return out
}

// birthOutcomes reads the test-only birth accounting witness (see
// opaque_birth_outcomes in the candidate object).
func (v *opaqueVerdictRun) birthOutcomes(label string) [8]uint64 {
	v.t.Helper()
	m := v.c.Maps["opaque_birth_outcomes"]
	if m == nil {
		v.t.Fatalf("%s: verdict object lacks the opaque_birth_outcomes witness", label)
	}
	var out [8]uint64
	for i := range out {
		if err := m.Lookup(uint32(i), &out[i]); err != nil {
			v.t.Fatalf("%s: opaque_birth_outcomes[%d]: %v", label, i, err)
		}
	}
	return out
}

// leaks logs every charged TASK slot of the parent's account (charge,
// se_ol_meta and se_opaque_keys membership) and every non-parent WORK
// charge, after the account failed to return to its baseline.
func (v *opaqueVerdictRun) leaks(label string) {
	v.t.Helper()
	var chargeType *btf.Struct
	if err := v.spec.Types.TypeByName("se_oc_charge", &chargeType); err != nil {
		v.t.Errorf("%s: %v", label, err)
		return
	}
	keyed := map[uint64]uint64{} // locator -> physical key
	var key, value uint64
	keys := v.c.Maps["se_opaque_keys"].Iterate()
	for keys.Next(&key, &value) {
		keyed[value] = key
	}
	if keys.Err() != nil {
		v.t.Logf("%s: se_opaque_keys: %v", label, keys.Err())
	}
	account := v.parentSlot() / v.taskQuota
	for slot := account * v.taskQuota; slot < (account+1)*v.taskQuota; slot++ {
		raw, err := v.c.Maps["se_opaque_charges"].LookupBytes(slot)
		if err != nil {
			v.t.Logf("%s: TASK charge %d: %v", label, slot, err)
			continue
		}
		cookie := v.field(chargeType, raw, "cookie")
		if cookie == 0 {
			continue
		}
		meta, err := v.c.Maps["se_opaque_meta"].LookupBytes(slot)
		if err != nil {
			v.t.Logf("%s: TASK meta %d: %v", label, slot, err)
			continue
		}
		locator := v.field(v.metaType, meta, "locator")
		physical, inKeys := keyed[locator]
		v.t.Logf("%s: TASK slot %d parent=%v charge cookie=%d state=%d; meta phase=%d cookie=%d locator=%#x active_leases=%d exclusive=%d directory_state=%d cleanup_done=%#x cleanup_error=%d; se_opaque_keys holds=%v (%#x)",
			label, slot, slot == v.parentSlot(), cookie, v.field(chargeType, raw, "state"),
			v.field(v.metaType, meta, "phase"), v.field(v.metaType, meta, "cookie"), locator,
			v.field(v.metaType, meta, "active_leases"), v.field(v.metaType, meta, "exclusive"),
			v.field(v.metaType, meta, "directory_state"), v.field(v.metaType, meta, "cleanup_done"),
			v.field(v.metaType, meta, "cleanup_error"), inKeys, physical)
	}
	for slot := account * v.workQuota; slot < (account+1)*v.workQuota; slot++ {
		raw, err := v.c.Maps["se_opaque_work_charges"].LookupBytes(slot)
		if err != nil || len(raw) < 8 {
			continue
		}
		cookie := binary.LittleEndian.Uint64(raw[:8])
		if cookie == 0 || v.parentWorks[slot] == cookie {
			continue
		}
		meta, _ := v.c.Maps["se_opaque_work_meta"].LookupBytes(slot)
		phase := uint32(0)
		if len(meta) >= 8 {
			phase = binary.LittleEndian.Uint32(meta[4:8])
		}
		v.t.Logf("%s: WORK slot %d charge cookie=%d meta phase=%d", label, slot, cookie, phase)
	}
}

// dump logs the diagnostic witnesses after an unexpected outcome.
func (v *opaqueVerdictRun) dump(label string) {
	v.t.Helper()
	var p struct {
		StageBegin, RuleEval, Matched, ObservedUID int32
		RuleEvalCount, MatchedCount                uint64
	}
	_ = v.c.Maps["opaque_real_owner_rule_progress"].Lookup(uint32(0), &p)
	v.t.Logf("%s: rule progress %+v", label, p)
	if raw, err := v.c.Maps["se_exec_capsule_stats"].LookupBytes(uint32(0)); err == nil {
		var stats [14]uint64
		for i := range stats {
			stats[i] = binary.LittleEndian.Uint64(raw[8*i:])
		}
		v.t.Logf("%s: capsule stats %v", label, stats)
	}
	slot := uint32(v.parentLocator & ((1 << 14) - 1))
	if raw, err := v.c.Maps["se_opaque_payload"].LookupBytes(slot); err == nil {
		v.t.Logf("%s: parent flags=%d reader.owned=%d exec.owned=%d", label,
			v.field(v.taskType, raw, "flags"), v.field(v.taskType, raw, "reader", "owned"),
			v.field(v.taskType, raw, "exec", "owned"))
	}
	var receipt [64]byte
	err := v.c.Maps["se_exec_terminal_receipts"].Lookup(v.parent, &receipt)
	v.t.Logf("%s: parent receipt present=%v", label, err == nil)
	if raw, err := v.c.Maps["opaque_real_owner_policy_witness"].LookupBytes(uint32(0)); err == nil {
		v.t.Logf("%s: policy witness %x", label, raw)
	}
}

func (v *opaqueVerdictRun) capsuleBalanced() {
	v.t.Helper()
	raw, err := v.c.Maps["se_exec_capsule_stats"].LookupBytes(uint32(0))
	if err != nil {
		v.t.Fatal(err)
	}
	var stats [14]uint64
	for i := range stats {
		stats[i] = binary.LittleEndian.Uint64(raw[8*i:])
	}
	v.t.Logf("capsule stats begin=%d frozen=%d pinned=%d original_claim=%d terminal=%d foreign=%d success=%d release_fault=%d fault=%d pin_failed=%d",
		stats[0], stats[3], stats[5], stats[7], stats[8], stats[9], stats[10], stats[12], stats[13], stats[6])
	if stats[12] != 0 || stats[13] != 0 || stats[6] != 0 {
		v.t.Fatal("capsule faults recorded")
	}
	for slot := uint32(0); slot < uint32(v.spec.Maps["se_routes"].MaxEntries); slot++ {
		route, err := v.c.Maps["se_routes"].LookupBytes(slot)
		if err != nil || len(route) != 104 {
			v.t.Fatalf("route %d: len=%d err=%v", slot, len(route), err)
		}
		if early, pins, latch := binary.LittleEndian.Uint32(route[64:]), binary.LittleEndian.Uint32(route[96:]),
			binary.LittleEndian.Uint32(route[100:]); early|pins|latch != 0 {
			v.t.Fatalf("route %d unbalanced: early=%d pins=%d unresolved=%d", slot, early, pins, latch)
		}
	}
}

// reuseRace (IG_OPAQUE_REAL_VERDICT_REUSE_RACE=1, G025 batch F) drives the
// physical-reuse collision deterministically. On one pinned CPU (SLUB per-CPU
// freelists are LIFO) a predecessor P is born and dies without exec; after
// its final free the directory entry must already be DELETED with no key.
// One exact reaper visit then emulates a reaper in the middle of P's
// withdrawal: without the fix it claims (WITHDRAW_CLAIM) and the newborn at
// P's address loses to it (CONTENDED, refused); with it, it only wipes the
// archive. Children are forked until one reuses P's address (each child that
// does not becomes the next predecessor, so the freelist head is always the
// latest dead TASK), at most opaqueReuseAttempts. The colliding child must
// construct with a newer cookie, unquarantined; every TASK cookie is
// returned exactly once; no constructor is STALE/CONTENDED and no
// replacement-failure site fires; the account returns to its baseline.
// Then the fallback: a reader hold taken while LIVE makes the final-free
// withdrawal refuse, and the reaper path completes exactly once after it.
const opaqueReuseAttempts = 4096

func (v *opaqueVerdictRun) reuseRace(cpu int) {
	v.t.Helper()
	label := "physical reuse race"
	if left := v.childTasks(label); len(left) != 0 {
		v.t.Fatalf("%s: %d child TASKs still charged before the race", label, len(left))
	}
	replaceWitness := v.c.Maps["opaque_real_replace_failures"]
	beforeReplace := v.counters(label, replaceWitness, 4)
	beforeBirths := v.birthOutcomes(label)
	baseTasks, baseWorks := v.accounts(label)
	v.pin(label, cpu)
	births := 0
	fork := func() opaqueChildTask {
		v.t.Helper()
		before := map[uint32]bool{}
		for _, c := range v.childTasks(label) {
			before[c.slot] = true
		}
		if _, err := io.WriteString(v.stdin, "FORKE\n"); err != nil {
			v.t.Fatal(err)
		}
		line, err := v.stdout.ReadString('\n')
		var pid, code int
		if n, _ := fmt.Sscanf(line, "FORKED:%d:%d\n", &pid, &code); err != nil || n != 2 || pid <= 0 || code != 0 {
			v.t.Fatalf("%s: birth %d refused or failed: line=%q err=%v (a constructor that lost to a DEAD predecessor is refused) stderr=%q",
				label, births+1, line, err, v.stderr.String())
		}
		births++
		var born []opaqueChildTask
		for _, c := range v.childTasks(label) {
			if !before[c.slot] {
				born = append(born, c)
			}
		}
		if len(born) != 1 {
			v.t.Fatalf("%s: birth %d (pid %d) charged %d new TASKs, want exactly 1", label, births, pid, len(born))
		}
		return born[0]
	}
	midWithdrawal := func(c opaqueChildTask) {
		v.t.Helper()
		if code, err := v.reapStep("task", c.slot, c.cookie); err != nil || code != 1 {
			v.t.Fatalf("%s: one reaper visit of TASK %#x cookie %d: code=%d err=%v, want PROGRESS", label, c.physical, c.cookie, code, err)
		}
	}
	retire := func(c opaqueChildTask) {
		v.t.Helper()
		v.settleRound(label, -1)
		v.reapOnce(label, c)
	}
	prev := fork()
	v.finalFree(label, prev)
	midWithdrawal(prev)
	reuses, attempts := 0, 0
	for reuses == 0 && attempts < opaqueReuseAttempts {
		attempts++
		c := fork()
		v.finalFree(label, c)
		flags, cookie, settled := v.task(c.physical, c.locator)
		if flags&2 != 0 || !settled || cookie != c.cookie {
			v.t.Fatalf("%s: TASK %#x flags=%d settled=%v cookie=%d (charge %d), want unquarantined and settled",
				label, c.physical, flags, settled, cookie, c.cookie)
		}
		if c.physical == prev.physical {
			if c.cookie <= prev.cookie || c.slot == prev.slot {
				v.t.Fatalf("%s: reuse of %#x kept a stale identity: cookie %d slot %d after cookie %d slot %d",
					label, c.physical, c.cookie, c.slot, prev.cookie, prev.slot)
			}
			reuses++
			v.reuses++
			v.t.Logf("%s: attempt %d: TASK %#x reused by cookie %d (slot %d) while its predecessor cookie %d (slot %d) was unreaped",
				label, attempts, c.physical, c.cookie, c.slot, prev.cookie, prev.slot)
		}
		retire(prev)
		prev = c
		midWithdrawal(prev)
	}
	retire(prev)
	if reuses == 0 {
		v.t.Fatalf("%s: no physical reuse in %d births pinned to CPU %d (set IG_OPAQUE_REAL_VERDICT_REUSE_CPU to an idle CPU)",
			label, attempts, cpu)
	}
	afterBirths := v.birthOutcomes(label)
	var outcomes [8]uint64
	for i := range outcomes {
		outcomes[i] = afterBirths[i] - beforeBirths[i]
	}
	if want := [8]uint64{1: uint64(births)}; outcomes != want {
		v.t.Fatalf("%s: birth outcomes %v for %d births, want every constructor OK (%v)", label, outcomes, births, want)
	}
	afterReplace := v.counters(label, replaceWitness, 4)
	for i := range afterReplace {
		if afterReplace[i] != beforeReplace[i] {
			v.t.Fatalf("%s: replacement failures %v -> %v, want none", label, beforeReplace, afterReplace)
		}
	}
	if tasks, works := v.accounts(label); tasks != baseTasks || works != baseWorks {
		v.t.Fatalf("%s: account TASK %d WORK %d after exact refunds, want baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
	}
	v.t.Logf("%s: %d births on CPU %d, reuse after %d attempts; every constructor OK, every TASK cookie returned once, replacement failures 0",
		label, births, cpu, attempts)
	v.reuseFallback(label)
	v.pin(label, -1)
	v.parentQualified(label)
}

// reuseFallback: a reader hold on a LIVE child makes its final-free
// withdrawal refuse; the state stays PUBLISHED and the reaper completes the
// withdrawal exactly once after the hold is released.
func (v *opaqueVerdictRun) reuseFallback(label string) {
	v.t.Helper()
	label += ": reader-hold fallback"
	baseTasks, baseWorks := v.accounts(label)
	if _, err := io.WriteString(v.stdin, "SPAWN\n"); err != nil {
		v.t.Fatal(err)
	}
	if line, err := v.stdout.ReadString('\n'); err != nil || !strings.HasPrefix(line, "SPAWNED:") {
		v.t.Fatalf("%s: line=%q err=%v stderr=%q", label, line, err, v.stderr.String())
	}
	children := v.childTasks(label)
	if len(children) != 1 {
		v.t.Fatalf("%s: %d child TASKs, want the one spawned", label, len(children))
	}
	f := children[0]
	hold := func(release uint32) {
		v.t.Helper()
		request := struct {
			Physical, Cookie uint64
			Slot, Release    uint32
		}{f.physical, f.cookie, f.slot, release}
		if err := v.c.Maps["opaque_real_reuse_hold_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			v.t.Fatal(err)
		}
		if code, _, err := v.c.Programs["opaque_real_reuse_hold"].Test(make([]byte, 64)); err != nil || code != 0 {
			v.t.Fatalf("%s: hold (release=%d) on TASK %#x: code=%d err=%v", label, release, f.physical, code, err)
		}
	}
	meta := func() []byte {
		v.t.Helper()
		raw, err := v.c.Maps["se_opaque_meta"].LookupBytes(f.slot)
		if err != nil {
			v.t.Fatal(err)
		}
		return raw
	}
	hold(0)
	if raw := meta(); v.field(v.metaType, raw, "phase") != 1 || v.field(v.metaType, raw, "reader_holds") != 1 {
		v.t.Fatalf("%s: hold on LIVE TASK: phase=%d reader_holds=%d", label,
			v.field(v.metaType, raw, "phase"), v.field(v.metaType, raw, "reader_holds"))
	}
	if _, err := io.WriteString(v.stdin, "REAP\n"); err != nil {
		v.t.Fatal(err)
	}
	if line, err := v.stdout.ReadString('\n'); err != nil || line != "REAPED:1\n" {
		v.t.Fatalf("%s: line=%q err=%v stderr=%q", label, line, err, v.stderr.String())
	}
	raw := v.waitFinalFree(label, f)
	var value uint64
	if v.field(v.metaType, raw, "directory_state") != opaqueDirectoryPublished ||
		v.field(v.metaType, raw, "cleanup_done")&opaqueCleanupDirDone != 0 ||
		v.field(v.metaType, raw, "exclusive") != 0 || v.field(v.metaType, raw, "exclusive_owner") != 0 ||
		v.field(v.metaType, raw, "reader_holds") != 1 ||
		v.c.Maps["se_opaque_keys"].Lookup(f.physical, &value) != nil || value != f.locator {
		v.t.Fatalf("%s: refused final-free withdrawal changed state: directory_state=%d cleanup_done=%#x exclusive=%d reader_holds=%d key=%#x, want PUBLISHED untouched",
			label, v.field(v.metaType, raw, "directory_state"), v.field(v.metaType, raw, "cleanup_done"),
			v.field(v.metaType, raw, "exclusive"), v.field(v.metaType, raw, "reader_holds"), value)
	}
	// The same hold also blocks the reaper's claim.
	if code, err := v.reapStep("task", f.slot, f.cookie); err != nil || code != 3 {
		v.t.Fatalf("%s: reaper visit under the hold: code=%d err=%v, want PENDING", label, code, err)
	}
	hold(1)
	v.settleRound(label, -1)
	v.reapOnce(label, f)
	if err := v.c.Maps["se_opaque_keys"].Lookup(f.physical, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		v.t.Fatalf("%s: directory key survived the reaper withdrawal: %v", label, err)
	}
	if tasks, works := v.accounts(label); tasks != baseTasks || works != baseWorks {
		v.t.Fatalf("%s: account TASK %d WORK %d after exact refunds, want baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
	}
	v.t.Logf("%s: final-free withdrawal refused under the hold; reaper withdrew and returned TASK cookie %d exactly once", label, f.cookie)
}

// reapOnce returns the exact TASK credit, then checks a second visit for the
// same cookie is refused (the charge no longer carries it).
func (v *opaqueVerdictRun) reapOnce(label string, c opaqueChildTask) {
	v.t.Helper()
	v.reap("task", c.slot, c.cookie)
	if code, err := v.reapStep("task", c.slot, c.cookie); err != nil || code != 4 {
		v.t.Fatalf("%s: second reap of TASK cookie %d: code=%d err=%v, want the refused stale cookie (4)", label, c.cookie, code, err)
	}
}

// pin pins the helper parent (and its later children) to cpu; -1 restores.
func (v *opaqueVerdictRun) pin(label string, cpu int) {
	v.t.Helper()
	if _, err := fmt.Fprintf(v.stdin, "PIN:%d\n", cpu); err != nil {
		v.t.Fatal(err)
	}
	if line, err := v.stdout.ReadString('\n'); err != nil || line != fmt.Sprintf("PINNED:%d:0\n", cpu) {
		v.t.Fatalf("%s: pin to CPU %d: line=%q err=%v", label, cpu, line, err)
	}
}
