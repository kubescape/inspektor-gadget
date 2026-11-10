// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type sharedHostContext struct {
	operators.GadgetContext
	vars  map[string]any
	image string
}

func (c *sharedHostContext) GetVar(k string) (any, bool) { v, ok := c.vars[k]; return v, ok }
func (c *sharedHostContext) SetVar(k string, v any)      { c.vars[k] = v }
func (c *sharedHostContext) Context() context.Context    { return context.Background() }
func (c *sharedHostContext) ImageName() string           { return c.image }
func TestSharedHostTwoPhaseAdmission(t *testing.T) {
	cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
	bad := cfg
	bad.ABI3Development = false
	if _, err := NewNodeEnforcer(bad); err == nil {
		t.Fatal("default enabled shared host")
	}
	n, err := NewNodeEnforcer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	acquired := false
	if _, err = n.Bind(t.Context(), SharedBindingConfig{CgroupID: 1, Acquire: func(context.Context) (BindingLease, error) { acquired = true; return &sharedTestLease{}, nil }}); err == nil || acquired {
		t.Fatal("binding without trusted init identity")
	}
	gc := &sharedHostContext{vars: map[string]any{sharedNodeKey: n}, image: cfg.Image}
	gc.vars["config"] = viper.New()
	if _, err = New().InstantiateDataOperator(gc, nil); err == nil {
		t.Fatal("unmarked image admitted through real operator")
	}
	metadata := viper.New()
	metadata.Set("annotations.enforce-exec-owner-abi", "3")
	metadata.Set("annotations.enforce-exec-owner-development", true)
	metadata.Set("annotations.enforce-exec-shared-profile", "1")
	gc.vars["config"] = metadata
	if _, err = New().InstantiateDataOperator(gc, nil); err == nil {
		t.Fatal("missing image geometry/maps admitted")
	}
	if err = n.Ready(gc); err == nil {
		t.Fatal("protocol foundation advertised protection")
	}
	if err = n.ReleaseAfterDetach(); err != nil {
		t.Fatal("never-claimed native handle release", err)
	}
}

func TestSharedHostStopDoesNotPretendManagerDetached(t *testing.T) {
	cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
	n, err := NewNodeEnforcer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.host.claimed = true // simulate host ownership without allocating BPF
	if err = n.StopNode(t.Context()); err == nil {
		t.Fatal("host manager detach falsely inferred")
	}
	if n.host.released {
		t.Fatal("released while operator remains claimed")
	}
	if err = n.Start(nil); err == nil {
		t.Fatal("nil context")
	}
	if err = n.Stop(nil); err == nil {
		t.Fatal("nil stop context")
	}
	if err = n.Close(nil); err == nil {
		t.Fatal("nil close context")
	}
}

func TestSharedHostJoinedPanicCleanup(t *testing.T) {
	cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
	n, err := NewNodeEnforcer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gc := &sharedHostContext{vars: map[string]any{}, image: cfg.Image}
	n.host.claimed = true
	n.host.context = gc
	thread, err := startControlThread(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	n.host.control = &sharedControl{thread: thread}
	if err = thread.do(t.Context(), func() error { panic("command panic") }); err == nil {
		t.Fatal("panic diagnostic lost")
	}
	if err = n.Close(gc); err == nil {
		t.Fatal("sticky panic diagnostic lost")
	}
	select {
	case <-thread.done:
	default:
		t.Fatal("command thread not joined")
	}
	// No BPF resources are allocated in this unit fixture. Manager teardown has
	// no borrowed FDs to close; joined diagnostics must not retain the handle.
	if !n.host.operatorClosed {
		t.Fatal("joined cleanup reported permanently incomplete")
	}
	if err = n.ReleaseAfterDetach(); err != nil {
		t.Fatal("joined failed command prevented release", err)
	}
}

func TestSharedHostBindingRefusalIsNotJoinedCleanup(t *testing.T) {
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "development"})
	if err != nil {
		t.Fatal(err)
	}
	gc := &sharedHostContext{vars: map[string]any{}, image: "development"}
	n.host.context = gc
	n.host.claimed = true
	n.bindings[1] = &BindingSession{node: n, prepared: 1, cgroup: 1}
	if err = n.Close(gc); err == nil || n.host.operatorClosed {
		t.Fatal("active binding drain refusal marked closed")
	}
	if err = n.ReleaseAfterDetach(); err == nil {
		t.Fatal("unjoined cleanup released")
	}
}

func TestSharedHostRejectsImageKeyGeometry(t *testing.T) {
	for _, key := range []string{"images", "image-quota"} {
		for _, value := range []string{"", "0", "3", "4294967296"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
				n, err := NewNodeEnforcer(cfg)
				if err != nil {
					t.Fatal(err)
				}
				gc := &sharedHostContext{vars: map[string]any{}, image: cfg.Image}
				metadata := viper.New()
				metadata.Set("annotations.enforce-exec-owner-abi", "3")
				metadata.Set("annotations.enforce-exec-owner-development", true)
				metadata.Set("annotations.enforce-exec-shared-profile", "1")
				p := cfg.Profile
				for name, count := range map[string]uint64{"inode-facts": p.InodeFacts, "inode-quota": p.PerBinding.InodeFacts, "tasks": p.Tasks, "scratch": p.Scratch, "accepted-uids": p.AcceptedUIDs, "task-quota": p.PerBinding.Tasks, "scratch-quota": p.PerBinding.Scratch, "bindings": p.Bindings, "slots-256": p.PolicySlots[0], "slots-1024": p.PolicySlots[1], "slots-4096": p.PolicySlots[2], "slots-16384": p.PolicySlots[3], "images": p.Images, "image-quota": p.PerBinding.Images} {
					metadata.Set("annotations.enforce-exec-shared-"+name, strconv.FormatUint(count, 10))
				}
				metadata.Set("annotations.enforce-exec-shared-"+key, value)
				_, err = instantiateSharedNode(gc, metadata, n)
				if err == nil || !strings.Contains(err.Error(), "shared image geometry mismatch: "+key) {
					t.Fatalf("wrong geometry admission: %v", err)
				}
				if n.host.claimed || n.host.admitted != nil || n.host.ready {
					t.Fatal("invalid image geometry acquired host authority")
				}
			})
		}
	}
}

// The verdict candidate's compile-time guards are part of its fail-closed
// boundary (G025 step 10): the same-bprm continuation has no proved
// pre-dispatch class recovery, the verdict needs staged evaluation and the
// exact reader catalogue, and the source capsule and test-only injectors
// need the guarded verdict and disposable bootstrap. Removing or weakening
// one of these #error blocks must fail CI.
func TestOpaqueRealVerdictCandidateCompileGuards(t *testing.T) {
	raw, err := os.ReadFile("bpf/opaque_real_owner_child_candidate.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, guard := range []string{
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) && \\\n" +
			"    defined(ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC)\n" +
			"#error \"verdict candidate has no proved pre-dispatch interpreter class recovery\"\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC) && \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE)\n" +
			"#error \"same-bprm continuation requires the exact policy bridge\"\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) && \\\n" +
			"    (!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC) || \\\n" +
			"     !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC) || \\\n" +
			"     !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE))\n" +
			"#error \"real-policy verdict requires staged evaluation and exact reader catalogue\"\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE\n" +
			"#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE\n" +
			"#error \"source capsule admission requires the real-policy verdict candidate\"\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_POLICY_TASK_CLOSE_FAULT_DIAGNOSTIC) && \\\n" +
			"    (!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) || \\\n" +
			"     !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC))\n" +
			"#error \"policy close injection requires guarded verdict and disposable bootstrap\"\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC) || \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)\n" +
			"#error \"abort injection requires successful-birth disposable bootstrap\"\n#endif\n",
		"#ifdef SE_TEST_DEFERRED_STORAGE_ENTRIES\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC) || \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)\n" +
			"#error \"shrunken deferred storage requires its witness and disposable bootstrap\"\n#endif\n",
		"#if SE_TEST_DEFERRED_STORAGE_ENTRIES < 1 || \\\n" +
			"    SE_TEST_DEFERRED_STORAGE_ENTRIES > SE_PROFILE_TASKS\n" +
			"#error \"deferred storage override must be 1..SE_PROFILE_TASKS\"\n#endif\n",
		// G025 batch C: per-map storage overrides, route migration and
		// the generation advance stay test-only.
		"#if defined(SE_TEST_TERMINAL_RECEIPT_ENTRIES) || \\\n" +
			"    defined(SE_TEST_BIRTH_RECEIPT_ENTRIES) || \\\n" +
			"    defined(SE_TEST_FAILURE_FRAME_ENTRIES)\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC) || \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)\n" +
			"#error \"per-map deferred storage overrides require the witness and disposable bootstrap\"\n#endif\n#endif\n",
		"#if SE_TEST_TERMINAL_RECEIPT_ENTRIES < 1 || \\\n" +
			"    SE_TEST_TERMINAL_RECEIPT_ENTRIES > SE_PROFILE_TASKS\n" +
			"#error \"terminal receipt override must be 1..SE_PROFILE_TASKS\"\n#endif\n",
		"#if SE_TEST_BIRTH_RECEIPT_ENTRIES < 1 || \\\n" +
			"    SE_TEST_BIRTH_RECEIPT_ENTRIES > SE_PROFILE_TASKS\n" +
			"#error \"birth receipt override must be 1..SE_PROFILE_TASKS\"\n#endif\n",
		"#if SE_TEST_FAILURE_FRAME_ENTRIES < 1 || \\\n" +
			"    SE_TEST_FAILURE_FRAME_ENTRIES > SE_PROFILE_TASKS\n" +
			"#error \"failure frame override must be 1..SE_PROFILE_TASKS\"\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_ROUTE_MIGRATION_DIAGNOSTIC\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) || \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC) || \\\n" +
			"    SE_PROFILE_BINDINGS < 2\n" +
			"#error \"route migration requires the source capsule, disposable bootstrap and two bindings\"\n#endif\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_RELOAD_DIAGNOSTIC\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) || \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)\n" +
			"#error \"generation advance requires the source capsule and disposable bootstrap\"\n#endif\n#endif\n",
		// G025 batch D: the fail-closed rate witness rides only the
		// guarded verdict, and the quota profile stays an exact per-binding
		// partition within the measured stack range.
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE\n" +
			"#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE\n" +
			"#error \"fail-closed rate witness requires the real-policy verdict candidate\"\n#endif\n",
		"_Static_assert((__u64)SE_PROFILE_BINDINGS * SE_PROFILE_TASK_QUOTA ==\n" +
			"\t\t       SE_PROFILE_TASKS &&\n" +
			"\t       (__u64)SE_PROFILE_BINDINGS * SE_PROFILE_SCRATCH_QUOTA ==\n" +
			"\t\t       SE_PROFILE_SCRATCH,\n",
		"_Static_assert(SE_PROFILE_TASK_QUOTA >= 1 && SE_PROFILE_TASK_QUOTA <= 256 &&\n" +
			"\t       SE_PROFILE_SCRATCH_QUOTA >= 1 && SE_PROFILE_SCRATCH_QUOTA <= 32,\n",
		"_Static_assert(SE_PROFILE_WORK_RETRIES >= 1 &&\n" +
			"\t       SE_PROFILE_WORK_RETRIES <= SE_PROFILE_SCRATCH_QUOTA &&\n" +
			"\t       SE_PROFILE_WORK_RETRIES <= 16,\n",
		// G025 final: the physical-reuse directory withdrawal is a
		// correctness fix of every build of the final-free program, never
		// gated by the rate witness or any other option.
		"#ifndef SE_OF_WITHDRAW_DIRECTORY\n" +
			"#error \"real-map final-free requires the physical-reuse directory withdrawal\"\n#endif\n",
		"#ifndef SE_OP_INSERT_RETRY\n" +
			"#error \"real-map birth requires the physical-reuse single insert retry\"\n#endif\n",
		"\t\t(void)se_of_complete_native_unheld(&lease, physical);\n" +
			"\t\t/* Withdraw the directory entry before this address can be reused\n" +
			"\t\t * (full/shared_pool_opaque_final_free_candidate.h). Any refusal\n" +
			"\t\t * leaves the reaper's ordinary withdrawal as the fallback. */\n" +
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE\n" +
			"\t\t/* Mirror se_or_task_terminal_guard: a receipt left at this key\n" +
			"\t\t * keeps the key for its consumer; only the reaper retires it. */\n" +
			"\t\tif (!bpf_map_lookup_elem(&se_exec_terminal_receipts,\n" +
			"\t\t\t\t\t &receipt_key))\n" +
			"#endif\n" +
			"\t\t\t(void)se_of_withdraw_directory(&lease, physical);\n" +
			"\t\t(void)se_of_release(&lease, physical);\n",
	} {
		if strings.Count(source, guard) != 1 {
			t.Errorf("verdict candidate compile guard missing or changed:\n%s", guard)
		}
	}
	// The withdrawal and its marker are defined unconditionally in the
	// final-free header (only its LOCATOR_CANDIDATE file guard applies).
	raw, err = os.ReadFile("../full/shared_pool_opaque_final_free_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	header := string(raw)
	marker := "#include \"shared_pool_opaque_writer_candidate.h\"\n/* Physical-reuse fix (G025 batch F)."
	withdraw := "#define SE_OF_WITHDRAW_DIRECTORY 1\nstatic inline int se_of_withdraw_directory(struct se_of_lease *lease,\n"
	if strings.Count(header, marker) != 1 || strings.Count(header, withdraw) != 1 {
		t.Error("final-free header lost the unconditional physical-reuse directory withdrawal")
	}
	// The single insert retry (and its non-aborting STALE return) is
	// unconditional in the birth header.
	raw, err = os.ReadFile("../full/shared_pool_opaque_birth_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	birth := string(raw)
	for _, pin := range []string{
		"#define SE_OP_INSERT_RETRY 1\nstatic __attribute__((noinline)) int se_op_replace_charged_child(",
		"\t\tif (status == SE_OL_STALE)\n\t\t\treturn -1;\n",
		"\tif (status == SE_OL_CONTENDED) {\n\t\tstatus = se_op_replace_charged_child(reservation, opaque_key,\n\t\t\tarchive);\n\t\tif (status != -1)\n\t\t\treturn status;\n\t\tstatus = se_ow_insert_zero(reservation->meta,\n",
	} {
		if strings.Count(birth, pin) != 1 {
			t.Errorf("birth header lost the unconditional physical-reuse insert retry:\n%s", pin)
		}
	}
	if strings.Contains(birth, "FAIL_CLOSED_RATE_CANDIDATE") {
		t.Error("birth header gates behaviour on the fail-closed rate witness again")
	}
	var conditionals []string
	for _, line := range strings.Split(header, "\n") {
		if strings.HasPrefix(line, "#if") {
			conditionals = append(conditionals, line)
		}
	}
	if want := []string{
		"#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_FINAL_FREE_CANDIDATE_H",
		"#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE",
	}; !slices.Equal(conditionals, want) {
		t.Errorf("final-free header conditionals %q, want only %q: the withdrawal must not depend on any option", conditionals, want)
	}
	// SE_OC_WORD has no bound of its own in the one-word profile; its
	// documented precondition must stay next to the macro.
	raw, err = os.ReadFile("../full/shared_pool_opaque_charge_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	precondition := "/* Bitmap word of a slot-local TASK index.\n * Precondition: local < SE_OC_QUOTA."
	if strings.Count(string(raw), precondition) != 1 {
		t.Error("charge header lost the SE_OC_WORD precondition (local < SE_OC_QUOTA)")
	}
}
