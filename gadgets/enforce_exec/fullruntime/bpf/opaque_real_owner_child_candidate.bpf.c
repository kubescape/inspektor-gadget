// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Default-inert real-map composition candidate. No product image selects this
 * object: final-free settles only the exec/reader owner; native completion,
 * WORK/TASK reaping and the complete Ready proof are still absent. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#error "source capsule admission requires the real-policy verdict candidate"
#endif
/* 104-byte route with source pins (full/shared_route.h). Must precede the
 * first include of shared_route.h. */
#define ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE 1
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#define SE_EXEC_ROLE_FILL_BPF_LOOP 1
#endif
#define ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_FAULT_INLINE_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_OPEN_INLINE_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_SNAPSHOT_BRANCHLESS_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_OWNED_INLINE_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_CHOOSE_INLINE_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_SNAPSHOT_MATCH_NOINLINE_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_PARENT_PROJECT_SPLIT_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_PARENT_PROJECT_INLINE_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_CANCEL_OBSERVATION_INLINE_DIAGNOSTIC 1
/* The constructor's inline boundaries are verifier-budget diagnostics until
 * this complete real-map path has passed admitted-kernel qualification. */
#define ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC 1
#if (defined(ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_CLOSE_FAULT_DIAGNOSTIC) ||       \
     defined(ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_TASK_CLOSE_FAULT_DIAGNOSTIC)) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "post-publication close fault injection requires disposable bootstrap"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_CLOSE_FAULT_DIAGNOSTIC) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_TASK_CLOSE_FAULT_DIAGNOSTIC)
#error "inject only one post-publication close fault"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_NATIVE_CONFIG_GATE_CANDIDATE) &&  \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) || \
	 defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC))
#error "native-config gate requires recovered control and no synthetic bootstrap"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_READER_BEGIN_PROBE)
#error "reader lifecycle probe requires the begin probe"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE) && \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE))
#error "staged policy bridge requires exact reader and failure-terminal probes"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC) && \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_COMPLETION_PROBE) ||          \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE))
#error "success-source completion requires WORK completion and terminal producer"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_SOURCE_COMPLETION_DIAGNOSTIC) && \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_COMPLETION_PROBE) ||          \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE))
#error "failure-source completion requires WORK completion and exact failure frames"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_SOURCE_COMPLETION_DIAGNOSTIC)
static __attribute__((noinline)) int
real_owner_work_completion_shape(__u64 key);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_TERMINAL_DRAIN_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_COMPLETION_PROBE) ||      \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_READER_BEGIN_PROBE)
#error "source terminal drain requires WORK completion and reader lifecycle"
#endif
static __attribute__((noinline)) int real_owner_source_terminal_drain(void);
static __attribute__((noinline)) int
real_owner_reader_quarantine_pending(__u64 physical);
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE)
#error "same-bprm continuation requires the exact policy bridge"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) &&     \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE))
#error "real-policy verdict requires staged evaluation and exact reader catalogue"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC)
#error "verdict candidate has no proved pre-dispatch interpreter class recovery"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_POLICY_TASK_CLOSE_FAULT_DIAGNOSTIC) &&  \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC))
#error "policy close injection requires guarded verdict and disposable bootstrap"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
#error "real stage begin requires the exact real-policy WORK bridge"
#endif
/* This diagnostic selects the same bounded evaluator wire as the staged
 * fixture, but resolves its header through the real retained WORK and policy
 * cohort. It does not observe facts, evaluate rules or emit a verdict. */
#define ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE 1
#define ENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE 1
#define ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC 1
#define ENFORCE_EXEC_STAGE2_SOURCE_OBJECT 1
#define FE_BOUNDED_LOOP_CANDIDATE 1
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
#define FE_STAGE_RULES 1U
#define FE_STAGE_RELOOKUP_HEADER_CANDIDATE 1
#define FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC 1
#define FE_RULE_STEP_INLINE_DIAGNOSTIC 1
#define SE_OBJECT_RANGE_INLINE_DIAGNOSTIC 1
#define FM_WORK_RUN_STATE_DIAGNOSTIC 1
/* The successor already owns its lexical output ticket. Reuse it during
 * resume instead of reserving a second 64-byte ticket in the callee. */
#define ENFORCE_EXEC_POOL_OPAQUE_RESUME_OUTPUT_TICKET_DIAGNOSTIC 1
#endif
#define FM_STAGE_INLINE_INSTRUCTION_WINDOW 1
#define SE_POLICY_EVALUATOR_HEADER "evaluator_stage_candidate.h"
struct fm_blob;
struct fm_global_token;
struct se_policy_view;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
#define REAL_OWNER_STAGE_VIEW_INLINE __attribute__((always_inline))
#define REAL_OWNER_STAGE_BLOB_INLINE __attribute__((always_inline))
#else
#define REAL_OWNER_STAGE_VIEW_INLINE
#define REAL_OWNER_STAGE_BLOB_INLINE
#endif
static REAL_OWNER_STAGE_VIEW_INLINE inline struct se_policy_view *
real_owner_stage_view(const struct fm_global_token *);
static REAL_OWNER_STAGE_BLOB_INLINE inline const struct fm_blob *
real_owner_stage_blob(unsigned int, unsigned long long, unsigned int);
#define SE_POLICY_VIEW(ctx) \
	real_owner_stage_view((const struct fm_global_token *)(ctx))
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	real_owner_stage_blob((slot), (cookie), (key))
#endif
#define SE_CATALOGUE_FROM_BANK 1
/* WORK continuation stage that the stage/rule/propose programs consume. The
 * verdict build inserts a separate prepare program (stage 1 -> 2) because
 * history/catalogue/role preparation inside the policy program exceeded 1M
 * processed instructions and 512 stack bytes on exact AL2023 6.18. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#define REAL_OWNER_EVAL_STAGE 2
/* A proposed evaluation WORK stays suspended for the exec terminal, which
 * completes into it instead of charging a third credit (monotone next). */
#define REAL_OWNER_TERMINAL_STAGE (REAL_OWNER_EVAL_STAGE + 1)
#else
#define REAL_OWNER_EVAL_STAGE 1
#endif
#define SE_OWK_EVAL_VIEW_STAGE REAL_OWNER_EVAL_STAGE
#ifdef ENFORCE_EXEC_POOL_OPAQUE_ADVANCE_DIAGNOSTIC
/* Disposable observation of the exact post-death locator CAS. */
struct se_ow_advance_observation {
	__u64 locator, observed, previous;
	__u32 stage, exact, attempts, reserved;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_ow_advance_observation);
} se_ow_advance_observation SEC(".maps");
static __always_inline void se_ow_advance_observe(__u32 stage, __u64 locator,
						  __u64 observed,
						  __u64 previous, __u32 exact)
{
	__u32 zero = 0;
	struct se_ow_advance_observation *o =
		bpf_map_lookup_elem(&se_ow_advance_observation, &zero);
	if (o) {
		o->locator = locator;
		o->observed = observed;
		o->previous = previous;
		o->stage = stage;
		o->exact = exact;
		o->attempts++;
	}
}
#define SE_OW_ADVANCE_DIAG(stage, locator, observed, previous, exact) \
	se_ow_advance_observe(stage, locator, observed, previous, exact)
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "abort injection requires successful-birth disposable bootstrap"
#endif
/* Test-only fault edge: every Nth published-zero child constructor takes the
 * exact semantic abort (phase ABORTED, charge still OWNED), the same path as
 * a naturally lost replacement. [0] of the selector is N; 0 disables it. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_abort_every SEC(".maps");
/* [0] constructors reaching the fault edge while enabled, [1] injected
 * aborts, [2] exact semantic aborts to ABORTED (injected or natural). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_abort_counts SEC(".maps");
static __always_inline void real_owner_abort_count(__u32 index)
{
	__u64 *count = bpf_map_lookup_elem(&opaque_real_abort_counts, &index);
	if (count)
		__sync_fetch_and_add(count, 1);
}
static __always_inline int real_owner_abort_inject(void)
{
	__u32 zero = 0;
	const __u32 *every =
		bpf_map_lookup_elem(&opaque_real_abort_every, &zero);
	__u64 *seen = bpf_map_lookup_elem(&opaque_real_abort_counts, &zero);
	__u32 n = every ? *every : 0;
	if (!n || !seen || __sync_add_and_fetch(seen, 1) % n)
		return 0;
	real_owner_abort_count(1);
	return 1;
}
#define SE_OP_ABORT_AFTER_PUBLISH_ZERO() real_owner_abort_inject()
#define SE_OP_ABORTED_WITNESS() real_owner_abort_count(2)
/* Test-only physical-reuse witness: replacement failures of a constructor
 * whose task address still had a directory entry (se_op_replace_charged_child):
 * [0] key gone before observation, [1] zero/withdrawn value, [2] predecessor
 * not holdable (claimed or not DEAD), [3] replacement claim lost. Leaf frame
 * only: the target chain is at the 512-byte combined stack. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_replace_failures SEC(".maps");
static __attribute__((noinline)) void real_owner_replace_failure(__u32 site)
{
	__u32 key = site < 4 ? site : 3;
	__u64 *count = bpf_map_lookup_elem(&opaque_real_replace_failures, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#define SE_OP_REPLACE_FAILURE(site) real_owner_replace_failure(site)
#endif
/* G025 step 7: a second disposable route of the opposite class on a second
 * cgroup, for migration. Admission must go through the source capsule. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_ROUTE_MIGRATION_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) ||           \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC) || \
	SE_PROFILE_BINDINGS < 2
#error "route migration requires the source capsule, disposable bootstrap and two bindings"
#endif
#endif
/* G025 step 8: test-only generation advance through the product route and
 * binding commit primitives, during churn. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_RELOAD_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "generation advance requires the source capsule and disposable bootstrap"
#endif
#endif
/* Deferred plain storage: the terminal receipt and failure-frame HASHes (and
 * the test-only birth receipts) are sized to the TASK pool. A test-only
 * override shrinks only these maps so every insert refusal is exercised. */
#ifdef SE_TEST_DEFERRED_STORAGE_ENTRIES
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "shrunken deferred storage requires its witness and disposable bootstrap"
#endif
#if SE_TEST_DEFERRED_STORAGE_ENTRIES < 1 || \
	SE_TEST_DEFERRED_STORAGE_ENTRIES > SE_PROFILE_TASKS
#error "deferred storage override must be 1..SE_PROFILE_TASKS"
#endif
#define SE_DEFERRED_STORAGE_ENTRIES SE_TEST_DEFERRED_STORAGE_ENTRIES
#else
#define SE_DEFERRED_STORAGE_ENTRIES SE_PROFILE_TASKS
#endif
/* Independent test-only per-map overrides (G025 step 4b): shrinking only the
 * terminal receipts while birth receipts stay full size makes the terminal
 * receipt insert refusal reachable. Each defaults to the shared size. */
#if defined(SE_TEST_TERMINAL_RECEIPT_ENTRIES) ||  \
	defined(SE_TEST_BIRTH_RECEIPT_ENTRIES) || \
	defined(SE_TEST_FAILURE_FRAME_ENTRIES)
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "per-map deferred storage overrides require the witness and disposable bootstrap"
#endif
#endif
#ifdef SE_TEST_TERMINAL_RECEIPT_ENTRIES
#if SE_TEST_TERMINAL_RECEIPT_ENTRIES < 1 || \
	SE_TEST_TERMINAL_RECEIPT_ENTRIES > SE_PROFILE_TASKS
#error "terminal receipt override must be 1..SE_PROFILE_TASKS"
#endif
#define SE_TERMINAL_RECEIPT_ENTRIES SE_TEST_TERMINAL_RECEIPT_ENTRIES
#else
#define SE_TERMINAL_RECEIPT_ENTRIES SE_DEFERRED_STORAGE_ENTRIES
#endif
#ifdef SE_TEST_BIRTH_RECEIPT_ENTRIES
#if SE_TEST_BIRTH_RECEIPT_ENTRIES < 1 || \
	SE_TEST_BIRTH_RECEIPT_ENTRIES > SE_PROFILE_TASKS
#error "birth receipt override must be 1..SE_PROFILE_TASKS"
#endif
#define SE_BIRTH_RECEIPT_ENTRIES SE_TEST_BIRTH_RECEIPT_ENTRIES
#else
#define SE_BIRTH_RECEIPT_ENTRIES SE_DEFERRED_STORAGE_ENTRIES
#endif
#ifdef SE_TEST_FAILURE_FRAME_ENTRIES
#if SE_TEST_FAILURE_FRAME_ENTRIES < 1 || \
	SE_TEST_FAILURE_FRAME_ENTRIES > SE_PROFILE_TASKS
#error "failure frame override must be 1..SE_PROFILE_TASKS"
#endif
#define SE_FAILURE_FRAME_ENTRIES SE_TEST_FAILURE_FRAME_ENTRIES
#else
#define SE_FAILURE_FRAME_ENTRIES SE_DEFERRED_STORAGE_ENTRIES
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) ||   \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE) ||  \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "deferred storage witness requires the verdict, birth and failure-frame disposable build"
#endif
/* Test-only insert-refusal witness, read by the attached verdict test.
 * [0] terminal receipt insert refused (verdict reader quarantined); [1] outer
 * failure frame insert refused; [2] handler failure frame insert refused;
 * [3] birth receipt insert refused (source finishes the birth WORK without a
 * target); [4] verdict reader quarantined because its frames were not ready. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 5);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_deferred_storage_refusals SEC(".maps");
static __always_inline void real_owner_storage_refused(__u32 index)
{
	__u64 *count = bpf_map_lookup_elem(
		&opaque_real_deferred_storage_refusals, &index);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#define SE_DEFERRED_STORAGE_REFUSED(index) real_owner_storage_refused(index)
#else
#define SE_DEFERRED_STORAGE_REFUSED(index) \
	do {                               \
	} while (0)
#endif
/* G025 decision 3: fail-closed rate witness. Default-off candidate, not a
 * test diagnostic: a future product loader reads these counters and must
 * report NotReady/degraded when their deltas are nonzero (or above its
 * threshold); see fullruntime.FailClosedRateVerdict. Each counts a managed
 * birth or exec that was refused (Strict) or left unevaluated (Audit):
 * [0] constructor TASK quota LIMIT; [1] source refused the birth before the
 * target (start_work refusal, parent/terminal fault); [2] birth WORK
 * finished without a constructor (missing target, target resume/open
 * failure); [3] evaluation WORK refused (reader quarantined); [4] deferred
 * storage quarantine (terminal receipt refused, failure frames not ready);
 * [5] other constructor failure (STALE, CONTENDED, CORRUPT, not attempted).
 * [6] is a subset, not a class: start_work exhausted SE_PROFILE_WORK_RETRIES
 * lost races; that refusal is also counted as [1], [3] or a refused
 * terminal fallback. Leaf frame only, at the existing witness call sites. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#error "fail-closed rate witness requires the real-policy verdict candidate"
#endif
#define REAL_OWNER_RATE_LIMIT 0
#define REAL_OWNER_RATE_SOURCE 1
#define REAL_OWNER_RATE_MISSING_TARGET 2
#define REAL_OWNER_RATE_EVAL_WORK 3
#define REAL_OWNER_RATE_STORAGE 4
#define REAL_OWNER_RATE_CONSTRUCT 5
#define REAL_OWNER_RATE_WORK_RETRY 6
#define REAL_OWNER_RATE_CLASSES 7
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, REAL_OWNER_RATE_CLASSES);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_fail_closed_rates SEC(".maps");
static __attribute__((noinline)) void real_owner_fail_closed_rate(__u32 index)
{
	__u32 key = index < REAL_OWNER_RATE_CLASSES ? index :
						      REAL_OWNER_RATE_CONSTRUCT;
	__u64 *count =
		bpf_map_lookup_elem(&opaque_real_fail_closed_rates, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#define SE_FAIL_CLOSED_RATE(index) real_owner_fail_closed_rate(index)
#else
#define SE_FAIL_CLOSED_RATE(index) \
	do {                       \
	} while (0)
#endif
/* WORK start retries per lost bit race (each loss is a sibling's charge).
 * Default: one per WORK credit up to 16 (min(WORK quota, 16)), so
 * contention alone never refuses at 64/8 and 128/16. The
 * rolled retry loop is re-walked per attempt; 32 attempts exceeded the 8192
 * pending-jump limit in the completion probes on AL2023 6.12 (g25d), 16
 * loaded. A smaller bound refuses fail-closed, witnessed by rate [6]. */
#ifndef SE_PROFILE_WORK_RETRIES
#define SE_PROFILE_WORK_RETRIES \
	(SE_PROFILE_SCRATCH_QUOTA < 16 ? SE_PROFILE_SCRATCH_QUOTA : 16)
#endif
_Static_assert(
	SE_PROFILE_WORK_RETRIES >= 1 &&
		SE_PROFILE_WORK_RETRIES <= SE_PROFILE_SCRATCH_QUOTA &&
		SE_PROFILE_WORK_RETRIES <= 16,
	"WORK start retries must be 1..min(WORK quota, 16): the verifier's pending-jump bound");
/* G025 decision 2: the TASK and WORK quotas are the build-profile parameters
 * SE_PROFILE_TASK_QUOTA and SE_PROFILE_SCRATCH_QUOTA (WORK). The opaque
 * owner partitions each pool exactly per binding; the WORK account is one
 * 64-bit bitmap and the evaluation start_work retries at most once per WORK
 * credit. Only 64/8, 128/16 and 256/32 (two bindings) have been measured
 * against the 512-byte combined stack: requalify before widening. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
_Static_assert(
	(__u64)SE_PROFILE_BINDINGS *SE_PROFILE_TASK_QUOTA == SE_PROFILE_TASKS &&
		(__u64)SE_PROFILE_BINDINGS * SE_PROFILE_SCRATCH_QUOTA ==
			SE_PROFILE_SCRATCH,
	"verdict TASK/WORK pools must be partitioned exactly per binding");
_Static_assert(
	SE_PROFILE_TASK_QUOTA >= 1 && SE_PROFILE_TASK_QUOTA <= 256 &&
		SE_PROFILE_SCRATCH_QUOTA >= 1 && SE_PROFILE_SCRATCH_QUOTA <= 32,
	"verdict quota profile outside the measured TASK 1..256 / WORK 1..32 range");
#endif
/* Test-only recovered-control composition. The physical admin registry
 * replaces TASK_STORAGE, but its guardian/admin protocol and native owner
 * must be qualified separately before any selected image may use it. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
#define ENFORCE_EXEC_SHARED_RECOVERY 1
#include "shared_recovery_kernel.h"
#endif
/* Generic role helpers have no lexical scope parameter in this candidate.
 * Only the explicit scoped WORK catalogue path below is used for projection;
 * unrelated generic lookups fail closed rather than infer current cgroup. */
#define ER_ACCEPTED_EPOCH(uid) (~0ULL)
#include "epoch_roles.h"
#include "shared_pool_opaque_real_control_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* The loader must install the matching static-class wrapper in each graph
 * and freeze every map before linking the source. No mutable map data or
 * receipt lookup is allowed to choose a failure verdict after dispatch. */
#define REAL_OWNER_CLASS_GRAPH(name)                   \
	struct {                                       \
		__uint(type, BPF_MAP_TYPE_PROG_ARRAY); \
		__uint(max_entries, 1);                \
		__type(key, __u32);                    \
		__type(value, __u32);                  \
	} name SEC(".maps")
REAL_OWNER_CLASS_GRAPH(opaque_real_policy_audit);
REAL_OWNER_CLASS_GRAPH(opaque_real_policy_strict);
REAL_OWNER_CLASS_GRAPH(opaque_real_prepare_audit);
REAL_OWNER_CLASS_GRAPH(opaque_real_prepare_strict);
REAL_OWNER_CLASS_GRAPH(opaque_real_stage_audit);
REAL_OWNER_CLASS_GRAPH(opaque_real_stage_strict);
REAL_OWNER_CLASS_GRAPH(opaque_real_rule_audit);
REAL_OWNER_CLASS_GRAPH(opaque_real_rule_strict);
REAL_OWNER_CLASS_GRAPH(opaque_real_finish_audit);
/* Test-only witness: rule-program re-entries (windows after the first). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_owner_rule_windows SEC(".maps");
REAL_OWNER_CLASS_GRAPH(opaque_real_finish_strict);
#undef REAL_OWNER_CLASS_GRAPH
#else
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_policy_targets SEC(".maps");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_policy_stage_targets SEC(".maps");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_rule_targets SEC(".maps");
#endif
#endif
#endif /* static-class graphs versus original Audit diagnostics */
/* Test-only observation, never a policy or cleanup authority. Only an
 * unattached target reached through the source tail call may write it. */
struct opaque_real_owner_policy_witness {
	__u64 prepared, physical, cookie, invocation;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_real_owner_policy_witness);
} opaque_real_owner_policy_witness SEC(".maps");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
struct opaque_real_owner_rule_progress {
	int stage_begin, rule_eval, matched, observed_uid;
	__u64 rule_eval_count, matched_count;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_real_owner_rule_progress);
} opaque_real_owner_rule_progress SEC(".maps");
/* Test-only expected UID, set before the BPF seed. It is not a policy source
 * or admission authority; the rule target observes the actual current eUID. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_rule_uid_expect SEC(".maps");
static __attribute__((noinline)) void real_owner_rule_progress(__u32 stage,
							       int result)
{
	__u32 zero = 0;
	struct opaque_real_owner_rule_progress *progress =
		bpf_map_lookup_elem(&opaque_real_owner_rule_progress, &zero);
	if (!progress)
		return;
	if (stage == 0)
		progress->stage_begin = result;
	else if (stage == 1) {
		progress->rule_eval = result;
		if (result == 1)
			__sync_fetch_and_add(&progress->rule_eval_count, 1);
	} else if (stage == 2) {
		progress->matched = result;
		if (result == 1)
			__sync_fetch_and_add(&progress->matched_count, 1);
	} else if (stage == 3)
		progress->observed_uid = result;
}
#endif
/* The real route/snapshot/object cohort, not the lifecycle fixture's
 * synthetic policy maps, supplies the held WORK view. This remains an
 * opt-in diagnostic until source, terminal and native owner gates pass. */
#include "shared_policy_prepare.h"
#include "shared_pool_opaque_work_eval_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
#define SE_OWK_CURRENT_TASK() bpf_get_current_task_btf()
#include "shared_pool_opaque_work_suspended_read_candidate.h"
static REAL_OWNER_STAGE_VIEW_INLINE inline struct se_policy_view *
real_owner_stage_view(const struct fm_global_token *token)
{
	return token && !token->reserved ?
		       se_owk_suspended_view_from_token(token->slot,
							token->cookie) :
		       0;
}
static REAL_OWNER_STAGE_BLOB_INLINE inline const struct fm_blob *
real_owner_stage_blob(unsigned int slot, unsigned long long cookie,
		      unsigned int key)
{
	struct fm_global_token token = { .slot = slot, .cookie = cookie };
	return se_policy_data(real_owner_stage_view(&token), key);
}
#endif
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
static struct se_binding_snapshots *real_owner_work_binding_lookup(__u32 slot)
{
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &slot);
	return binding ? &binding->state : 0;
}
#define SE_OWK_BINDING_LOOKUP(slot) real_owner_work_binding_lookup(slot)
#endif
#define SE_OWK_CATALOGUE_EPOCH(scope, uid) se_catalogue_epoch((scope), (uid))
#define SE_POOL_CATALOGUE_ROW_NOINLINE 1
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
/* A map row is never a successful-fork signal. task_alloc invalidates old
 * pointer state; only the charged, published child may stamp this receipt.
 * The post-success kernel tracepoint must still validate it before any
 * eligibility transition. User space cannot populate this diagnostic map. */
struct opaque_birth_receipt {
	__u64 child, child_cookie, child_locator;
	__u64 parent, parent_cookie, scope, generation, serial;
	__u32 slot, incarnation, record, state, observation, reserved;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_BIRTH_RECEIPT_ENTRIES);
	/* Stock Rocky 4.18 tracing programs cannot access runtime-allocated HASH
	 * values, so this map is preallocated. It is NOT bounded by the TASK
	 * pool: a receipt lives until the child's RCU-deferred free, including
	 * unconstructed children, so a full map makes the source finish the birth
	 * WORK without the target (fail closed in Strict). */
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct opaque_birth_receipt);
} opaque_birth_receipts SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_birth_receipt);
} opaque_birth_receipt_zero SEC(".maps");
/* Test-only failed-birth witness: retired receipts that were issued and
 * stamped but never observed by sched_process_fork, i.e. copy_process failed
 * after security_task_alloc. [0] task_free retired it, [1] free_task did. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_birth_failed_retired SEC(".maps");
static __always_inline void real_owner_birth_retire(__u64 key, __u32 path)
{
	const struct opaque_birth_receipt *receipt =
		bpf_map_lookup_elem(&opaque_birth_receipts, &key);
	if (receipt && receipt->state == 1 && receipt->child_cookie &&
	    !receipt->observation) {
		__u64 *count = bpf_map_lookup_elem(&opaque_birth_failed_retired,
						   &path);
		if (count)
			__sync_fetch_and_add(count, 1);
	}
	(void)bpf_map_delete_elem(&opaque_birth_receipts, &key);
}
/* Test-only birth accounting witness. [0] source birth start_work refused
 * before any WORK was charged; [1..5] target constructor status + 1 (OK,
 * STALE, CONTENDED, LIMIT, CORRUPT/other); [6] constructor not attempted
 * (route/binding/snapshot); [7] birth WORK finished without a constructor
 * (target resume/open failure or source missing target). Leaf frame only:
 * the source and target chains are at the 512-byte combined stack. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_birth_outcomes SEC(".maps");
static __attribute__((noinline)) void real_owner_birth_outcome(__u32 index)
{
	__u32 key = index < 8 ? index : 5;
	__u64 *count = bpf_map_lookup_elem(&opaque_birth_outcomes, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#endif
#include "shared_pool_opaque_inherit_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
#include "shared_pool_opaque_exec_work_completion_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#include "shared_pool_opaque_exec_prepare_candidate.h"
#include "shared_pool_opaque_exec_propose_candidate.h"
#endif
#endif
#include "shared_pool_opaque_final_semantic_candidate.h"

#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
/* Plain, bounded diagnostic mailbox. The tracing callback cannot access a
 * map whose values contain spinlocks on stock Rocky 4.18. This receipt is
 * evidence only: a future authenticated TC consumer must validate the exact
 * live owner and release its reader; this map alone never grants cleanup. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_TERMINAL_RECEIPT_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct se_exec_terminal_receipt);
} se_exec_terminal_receipts SEC(".maps");
/* Both actual terminal producers use this exact, one-way transition. A
 * failed exec's outer frame supplies independent identity; the success
 * tracepoint supplies the live receipt's identity and bprm. Only the first
 * REGISTERED -> terminal CAS can win. This does not grant cleanup authority. */
static __always_inline int
real_owner_terminal_transition(struct se_exec_terminal_receipt *receipt,
			       __u64 physical, __u64 bprm, __u64 cookie,
			       __u64 locator, __u64 invocation, __u64 scope,
			       __u64 generation, __u32 terminal)
{
	if (!receipt || !physical || !bprm || !cookie || !locator ||
	    !invocation || !scope || !generation || receipt->reserved ||
	    (terminal != SE_EXEC_TERMINAL_SUCCESS &&
	     terminal != SE_EXEC_TERMINAL_FAILURE) ||
	    receipt->physical != physical || receipt->bprm != bprm ||
	    receipt->cookie != cookie || receipt->locator != locator ||
	    receipt->invocation != invocation || receipt->scope != scope ||
	    receipt->generation != generation)
		return 0;
	return __sync_val_compare_and_swap(&receipt->phase,
					   SE_EXEC_TERMINAL_REGISTERED,
					   terminal) ==
	       SE_EXEC_TERMINAL_REGISTERED;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PENDING_RECEIPT_DIAGNOSTIC
/* Test-only injection of a mismatched receipt before the real bprm source.
 * Only the exact isolated physical task chosen by the controller is touched.
 * The separate cleanup entrypoint refuses to delete any other receipt. */
struct opaque_real_pending_selector {
	__u64 physical;
	__u64 stale_cookie;
	__u64 stale_locator;
	__u64 cgroup;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_pending_selector);
} opaque_real_pending_selector SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
	__type(key, __u64);
	__type(value, struct opaque_real_pending_selector);
} opaque_real_pending_history SEC(".maps");
static __attribute__((noinline)) int real_pending_receipt_inject(void)
{
	__u32 zero = 0;
	const struct opaque_real_pending_selector *selected =
		bpf_map_lookup_elem(&opaque_real_pending_selector, &zero);
	__u64 physical = (__u64)bpf_get_current_task_btf();
	if (!selected || selected->physical != physical)
		selected = bpf_map_lookup_elem(&opaque_real_pending_history,
					       &physical);
	if (!selected || !physical || selected->physical != physical ||
	    !selected->cgroup ||
	    selected->cgroup != bpf_get_current_cgroup_id() ||
	    !selected->stale_cookie || !selected->stale_locator)
		return 0;
	struct se_exec_terminal_receipt receipt = {
		.physical = physical,
		.bprm = 1,
		.cookie = selected->stale_cookie,
		.locator = selected->stale_locator,
		.invocation = 1,
		.scope = 10,
		.generation = 1,
		.phase = SE_EXEC_TERMINAL_REGISTERED,
	};
	(void)bpf_map_update_elem(&se_exec_terminal_receipts, &physical,
				  &receipt, BPF_NOEXIST);
	return 0;
}
SEC("tc")
int opaque_real_pending_receipt_cleanup(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const struct opaque_real_pending_selector *selected =
		bpf_map_lookup_elem(&opaque_real_pending_selector, &zero);
	if (!selected || !selected->physical || !selected->stale_cookie ||
	    !selected->stale_locator)
		return 1;
	const struct se_exec_terminal_receipt *receipt = bpf_map_lookup_elem(
		&se_exec_terminal_receipts, &selected->physical);
	if (!receipt || receipt->physical != selected->physical ||
	    receipt->cookie != selected->stale_cookie ||
	    receipt->locator != selected->stale_locator ||
	    receipt->phase != SE_EXEC_TERMINAL_REGISTERED)
		return 2;
	return bpf_map_delete_elem(&se_exec_terminal_receipts,
				   &selected->physical) ?
		       3 :
		       0;
}
#endif
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
#define ENFORCE_EXEC_POOL_REAPER_CANDIDATE 1
#include "shared_pool_reaper_wire_candidate.h"
#define SE_POOL_T SE_OL_TASKS
#define SE_POOL_W SE_OWK_WORKS
#include "shared_pool_reaper_control_candidate.h"
#include "shared_pool_opaque_reaper_visit_candidate.h"
/* Reaper transport is not selected by the product. Its request is writable
 * only by the controller; control and receipt are writable only by BPF. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct se_pool_request);
} se_pool_reap_request SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_pool_control);
} se_pool_reap_control SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_pool_receipt);
} se_pool_reap_receipt SEC(".maps");
#include "shared_pool_opaque_reaper_chunk_candidate.h"
#include "shared_pool_reaper_transport_candidate.h"
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC
/* Disposable test authority only: it creates one synthetic parent in the
 * actual opaque maps so the real callbacks can be exercised while linked.
 * The selected image must never define this macro or expose these programs. */
#include "opaque_real_owner_live_bootstrap_diagnostic.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
/* Disposable BPF-only seed into the REAL fixed object/arena/binding maps.
 * Run once after bootstrap control and before any hook link is attached.
 * It bypasses native admission solely to exercise the source/reader/WORK
 * chain; the host manifest rejects this image as a product. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* Test-only fallback for the one seeded policy: 0 none, 1 allow, 2 deny.
 * Frozen by the controller before the seed runs; never product config. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_policy_verdict_fallback SEC(".maps");
/* Test-only rule count (1..256; 0 means 1). Rules 0..N-2 match only the
 * absent uid 4242; rule N-1 matches the expected uid, so an allow under a
 * deny fallback proves every window up to the last one was evaluated. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_policy_verdict_rules SEC(".maps");
/* Test-only role the matching rule proposes (0: none). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_policy_verdict_set_role SEC(".maps");
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
struct real_owner_seed_rules {
	__u32 rules, mode, match_cell, miss_cell, written, base, set_role;
	int error;
};
/* One test-only rule cell per iteration (an open-coded 256-cell loop was
 * too complex for the TC verifier on exact 6.18). */
static int real_owner_seed_rule(__u32 i, void *raw)
{
	struct real_owner_seed_rules *ctx = raw;
	if (i >= ctx->rules || i >= 256)
		return 1;
	__u32 cell = ctx->base + 9 + i;
	struct se_arena_cell *slot = bpf_map_lookup_elem(&se_arena, &cell);
	if (!slot) {
		ctx->error = 1;
		return 1;
	}
	struct fe_rule *r = (void *)slot;
	r->policy = 0;
	r->mode = ctx->mode;
	r->deny = 0;
	r->actor_image = -1;
	r->target_image = -1;
	r->stdin_pipe = -1;
	r->uid.base = i + 1 == ctx->rules ? ctx->match_cell : ctx->miss_cell;
	r->set_role = i + 1 == ctx->rules ? ctx->set_role : 0;
	r->uid.count = 1;
	ctx->written++;
	return 0;
}
#endif
SEC("tc")
int opaque_real_owner_policy_seed_diagnostic(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0, one = 1;
	const struct opaque_real_live_bootstrap_gate *gate =
		bpf_map_lookup_elem(&opaque_real_live_bootstrap_gate, &zero);
	const struct se_node_config *config =
		bpf_map_lookup_elem(&se_configuration, &zero);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* Layout: header 0, policy 1, rules 9..9+N-1, uid data after. More than
	 * 245 rules exceed a 256-cell slot; use the first 1024-cell object. */
	const __u32 *rules_value =
		bpf_map_lookup_elem(&opaque_real_policy_verdict_rules, &zero);
	__u32 seed_rules = rules_value && *rules_value ? *rules_value : 1;
	__u32 seed_object = 0, seed_class_size = 0, seed_base = 0;
	if (seed_rules > 256 || !config)
		return -1;
	if (seed_rules > 1 && 11 + seed_rules > 256)
		seed_object = config->slots[0];
	if (se_object_range(config, seed_object, &seed_class_size,
			    &seed_base) ||
	    se_object_capacity(seed_class_size) < 11 + seed_rules ||
	    seed_base > 0xffffU)
		return -1;
	__u32 base_zero = seed_base, base_one = seed_base + 1;
	__u32 base_nine = seed_base + 9, base_ten = seed_base + 10;
#else
	__u32 seed_rules = 1, seed_object = 0, seed_class_size = 0,
	      seed_base = 0;
	__u32 base_zero = 0, base_one = 1, base_nine = 9, base_ten = 10;
#endif
	struct se_shared_object *object =
		bpf_map_lookup_elem(&se_objects, &seed_object);
	struct se_arena_cell *header_cell =
		bpf_map_lookup_elem(&se_arena, &base_zero);
	struct se_arena_cell *policy_cell =
		bpf_map_lookup_elem(&se_arena, &base_one);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	struct se_arena_cell *rule_cell =
		bpf_map_lookup_elem(&se_arena, &base_nine);
	struct se_arena_cell *uid_cell =
		bpf_map_lookup_elem(&se_arena, &base_ten);
	const __u32 *expected_uid =
		bpf_map_lookup_elem(&opaque_real_owner_rule_uid_expect, &zero);
#endif
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &zero);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* Route, snapshot, object, policy and rule classes stay equal; the
	 * bootstrap control seeded the route/snapshot from the same gate. */
	const __u32 *fallback_value = bpf_map_lookup_elem(
		&opaque_real_policy_verdict_fallback, &zero);
	__u32 seed_class = gate ? gate->execution_class : 0;
	__u32 seed_fallback = fallback_value ? *fallback_value : ~0U;
	/* Explicit class only: the route/snapshot were seeded from this gate. */
	if (!gate || seed_class < 1 || seed_class > 2 || seed_fallback > 2)
		return -1;
#else
	__u32 seed_class = 1, seed_fallback = 0;
	if (gate && gate->execution_class != 0)
		return -1;
#endif
	if (!gate || gate->enabled != 1 || gate->scope != 10 ||
	    !se_profile_matches(config) || !object || !header_cell ||
	    !policy_cell || !binding ||
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	    !rule_cell || !uid_cell || !expected_uid ||
#endif
	    object->state.phase != SE_OBJECT_FREE ||
	    binding->state.scope != gate->scope ||
	    binding->state.records[0].phase != SE_SNAPSHOT_ACTIVE ||
	    binding->state.records[0].tickets[0].phase != SE_TICKET_EMPTY)
		return -1;
	struct fe_header *header = (void *)header_cell;
	struct fe_policy *policy = (void *)policy_cell;
	header->policies = 1;
	header->rule_base = 9;
	policy->uid = 1;
	policy->root_role = 1;
	policy->mode = seed_class;
	policy->fallback = seed_fallback;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	struct fe_rule *rule = (void *)rule_cell;
	header->rules = seed_rules;
	rule->policy = 0;
	rule->mode = seed_class;
	rule->actor_image = -1;
	rule->target_image = -1;
	rule->stdin_pipe = -1;
	rule->uid.base = 10;
	rule->uid.count = 1;
	((struct fm_blob *)uid_cell)->words[0] = *expected_uid;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	const __u32 *set_role_value = bpf_map_lookup_elem(
		&opaque_real_policy_verdict_set_role, &zero);
	__u32 seed_set_role = set_role_value ? *set_role_value : 0;
	if (seed_rules == 1)
		rule->set_role = seed_set_role;
	if (seed_rules > 1) {
		/* Cells: rules 9..9+N-1, matching uid 9+N, absent uid 9+N+1. */
		/* Rule uid lists hold object-relative cell indices. */
		__u32 match_cell = 9 + seed_rules, miss_cell = 10 + seed_rules;
		__u32 match_abs = seed_base + match_cell;
		__u32 miss_abs = seed_base + miss_cell;
		struct se_arena_cell *match =
			bpf_map_lookup_elem(&se_arena, &match_abs);
		struct se_arena_cell *miss =
			bpf_map_lookup_elem(&se_arena, &miss_abs);
		if (!match || !miss)
			return -1;
		((struct fm_blob *)match)->words[0] = *expected_uid;
		((struct fm_blob *)miss)->words[0] = 4242;
		struct real_owner_seed_rules ctx = { .rules = seed_rules,
						     .base = seed_base,
						     .set_role = seed_set_role,
						     .mode = seed_class,
						     .match_cell = match_cell,
						     .miss_cell = miss_cell };
		bpf_loop(256, real_owner_seed_rule, &ctx, 0);
		if (ctx.error || ctx.written != seed_rules)
			return -1;
	}
#endif
#endif
	object->state.generation = 1;
	object->state.slot = seed_object;
	object->state.size_class = seed_class_size;
	object->state.phase = SE_OBJECT_READY;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	/* Physical preparation reserves one post-rule data cell even for a rule
	 * with no data predicates: entries >= 10 + rules. */
	object->state.length = seed_rules > 1 ? 11 + seed_rules : 11;
	object->state.completed = object->state.length;
#else
	object->state.length = 10;
	object->state.completed = 10;
#endif
	object->state.pins = 1;
	object->state.execution_class = seed_class;
	struct se_pin_ticket *ticket = &binding->state.records[0].tickets[0];
	ticket->scope = gate->scope;
	ticket->snapshot_serial = 1;
	ticket->object_generation = 1;
	ticket->position = 0;
	ticket->object_slot = seed_object;
	ticket->phase = SE_TICKET_HELD;
	return 0;
}
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) &&   \
	(defined(ENFORCE_EXEC_POOL_OPAQUE_ROUTE_MIGRATION_DIAGNOSTIC) || \
	 defined(ENFORCE_EXEC_POOL_OPAQUE_RELOAD_DIAGNOSTIC))
/* G025 steps 7/8, test-only second policy in fixed 256-cell object 1, with
 * one rule for the expected uid. binding 1 tickets it into the second
 * route's ACTIVE snapshot (migration); binding 0 leaves it READY and
 * unpinned for the generation advance (reload: same class, the frozen
 * fallback may differ). Run once after the first seed, before any link. */
struct opaque_real_second_policy {
	__u32 execution_class, fallback, binding, enabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_second_policy);
} opaque_real_second_policy SEC(".maps");
SEC("tc")
int opaque_real_owner_second_policy_seed(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0, one = 1, class_size = 0, base = 0;
	const struct opaque_real_second_policy *want =
		bpf_map_lookup_elem(&opaque_real_second_policy, &zero);
	const struct se_node_config *config =
		bpf_map_lookup_elem(&se_configuration, &zero);
	const __u32 *expected_uid =
		bpf_map_lookup_elem(&opaque_real_owner_rule_uid_expect, &zero);
	const __u32 *set_role_value = bpf_map_lookup_elem(
		&opaque_real_policy_verdict_set_role, &zero);
	if (!want || want->enabled != 1 || want->execution_class < 1 ||
	    want->execution_class > 2 || want->fallback > 2 ||
	    want->binding > 1 || !config || !expected_uid ||
	    !se_profile_matches(config) ||
	    se_object_range(config, 1, &class_size, &base) ||
	    se_object_capacity(class_size) < 11 || base > 0xffffU)
		return -1;
	__u32 header_index = base, policy_index = base + 1;
	__u32 rule_index = base + 9, uid_index = base + 10;
	struct se_shared_object *object =
		bpf_map_lookup_elem(&se_objects, &one);
	struct se_arena_cell *header_cell =
		bpf_map_lookup_elem(&se_arena, &header_index);
	struct se_arena_cell *policy_cell =
		bpf_map_lookup_elem(&se_arena, &policy_index);
	struct se_arena_cell *rule_cell =
		bpf_map_lookup_elem(&se_arena, &rule_index);
	struct se_arena_cell *uid_cell =
		bpf_map_lookup_elem(&se_arena, &uid_index);
	struct se_shared_binding *binding =
		want->binding ? bpf_map_lookup_elem(&se_bindings, &one) : 0;
	if (!object || !header_cell || !policy_cell || !rule_cell ||
	    !uid_cell || object->state.phase != SE_OBJECT_FREE)
		return -1;
	if (want->binding &&
	    (!binding || binding->state.scope != 11 ||
	     binding->state.records[0].phase != SE_SNAPSHOT_ACTIVE ||
	     binding->state.records[0].execution_class !=
		     want->execution_class ||
	     binding->state.records[0].tickets[0].phase != SE_TICKET_EMPTY))
		return -1;
	struct fe_header *header = (void *)header_cell;
	struct fe_policy *policy = (void *)policy_cell;
	struct fe_rule *rule = (void *)rule_cell;
	header->policies = 1;
	header->rule_base = 9;
	header->rules = 1;
	policy->uid = 1;
	policy->root_role = 1;
	policy->mode = want->execution_class;
	policy->fallback = want->fallback;
	rule->policy = 0;
	rule->mode = want->execution_class;
	rule->actor_image = -1;
	rule->target_image = -1;
	rule->stdin_pipe = -1;
	rule->uid.base = 10;
	rule->uid.count = 1;
	rule->set_role = set_role_value ? *set_role_value : 0;
	((struct fm_blob *)uid_cell)->words[0] = *expected_uid;
	object->state.generation = 1;
	object->state.slot = 1;
	object->state.size_class = class_size;
	object->state.phase = SE_OBJECT_READY;
	object->state.length = 11;
	object->state.completed = 11;
	object->state.pins = want->binding ? 1 : 0;
	object->state.execution_class = want->execution_class;
	if (binding) {
		struct se_pin_ticket *ticket =
			&binding->state.records[0].tickets[0];
		ticket->scope = 11;
		ticket->snapshot_serial = 1;
		ticket->object_generation = 1;
		ticket->position = 0;
		ticket->object_slot = 1;
		ticket->phase = SE_TICKET_HELD;
	}
	return 0;
}
#endif
#endif
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
/* Keep recovered-admin capture's lock frame out of the charged source
 * constructor's older-kernel call chain. The callee relooks the original
 * recovery maps; no map-value pointer crosses this boundary. */
static __attribute__((noinline)) int
real_owner_child_recovery_capture(struct task_struct *child,
				  unsigned long clone_flags, int prior)
{
	return se_rm_capture(child, clone_flags, prior);
}
static __attribute__((noinline)) void
real_owner_child_recovery_close(struct task_struct *physical)
{
	se_rm_close(physical);
}
#endif

/* The native-config opt-in is a source-shape prerequisite, NOT an activation
 * switch: no product host admits this incomplete image. Configuration must
 * be installed and frozen before hooks attach. Ordinary diagnostics retain
 * their separate test-only gate. */
#ifndef ENFORCE_EXEC_POOL_OPAQUE_NATIVE_CONFIG_GATE_CANDIDATE
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_child_gate SEC(".maps");
#endif
static __always_inline int real_owner_image_configured(void)
{
	__u32 zero = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_NATIVE_CONFIG_GATE_CANDIDATE
	const struct se_node_config *config =
		bpf_map_lookup_elem(&se_configuration, &zero);
	return se_profile_matches(config);
#else
	const __u32 *armed =
		bpf_map_lookup_elem(&opaque_real_owner_child_gate, &zero);
	return armed && *armed == 1;
#endif
}
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_child_targets SEC(".maps");

#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
#error "final failed-exec probe requires the source-owned reader receipt"
#endif
/* Exact-build Rocky 4.18 diagnostic, not a portable product attachment.
 * Both frames are BPF-only. A missed or nested entry is an uncertain terminal,
 * never permission to finalize a receipt or preserve a trusted audit role. */
struct se_failure_outer_frame {
	__u64 physical, bprm, cookie, locator, invocation, scope, generation;
	__u32 depth, uncertain;
};
struct se_failure_handler_frame {
	__u64 bprm;
	__u32 depth, uncertain;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_FAILURE_FRAME_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct se_failure_outer_frame);
} se_failure_outer_frames SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_FAILURE_FRAME_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct se_failure_handler_frame);
} se_failure_handler_frames SEC(".maps");

static __always_inline int real_owner_failure_scope(void)
{
	__u64 cgroup = bpf_get_current_cgroup_id();
	return real_owner_image_configured() && cgroup &&
	       se_opaque_real_route_index(&cgroup) != 0;
}
static __always_inline int real_owner_failure_frame_ready(__u64 key, __u64 bprm)
{
	struct se_failure_outer_frame *outer =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	struct se_failure_handler_frame *handler =
		bpf_map_lookup_elem(&se_failure_handler_frames, &key);
	return outer && handler && key && bprm && outer->physical == key &&
	       outer->depth == 1 && !outer->uncertain && !outer->bprm &&
	       handler->bprm == bprm && handler->depth == 1 &&
	       !handler->uncertain;
}
static __always_inline int
real_owner_failure_bind_receipt(const struct se_exec_terminal_receipt *receipt)
{
	if (!receipt ||
	    !real_owner_failure_frame_ready(receipt->physical, receipt->bprm))
		return -1;
	struct se_failure_outer_frame *outer = bpf_map_lookup_elem(
		&se_failure_outer_frames, &receipt->physical);
	if (!outer || !receipt->cookie || !receipt->locator ||
	    !receipt->invocation || !receipt->scope || !receipt->generation)
		return -1;
	outer->bprm = receipt->bprm;
	outer->cookie = receipt->cookie;
	outer->locator = receipt->locator;
	outer->invocation = receipt->invocation;
	outer->scope = receipt->scope;
	outer->generation = receipt->generation;
	return 0;
}

SEC("kprobe/do_execveat_common.isra.38")
int BPF_KPROBE(opaque_real_owner_failure_outer_enter)
{
	if (!real_owner_failure_scope())
		return 0;
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_failure_outer_frame *old =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	if (old) {
		old->uncertain = 1;
		if (old->depth < 255)
			old->depth++;
		return 0;
	}
	struct se_failure_outer_frame frame = { .physical = key, .depth = 1 };
	if (key && bpf_map_update_elem(&se_failure_outer_frames, &key, &frame,
				       BPF_NOEXIST))
		SE_DEFERRED_STORAGE_REFUSED(1);
	return 0;
}
SEC("kprobe/search_binary_handler")
int BPF_KPROBE(opaque_real_owner_failure_handler_enter,
	       struct linux_binprm *bprm)
{
	if (!real_owner_failure_scope())
		return 0;
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_failure_outer_frame *outer =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	if (!outer || outer->uncertain || outer->depth != 1 ||
	    outer->physical != key || !bprm)
		return 0;
	struct se_failure_handler_frame *old =
		bpf_map_lookup_elem(&se_failure_handler_frames, &key);
	if (old) {
		old->uncertain = outer->uncertain = 1;
		if (old->depth < 255)
			old->depth++;
		return 0;
	}
	struct se_failure_handler_frame frame = {
		.bprm = (__u64)bprm,
		.depth = 1,
	};
	if (bpf_map_update_elem(&se_failure_handler_frames, &key, &frame,
				BPF_NOEXIST))
		SE_DEFERRED_STORAGE_REFUSED(2);
	return 0;
}
SEC("kretprobe/search_binary_handler")
int BPF_KRETPROBE(opaque_real_owner_failure_handler_exit, int ret)
{
	(void)ret;
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_failure_handler_frame *frame =
		bpf_map_lookup_elem(&se_failure_handler_frames, &key);
	if (frame) {
		if (frame->depth > 1)
			frame->depth--;
		else
			(void)bpf_map_delete_elem(&se_failure_handler_frames,
						  &key);
	}
	return 0;
}
SEC("kretprobe/do_execveat_common.isra.38")
int BPF_KRETPROBE(opaque_real_owner_failure_outer_exit, int ret)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_failure_outer_frame *frame =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	if (!frame)
		return 0;
	if (frame->depth > 1) {
		frame->depth--;
		return 0;
	}
	/* Only a failed outer exec may publish FAILURE here. A successful
	 * exec's terminal comes from the actual sched_process_exec event; a
	 * zero return is not independent proof that its tracepoint ran. */
	if (ret < 0 && frame->depth == 1 && !frame->uncertain &&
	    frame->physical == key && frame->bprm && frame->cookie &&
	    frame->locator && frame->invocation && frame->scope &&
	    frame->generation) {
		struct se_exec_terminal_receipt *receipt =
			bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
		(void)real_owner_terminal_transition(
			receipt, key, frame->bprm, frame->cookie,
			frame->locator, frame->invocation, frame->scope,
			frame->generation, SE_EXEC_TERMINAL_FAILURE);
	}
	(void)bpf_map_delete_elem(&se_failure_handler_frames, &key);
	(void)bpf_map_delete_elem(&se_failure_outer_frames, &key);
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAILURE_SOURCE_COMPLETION_DIAGNOSTIC
/* End this producer's lexical frame before entering lock-bearing completion.
 * The independent outer tuple authenticates the receipt; the inner handler
 * frame has already returned and cannot be required here. */
static __attribute__((noinline)) int
real_owner_failure_fexit_publish(__u64 key, __u64 bprm)
{
	const struct se_failure_outer_frame *frame =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	if (!key || !bprm || !frame || frame->depth != 1 || frame->uncertain ||
	    frame->physical != key || frame->bprm != bprm || !frame->cookie ||
	    !frame->locator || !frame->invocation || !frame->scope ||
	    !frame->generation)
		return 0;
	struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	return real_owner_terminal_transition(receipt, key, bprm, frame->cookie,
					      frame->locator, frame->invocation,
					      frame->scope, frame->generation,
					      SE_EXEC_TERMINAL_FAILURE);
}

/* Exact-AL2023 diagnostic, not a selected product source. The enclosing
 * user-exec frame remains live while bprm_execve returns; no ordering between
 * fexit and a kretprobe on the same function is assumed. kernel_execve lacks
 * that outer frame and is deliberately not certified by this variant. */
SEC("fexit/bprm_execve")
int BPF_PROG(opaque_real_owner_failure_fexit_probe, struct linux_binprm *bprm)
{
	__u64 raw = 0;
	if (bpf_get_func_ret(ctx, &raw) || (__s32)raw >= 0)
		return 0;
	__u64 key = (__u64)bpf_get_current_task_btf();
	if (real_owner_failure_fexit_publish(key, (__u64)bprm))
		(void)real_owner_work_completion_shape(key);
	/* Outer kretprobe still cleans its frames. If completion retired the
	 * receipt, its later terminal CAS is a no-op, not a second completion. */
	return 0;
}
#endif
#endif

static __attribute__((noinline)) int
real_owner_child_release_claim(struct se_route_claim *claim)
{
	struct se_route_anchor *route = route_lookup(claim->slot);
	if (!route)
		return -1;
	bpf_spin_lock(&route->lock);
	int released = se_route_release_locked(route, claim);
	bpf_spin_unlock(&route->lock);
	return released;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_INITIAL_TASK_DIAGNOSTIC
#include "opaque_real_owner_initial_task_diagnostic.h"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_RECOVERED_INITIAL_TASK_DIAGNOSTIC
#include "opaque_real_owner_recovered_initial_task_diagnostic.h"
#endif

/* Isolate the short-lived observation/lease frame while keeping TASK open's
 * internal lexical checks inline in this one BPF function. */
static __attribute__((noinline)) int
real_owner_child_open_parent(struct se_ol_payload_handle *parent)
{
	__u64 parent_key = (__u64)bpf_get_current_task_btf();
	return se_ol_task_open(&parent_key, parent);
}

/* Source frame: prepare a canonical parent projection under the real route
 * claim, then suspend the exact WORK. No pointer, claim or stack address
 * crosses the tail call. The WORK retains its TASK owner reference. */
static __attribute__((noinline)) int
real_owner_child_start_work(struct se_ol_payload_handle *parent,
			    struct se_owk_ticket *ticket)
{
	if (se_owk_bind_owner(parent) != SE_OL_OK)
		return -1;
	/* begin's CONTENDED: a sibling charged the chosen bit (its credit, not
	 * ours) and our pin was rolled back. Each lost attempt still consumes a
	 * sequence cookie and task->next_work_sequence (SE_OWK_COOKIE_LIMIT). */
	int began = SE_OL_CONTENDED;
#pragma clang loop unroll(disable)
	for (__u32 attempt = 0; attempt < SE_PROFILE_WORK_RETRIES; attempt++) {
		__u32 work_slot = 0;
		if (se_owk_choose(parent, &work_slot) != SE_OL_OK)
			return -1;
		began = se_owk_begin(parent, work_slot, ticket);
		if (began != SE_OL_CONTENDED)
			break;
	}
	if (began != SE_OL_OK) {
		/* Bound exhausted: recoverable contention, refused uncharged. */
		if (began == SE_OL_CONTENDED)
			SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_WORK_RETRY);
		return -1;
	}
	if (se_owk_attach_owner(parent, ticket) != SE_OL_OK ||
	    se_owk_initialize_payload(parent, ticket) != SE_OL_OK ||
	    se_owk_commit(parent, ticket) != SE_OL_OK)
		return -1;
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
static __attribute__((noinline)) int
real_owner_policy_prepare(struct se_invocation *work, __u64 scope,
			  __u64 generation, const struct se_snapshot *snapshot)
{
	return se_prepare_policy_view(&work->view, scope, snapshot, generation);
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
/* The source has already consumed its lexical TASK/WORK handles. The current
 * physical TASK and suspended WORK must be reauthenticated by this target
 * before calling here; the scalar token is not an entry capability. */
static __attribute__((noinline)) int
real_owner_policy_stage_begin(struct se_owk_payload *payload)
{
	struct se_invocation *work = &payload->semantic;
	struct fm_global_token *token =
		&work->observation.stage_workspace.token;
	if (token->reserved || token->slot != work->slot ||
	    token->cookie != work->cookie ||
	    real_owner_stage_view(token) != &work->view)
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
		return -1;
#else
		return 0;
#endif
	int began = fe_stage_begin((void *)token, &work->observation.facts,
				   &work->observation.evaluator,
				   &work->observation.stage_cursor);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	if (began)
		return -2;
	return work->observation.stage_cursor.state >= FE_STAGE_ACTIVE ? 1 : -3;
#else
	return began == 0 &&
	       work->observation.stage_cursor.state >= FE_STAGE_ACTIVE;
#endif
}
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE)
/* Rule advances per rule-program invocation. While the cursor stays ACTIVE
 * the rule program re-enters itself through its class graph, so 256 rules
 * need at most 16 windows, within the tail-call budget after the
 * begin -> policy -> prepare -> stage hops. Alternatives measured on the
 * exact AL2023 kernels (g005b-verdict-load-20261109): an open-coded 256-step
 * loop and a bpf_for iterator exceeded the 8192 pending-jump limit (6.18);
 * a bpf_loop callback frame exceeded the 8-frame call depth (6.12). */
#define REAL_OWNER_RULE_WINDOW_STEPS 16
/* begin -> policy -> prepare -> stage -> rule x windows -> finish. */
_Static_assert(256 / REAL_OWNER_RULE_WINDOW_STEPS + 4 <= 33,
	       "rule windows must fit the tail-call budget");
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
static __attribute__((always_inline)) inline int
real_owner_policy_rule_window(struct se_owk_payload *payload)
{
	struct se_invocation *work = &payload->semantic;
	struct fm_global_token *token =
		&work->observation.stage_workspace.token;
	if (token->reserved || token->slot != work->slot ||
	    token->cookie != work->cookie ||
	    real_owner_stage_view(token) != &work->view)
		return -1;
	/* Current-task credentials are stable in this non-sleepable callback.
	 * The UID helper reports real UID, not the effective UID policy fact.
	 * Failed CO-RE reads leave the fact UNKNOWN, never inferred as root. */
	struct task_struct *task = bpf_get_current_task_btf();
	const struct cred *cred = 0;
	__u32 effective_uid = 0;
	work->observation.facts.effective_uid = 0;
	work->observation.facts.uid_known = 0;
	if (task && !BPF_CORE_READ_INTO(&cred, task, cred) && cred &&
	    !BPF_CORE_READ_INTO(&effective_uid, cred, euid.val)) {
		work->observation.facts.effective_uid = effective_uid;
		work->observation.facts.uid_known = 1;
	}
	real_owner_rule_progress(3, work->observation.facts.effective_uid);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#pragma clang loop unroll(disable)
	for (__u32 step = 0; step < REAL_OWNER_RULE_WINDOW_STEPS; step++) {
		if (work->observation.stage_cursor.state != FE_STAGE_ACTIVE)
			break;
		if (fe_stage_advance(
			    (void *)token, &work->observation.facts,
			    &work->observation.evaluator,
			    &work->observation.stage_cursor,
			    &work->observation.stage_workspace.alt_request) !=
		    0)
			return -2;
	}
	if (work->observation.stage_cursor.state == FE_STAGE_ACTIVE)
		return 2; /* more rules: re-enter through the class graph */
#else
	if (work->observation.stage_cursor.state == FE_STAGE_ACTIVE &&
	    fe_stage_advance((void *)token, &work->observation.facts,
			     &work->observation.evaluator,
			     &work->observation.stage_cursor,
			     &work->observation.stage_workspace.alt_request) !=
		    0)
		return -2;
#endif
	if (work->observation.stage_cursor.state != FE_STAGE_READY)
		return -3;
	if (fe_stage_finish((void *)token, &work->observation.evaluator,
			    &work->observation.stage_cursor) != 0)
		return -4;
	if (work->observation.stage_cursor.state != FE_STAGE_FINISHED)
		return -5;
	if (work->observation.evaluator.decision.error != FE_OK
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	    && work->observation.evaluator.decision.error != FE_AUDIT_UNKNOWN
#endif
	)
		return -6;
	real_owner_rule_progress(
		2, work->observation.evaluator.decision.matched_rules[0] & 1);
	return 1;
}
static __attribute__((always_inline)) inline int
real_owner_policy_rule_claimed_eval(__u64 scope)
{
	struct se_owk_payload *payload =
		se_owk_suspended_current(scope, REAL_OWNER_EVAL_STAGE, 3);
	return payload ? real_owner_policy_rule_window(payload) : -7;
}
#endif
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* Separate frame: inlined into the bridge, history snapshot + catalogue +
 * role classification pushed the policy program past 1M processed
 * instructions on exact AL2023 6.18 (g005b-verdict-load-20261109). */
static __attribute__((noinline)) int
real_owner_prepare_reader_frame(struct se_owk_semantic_handle *semantic,
				const struct se_exec_terminal_receipt *receipt,
				__u64 physical)
{
	return se_owk_exec_prepare_reader(semantic, receipt, physical);
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#error "evaluation WORK witness requires the real-policy verdict candidate"
#endif
/* Test-only evaluation WORK witness, read by the attached verdict test.
 * [0] policy bridge entered; [1] evaluation start_work refused before any
 * WORK was charged; [2] start_work failed after a charge; [3] the reader was
 * quarantined exactly and its receipt retired (abort handoff); [4] an exact
 * receipt was found but the abort handoff failed. Leaf frame only. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 5);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_eval_work_outcomes SEC(".maps");
static __attribute__((noinline)) void real_owner_eval_work_outcome(__u32 index)
{
	__u32 key = index < 5 ? index : 4;
	__u64 *count =
		bpf_map_lookup_elem(&opaque_real_eval_work_outcomes, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#endif
/* The caller first authenticates the retained reader against the original
 * binding. Its TASK lease brackets every policy read. WORK is DONE before
 * return; this test cut never emits a verdict or role. */
static __attribute__((noinline)) int
real_owner_policy_bridge(struct se_ol_payload_handle *owner, __u64 scope,
			 __u64 generation, const struct se_snapshot *snapshot)
{
	if (!owner || !scope || !generation || !snapshot ||
	    snapshot->scope != scope || snapshot->generation != generation ||
	    !snapshot->serial || !snapshot->claims)
		return -1;
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC
	real_owner_eval_work_outcome(0);
#endif
	if (real_owner_child_start_work(owner, &ticket)) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC
		real_owner_eval_work_outcome(ticket.held ? 2 : 1);
#endif
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_EVAL_WORK);
		goto failed;
	}
	if (se_owk_semantic_open(owner, &ticket, &semantic, &work) != SE_OL_OK)
		goto failed;
	int valid = real_owner_policy_prepare(work, scope, generation,
					      snapshot) == 0;
	/* Issue the token straight into this WORK's workspace: a stack copy put
	 * the verdict policy chain 16 bytes over the 512-byte combined stack on
	 * exact AL2023 6.18 (g005b-verdict-load-20261109). */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
	struct fm_global_token *token =
		&work->observation.stage_workspace.token;
#else
	struct fm_global_token token_storage = {};
	struct fm_global_token *token = &token_storage;
#endif
	if (valid)
		valid = se_owk_evaluator_token(&semantic, token) == SE_OL_OK &&
			se_owk_view_from_identity(token->slot, token->cookie) ==
				&work->view;
/* Verdict build: history/catalogue/role preparation runs in the separate
 * prepare program after this suspension (real_owner_prepare_frame). */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
	if (valid) {
		/* Source facts and the complete verdict path remain separate
		 * gates. A prepared history alone grants no policy decision. */
		__builtin_memset(&work->observation.stage_cursor, 0,
				 sizeof(work->observation.stage_cursor));
		if (se_owk_semantic_suspend(&semantic, &work, 1) == SE_OL_OK)
			return 1;
		valid = 0;
	}
#endif
	int closed = semantic.held && work &&
		     se_owk_semantic_done(&semantic, &work) == SE_OL_OK;
	return valid && closed ? 0 : -1;
failed:
	if (semantic.held && work)
		(void)se_owk_semantic_done(&semantic, &work);
	if (ticket.held) {
		if (ticket.stage == 0)
			(void)se_owk_abort_building(owner, &ticket);
		else if (ticket.stage == 1 || ticket.stage == 2)
			(void)se_owk_abort(owner, &ticket);
		else if (ticket.stage == 3)
			(void)se_owk_done(owner, &ticket);
	}
	return -1;
}
#endif
static __attribute__((noinline)) int
real_owner_child_prepare(const struct se_route_claim *claim,
			 __u64 *parent_cookie_out)
{
	if (!parent_cookie_out)
		return -1;
	*parent_cookie_out = 0;
	struct se_ol_payload_handle parent = {};
	if (real_owner_child_open_parent(&parent) != SE_OL_OK)
		return -1;
	struct se_owk_ticket ticket = {};
	if (real_owner_child_start_work(&parent, &ticket)) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
		if (!ticket.held)
			real_owner_birth_outcome(0);
#endif
		goto work_failure;
	}
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	if (se_owk_semantic_open(&parent, &ticket, &semantic, &work) !=
	    SE_OL_OK)
		goto work_failure;
	int valid =
		se_op_parent_snapshot_held(&parent, &semantic, work, claim) ==
			SE_OL_OK &&
		se_op_parent_project_held(&semantic, work, claim) == SE_OL_OK;
	if (!valid) {
		se_owk_fault_ticket(&ticket);
		(void)se_owk_semantic_done(&semantic, &work);
		goto close_parent;
	}
	__u64 parent_cookie = parent.lease.cookie;
	if (se_owk_semantic_suspend(&semantic, &work, 1) != SE_OL_OK)
		goto work_failure;
	if (se_ol_payload_close(&parent) != SE_OL_OK)
		return -2;
	*parent_cookie_out = parent_cookie;
	return 0;
work_failure:
	if (ticket.held) {
		if (ticket.stage == 0)
			(void)se_owk_abort_building(&parent, &ticket);
		else if (ticket.stage == 1 || ticket.stage == 2)
			(void)se_owk_abort(&parent, &ticket);
		else if (ticket.stage == 3)
			(void)se_owk_done(&parent, &ticket);
	}
close_parent:
	(void)se_ol_payload_close(&parent);
	return -1;
}

static __attribute__((noinline)) void real_owner_child_missing_target(void)
{
	__u64 parent_key = (__u64)bpf_get_current_task_btf();
	struct se_ol_payload_handle parent = {};
	struct se_owk_ticket ticket = {};
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	real_owner_birth_outcome(7);
#endif
	SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_MISSING_TARGET);
	if (se_ol_task_open(&parent_key, &parent) == SE_OL_OK) {
		if (se_owk_resume(&parent, 1, &ticket) == SE_OL_OK)
			(void)se_owk_done(&parent, &ticket);
		(void)se_ol_payload_close(&parent);
	}
}

#if (defined(ENFORCE_EXEC_POOL_OPAQUE_BIRTH_CLOSE_FAULT_DIAGNOSTIC) ||     \
     defined(ENFORCE_EXEC_POOL_OPAQUE_BIRTH_RELEASE_FAULT_DIAGNOSTIC)) &&  \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC))
#error "birth fault injection requires successful-birth disposable bootstrap"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
/* This issue is not proof of a successful fork. A zero row is allocated
 * while the original claim is held; raw sched_process_fork must later see
 * the same physical parent/child and exact charged child before eligibility. */
static __attribute__((noinline)) int
real_owner_child_birth_issue(struct task_struct *child,
			     const struct se_route_claim *claim,
			     __u64 parent_cookie)
{
	if (!child || !claim || !claim->owned || claim->reserved ||
	    !claim->scope || !claim->generation || !claim->serial ||
	    !parent_cookie)
		return -1;
	__u32 zero = 0;
	const struct opaque_birth_receipt *template =
		bpf_map_lookup_elem(&opaque_birth_receipt_zero, &zero);
	__u64 key = (__u64)child;
	if (!template)
		return -1;
	if (bpf_map_update_elem(&opaque_birth_receipts, &key, template,
				BPF_NOEXIST)) {
		SE_DEFERRED_STORAGE_REFUSED(3);
		return -1;
	}
	struct opaque_birth_receipt *receipt =
		bpf_map_lookup_elem(&opaque_birth_receipts, &key);
	if (!receipt || receipt->state || receipt->child)
		return -1;
	receipt->child = key;
	receipt->parent = (__u64)bpf_get_current_task_btf();
	receipt->parent_cookie = parent_cookie;
	receipt->scope = claim->scope;
	receipt->generation = claim->generation;
	receipt->serial = claim->serial;
	receipt->slot = claim->slot;
	receipt->incarnation = claim->incarnation;
	receipt->record = claim->record;
	receipt->state = 1;
	return receipt->parent ? 0 : -1;
}

/* A failed post-transition close must not leave a usable qualified TASK.
 * Only the exact charged generation is poisoned; a reused pointer is not
 * sufficient authority. The receipt also remains faulted if reopening fails. */
static __attribute__((noinline)) void
real_owner_birth_quarantine(__u64 key, __u64 cookie, __u64 locator)
{
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&key, &owner) != SE_OL_OK)
		return;
	struct se_task_state *task = 0;
	if (se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		if (owner.lease.cookie == cookie &&
		    owner.lease.locator == locator &&
		    task->physical_cookie == cookie) {
			if (!(task->flags & SE_TASK_QUARANTINED)) {
				task->flags |= SE_TASK_QUARANTINED;
				if (task->eligibility_version < ~0ULL - 1)
					task->eligibility_version++;
			}
			if (task->exec.owned)
				se_exec_fault_locked(&task->exec);
		}
		se_op_task_semantic_end(&owner, &task);
	}
	(void)se_ol_payload_close(&owner);
}

/* 1: qualified; 0: no eligible receipt; -1: uncertain transition. State 4
 * is a sticky in-flight/fault marker, installed before touching TASK flags.
 * First-use LSM callers must propagate -1 through their Audit/Strict gate. */
static __attribute__((noinline)) int
real_owner_birth_qualify(struct task_struct *target)
{
	__u64 key = (__u64)target;
	struct opaque_birth_receipt *receipt =
		bpf_map_lookup_elem(&opaque_birth_receipts, &key);
	if (receipt && receipt->state == 4)
		return -1;
	if (!receipt || receipt->state != 2 || receipt->child != key ||
	    !receipt->parent || !receipt->parent_cookie ||
	    !receipt->child_cookie || !receipt->child_locator ||
	    !receipt->scope || !receipt->generation || !receipt->serial ||
	    receipt->slot >= SE_PROFILE_BINDINGS || receipt->reserved)
		return 0;
	__u64 cgroup = 0;
	if (BPF_CORE_READ_INTO(&cgroup, target, cgroups, dfl_cgrp, kn, id) ||
	    !cgroup)
		return 0;
	struct se_route_claim claim = {};
	if (se_route_admit(cgroup, &claim) != SE_ROUTE_OWNED)
		return 0;
	int same_claim = claim.scope == receipt->scope &&
			 claim.generation == receipt->generation &&
			 claim.serial == receipt->serial &&
			 claim.slot == receipt->slot &&
			 claim.incarnation == receipt->incarnation &&
			 claim.record == receipt->record;
	__u64 cookie = receipt->child_cookie, locator = receipt->child_locator;
	__u64 parent = receipt->parent, parent_cookie = receipt->parent_cookie;
	int qualified = 0, transitioned = 0;
	if (same_claim) {
		/* The current task cannot race its own fork/exec first use. The
		 * fault marker also prevents a later use from trusting a partial
		 * transition when lexical ownership cleanup fails. */
		receipt->state = 4;
		struct se_ol_payload_handle owner = {};
		if (se_ol_task_open(&key, &owner) == SE_OL_OK) {
			struct se_task_state *task = 0;
			if (se_op_task_semantic_begin(&owner, &task) ==
			    SE_OL_OK) {
				if (!owner.lease.meta->cleanup_error &&
				    owner.lease.cookie == cookie &&
				    owner.lease.locator == locator &&
				    task->physical_cookie == cookie &&
				    task->flags == SE_TASK_LIVE &&
				    task->scope_cookie == claim.scope &&
				    task->scope_slot == claim.slot &&
				    task->committed.version &&
				    !task->exec.owned && !task->reader.owned &&
				    !task->next_invocation) {
					task->flags = SE_TASK_QUALIFIED;
					qualified = transitioned = 1;
				}
				se_op_task_semantic_end(&owner, &task);
			}
			if (se_ol_payload_close(&owner) != SE_OL_OK)
				qualified = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_BIRTH_CLOSE_FAULT_DIAGNOSTIC
			/* Exercise uncertain-close remediation after the real close;
			 * this does not model a leaked lexical lease. */
			qualified = 0;
#endif
		}
	}
	/* release may clear claim ownership; retain original identity scalars
	 * in claim itself, as required by se_route_release_locked. */
	int released = real_owner_child_release_claim(&claim);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_BIRTH_RELEASE_FAULT_DIAGNOSTIC
	/* Likewise, inject the result without deliberately leaking a claim. */
	if (transitioned)
		released = -1;
#endif
	receipt = bpf_map_lookup_elem(&opaque_birth_receipts, &key);
	if (qualified && !released && receipt && receipt->state == 4 &&
	    receipt->child == key && receipt->child_cookie == cookie &&
	    receipt->child_locator == locator && receipt->parent == parent &&
	    receipt->parent_cookie == parent_cookie &&
	    receipt->scope == claim.scope &&
	    receipt->generation == claim.generation &&
	    receipt->serial == claim.serial && receipt->slot == claim.slot &&
	    receipt->incarnation == claim.incarnation &&
	    receipt->record == claim.record && !receipt->reserved) {
		receipt->state = 3;
		return 1;
	}
	if (transitioned)
		real_owner_birth_quarantine(key, cookie, locator);
	return same_claim || released ? -1 : 0;
}

SEC("lsm/task_kill")
long BPF_PROG(opaque_real_owner_birth_signal0_diagnostic,
	      struct task_struct *target, struct kernel_siginfo *info,
	      int signal, const struct cred *cred, int prior)
{
	(void)info;
	(void)cred;
	if (prior || signal || !target || !real_owner_image_configured())
		return prior;
	(void)real_owner_birth_qualify(target);
	return 0;
}
#endif

/* Keep the route claim's stack quantum out of the LSM wrapper. A source
 * return of -2 means a suspended WORK may remain and needs exact fallback. */
static __attribute__((noinline)) int
real_owner_child_prepare_claimed(struct task_struct *child,
				 unsigned long clone_flags, __u32 *mode_out,
				 int terminal_fault)
{
	struct se_route_claim claim = {};
	int admission = se_route_admit(bpf_get_current_cgroup_id(), &claim);
	if (admission != SE_ROUTE_OWNED) {
		*mode_out = admission == SE_ROUTE_STRICT_FAULT ||
					    admission ==
						    SE_ROUTE_INVARIANT_FAULT ?
				    2 :
				    1;
		return -1;
	}
	*mode_out = claim.execution_class;
	if (terminal_fault) {
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_SOURCE);
		(void)real_owner_child_release_claim(&claim);
		return -1;
	}
	__u64 parent_cookie = 0;
	int result = clone_flags & (1ULL << 33) ?
			     -1 :
			     real_owner_child_prepare(&claim, &parent_cookie);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	if (!result &&
	    real_owner_child_birth_issue(child, &claim, parent_cookie))
		result =
			-2; /* finish the suspended WORK, never construct a child */
#endif
	int released = real_owner_child_release_claim(&claim);
	if (released && result == 0)
		return -2;
	if (result == -1)
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_SOURCE);
	return result;
}

SEC("lsm/task_alloc")
long BPF_PROG(opaque_real_owner_child_source_candidate,
	      struct task_struct *child, unsigned long clone_flags, int prior)
{
	(void)child;
	/* Preserve the verifier's signed LSM retval range. The BPF_PROG int
	 * argument cast can lose that range on newer kernels. */
	__s64 prior_ret = (__s64)ctx[2];
	if (prior_ret)
		return prior_ret;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	/* A reused task_struct address must never inherit a prior receipt. If
	 * deletion fails, NOEXIST at publication leaves it unqualified. */
	__u64 birth_key = (__u64)child;
	(void)bpf_map_delete_elem(&opaque_birth_receipts, &birth_key);
#endif
	if (!real_owner_image_configured())
		return 0;
	int birth_fault = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	birth_fault =
		real_owner_birth_qualify(
			(struct task_struct *)bpf_get_current_task_btf()) < 0;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
	int recovery_ret =
		real_owner_child_recovery_capture(child, clone_flags, prior);
	if (recovery_ret)
		return -1; /* prior was zero; recovery may only refuse this fork */
#endif
	int terminal_fault = birth_fault;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_TERMINAL_DRAIN_DIAGNOSTIC
	/* Finish the terminal outside the route-claim/parent-projection frame.
	 * An uncertain Audit fork remains nonblocking, without trusted roles. */
	terminal_fault |= real_owner_source_terminal_drain();
	if (terminal_fault)
		(void)real_owner_reader_quarantine_pending(
			(__u64)bpf_get_current_task_btf());
#endif
	__u32 mode = 1;
	int prepared = real_owner_child_prepare_claimed(child, clone_flags,
							&mode, terminal_fault);
	if (prepared) {
		if (prepared == -2)
			real_owner_child_missing_target();
		if (mode == 2)
			return -1;
		return 0;
	}
	bpf_tail_call(ctx, &opaque_real_owner_child_targets, 0);
	/* Missing target is not a successful child constructor. An audit route
	 * remains nonblocking; strict enforcement denies. */
	real_owner_child_missing_target();
	if (mode == 2)
		return -1;
	return 0;
}

/* Target frame: reopen original physical TASK, resume exact WORK, take a new
 * real route claim, and use its fixed original-binding snapshot. WORK and
 * claim cleanup happen even if publication or re-admission fails. */
static __attribute__((noinline)) int
real_owner_child_claimed_construct(struct se_owk_semantic_handle *semantic,
				   struct task_struct *child, __u32 *mode_out)
{
	struct se_route_claim claim = {};
	int admission = se_route_admit(bpf_get_current_cgroup_id(), &claim);
	int committed = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE
	int attempted = 0;
#endif
	if (admission == SE_ROUTE_OWNED) {
		*mode_out = claim.execution_class;
		if (claim.record < 2) {
			struct se_shared_binding *binding =
				bpf_map_lookup_elem(&se_bindings, &claim.slot);
			if (binding) {
				__u32 record = claim.record;
				asm volatile("" : "+r"(record));
				record &= 1;
				const struct se_snapshot *snapshot =
					&binding->state.records[record];
				struct task_struct *child_key = child;
				if (snapshot->phase == SE_SNAPSHOT_ACTIVE) {
					int status =
						se_op_construct_child_from_parent_work(
							semantic, &claim,
							snapshot, &child_key);
					committed = status == SE_OL_OK;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE
					attempted = 1;
					if (!committed)
						real_owner_fail_closed_rate(
							status == SE_OL_LIMIT ?
								REAL_OWNER_RATE_LIMIT :
								REAL_OWNER_RATE_CONSTRUCT);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
					real_owner_birth_outcome(
						status >= 0 ?
							(__u32)status + 1 :
							5);
					goto counted;
#endif
				}
			}
		}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE
		if (!attempted)
			real_owner_fail_closed_rate(REAL_OWNER_RATE_CONSTRUCT);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
		real_owner_birth_outcome(6);
counted:
#endif
		if (real_owner_child_release_claim(&claim) && !committed)
			*mode_out = 2; /* published child must not be denied */
	} else {
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_CONSTRUCT);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
		real_owner_birth_outcome(6);
#endif
		if (admission == SE_ROUTE_STRICT_FAULT ||
		    admission == SE_ROUTE_INVARIANT_FAULT)
			*mode_out = 2;
	}
	return committed ? 0 : -1;
}
/* A child may already be published when a later WORK/TASK close fails. A
 * post-publication fault cannot be converted into an LSM denial: keep the
 * exact parent charge unreapable instead. Never write a recycled slot whose
 * locator/cookie no longer matches this callback's held lease. */
static __attribute__((noinline)) void
real_owner_child_fault_open_parent(const struct se_ol_payload_handle *parent)
{
	if (!parent || parent->lease.held != 1 || !parent->lease.meta)
		return;
	struct se_ol_meta *meta = parent->lease.meta;
	bpf_spin_lock(&meta->lock);
	if (meta->locator == parent->lease.locator &&
	    meta->cookie == parent->lease.cookie)
		meta->cleanup_error = 1;
	bpf_spin_unlock(&meta->lock);
}
static __attribute__((noinline)) int
real_owner_child_finish(struct task_struct *child, __u32 *mode_out)
{
	struct se_ol_payload_handle parent = {};
	if (real_owner_child_open_parent(&parent) != SE_OL_OK)
		return -1;
	struct se_owk_ticket ticket = {};
	if (se_owk_resume(&parent, 1, &ticket) != SE_OL_OK)
		goto close_parent;
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	if (se_owk_semantic_open(&parent, &ticket, &semantic, &work) !=
	    SE_OL_OK) {
		(void)se_owk_done(&parent, &ticket);
		goto close_parent;
	}
	int result =
		real_owner_child_claimed_construct(&semantic, child, mode_out);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_CLOSE_FAULT_DIAGNOSTIC
	/* Test only: the child is already published, but the semantic handle
	 * cannot complete. The strict LSM return must not deny that child. */
	if (!result)
		semantic.held = 0;
#endif
	if (se_owk_semantic_done(&semantic, &work) != SE_OL_OK) {
		se_owk_fault_ticket(&ticket);
		real_owner_child_fault_open_parent(&parent);
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_TASK_CLOSE_FAULT_DIAGNOSTIC
	/* Test only: logical close precondition fails after successful WORK DONE.
	 * The exact TASK lease remains held, so reaping must remain impossible. */
	if (!result)
		parent.locked = 1;
#endif
	if (se_ol_payload_close(&parent) != SE_OL_OK)
		real_owner_child_fault_open_parent(&parent);
	/* result == 0 means the child has escaped publication. A failed close is
	 * now a retained structural fault, never a reason to deny that child. */
	return result;
close_parent:
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	real_owner_birth_outcome(7);
#endif
	SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_MISSING_TARGET);
	if (se_ol_payload_close(&parent) != SE_OL_OK)
		real_owner_child_fault_open_parent(&parent);
	return -1;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
/* Separate lexical frame: putting a receipt value in the constructor's
 * nested WORK/publication call exceeds Rocky 4.18's 512-byte BPF stack. */
static __attribute__((noinline)) void
real_owner_child_birth_stamp(struct task_struct *child)
{
	__u64 child_key = (__u64)child;
	struct opaque_birth_receipt *receipt =
		bpf_map_lookup_elem(&opaque_birth_receipts, &child_key);
	__u64 parent_key = (__u64)bpf_get_current_task_btf();
	if (!receipt || receipt->state != 1 || receipt->child != child_key ||
	    receipt->parent != parent_key || !receipt->parent_cookie ||
	    !receipt->scope || receipt->slot >= SE_PROFILE_BINDINGS)
		return;
	struct se_ol_payload_handle parent = {};
	if (se_ol_task_open(&parent_key, &parent) != SE_OL_OK)
		return;
	struct se_task_state *task = 0;
	int parent_exact = 0;
	if (se_op_task_semantic_begin(&parent, &task) == SE_OL_OK) {
		parent_exact = !parent.lease.meta->cleanup_error &&
			       parent.lease.cookie == receipt->parent_cookie &&
			       task->flags == SE_TASK_QUALIFIED &&
			       task->scope_cookie == receipt->scope &&
			       task->scope_slot == receipt->slot &&
			       task->committed.version != 0;
		se_op_task_semantic_end(&parent, &task);
	}
	if (se_ol_payload_close(&parent) != SE_OL_OK || !parent_exact)
		return;
	struct se_ol_payload_handle born = {};
	if (se_ol_task_open(&child_key, &born) != SE_OL_OK)
		return;
	int child_exact = 0;
	__u64 child_cookie = born.lease.cookie;
	__u64 child_locator = born.lease.locator;
	if (se_op_task_semantic_begin(&born, &task) == SE_OL_OK) {
		child_exact = !born.lease.meta->cleanup_error &&
			      task->flags == SE_TASK_LIVE &&
			      task->scope_cookie == receipt->scope &&
			      task->scope_slot == receipt->slot &&
			      task->committed.version != 0 &&
			      !task->exec.owned && !task->reader.owned;
		se_op_task_semantic_end(&born, &task);
	}
	if (se_ol_payload_close(&born) != SE_OL_OK || !child_exact)
		return;
	receipt = bpf_map_lookup_elem(&opaque_birth_receipts, &child_key);
	if (!receipt || receipt->state != 1 || receipt->child != child_key ||
	    receipt->parent != parent_key || !receipt->parent_cookie ||
	    receipt->child_cookie || receipt->child_locator)
		return;
	receipt->child_cookie = child_cookie;
	receipt->child_locator = child_locator;
}
#endif

SEC("lsm/task_alloc")
long BPF_PROG(opaque_real_owner_child_target_candidate,
	      struct task_struct *child, unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	(void)prior;
	__s64 prior_ret = (__s64)ctx[2];
	if (prior_ret)
		return prior_ret;
	if (!real_owner_image_configured())
		return 0;
	__u32 mode = 1;
	int result = real_owner_child_finish(child, &mode);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	if (!result)
		real_owner_child_birth_stamp(child);
#endif
	if (result && mode == 2) {
		/* Keep the strict deny as a signed 64-bit LSM return. Newer
		 * verifiers reject Clang's folded 32-bit boolean negation. */
		asm volatile("" ::: "memory");
		return -1;
	}
	return 0;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
/* Rocky 4.18 tracing programs cannot use the spinlocked TASK/route maps.
 * This hook only records independent success for the exact source-issued
 * parent/child pair. A separate LSM consumer must authenticate the charged
 * child, original route and parent before granting eligibility. */
SEC("raw_tp/sched_process_fork")
int opaque_real_owner_successful_birth_candidate(
	struct bpf_raw_tracepoint_args *ctx)
{
	__u64 parent = ctx->args[0], child = ctx->args[1];
	if (!parent || !child || parent == child ||
	    parent != (__u64)bpf_get_current_task_btf())
		return 0;
	struct opaque_birth_receipt *receipt =
		bpf_map_lookup_elem(&opaque_birth_receipts, &child);
	if (!receipt)
		return 0;
	receipt->observation = 1;
	if (receipt->state != 1 || receipt->child != child ||
	    receipt->parent != parent || !receipt->scope ||
	    !receipt->generation || !receipt->serial ||
	    !receipt->parent_cookie || !receipt->child_cookie ||
	    !receipt->child_locator || receipt->slot >= SE_PROFILE_BINDINGS)
		return 0;
	receipt->observation = 2;
	__u64 child_cgroup = 0;
	if (BPF_CORE_READ_INTO(&child_cgroup, (struct task_struct *)child,
			       cgroups, dfl_cgrp, kn, id) ||
	    child_cgroup != bpf_get_current_cgroup_id())
		return 0;
	receipt->observation = 3;
	receipt->state = 2;
	receipt->observation = 4;
	return 0;
}

/* security_task_free is skipped when security_task_alloc itself rejects a
 * fork. free_task is reached by that failure path after an RCU grace period;
 * it also covers later successful exits. Pointer reuse cannot inherit an
 * issued receipt while this source-owned cleanup link remains attached. */
SEC("kprobe/free_task")
int BPF_KPROBE(opaque_real_owner_birth_free_task_candidate,
	       struct task_struct *task)
{
	real_owner_birth_retire((__u64)task, 1);
	return 0;
}
#endif

/* A final-free lease pins the exact physical TASK while the two independent
 * locks settle their respective owners. Never hold the TASK metadata lock
 * across the route/binding lookup or the route lock. A failed reader release
 * retains the charge; it cannot be translated into an empty-owner receipt. */
static __attribute__((noinline)) int
real_owner_child_exec_death(struct se_of_lease *lease,
			    struct task_struct *physical)
{
	struct se_of_semantic_handle semantic = {};
	struct se_pool_task_wire *payload = 0;
	if (se_of_semantic_begin(lease, physical, &semantic, &payload) !=
	    SE_OL_OK)
		return SE_OL_CORRUPT;
	struct se_task_state *task = &payload->semantic;
	__u32 slot = task->scope_slot;
	__u64 invocation = task->reader_invocation;
	int abort_ok =
		!task->exec.owned ||
		(task->exec.bprm && task->exec.sequence &&
		 !se_exec_abort_locked(task, lease->cookie, task->exec.bprm,
				       task->exec.sequence));
	if (!abort_ok)
		lease->meta->cleanup_error = 1;
	/* begin's successful branch holds this exact metadata lock. The generic
	 * conditional end has verifier-visible error exits while locked here;
	 * close this proven lexical branch without another fallible check. */
	lease->locked = 0;
	payload = 0;
	bpf_spin_unlock(&lease->meta->lock);
	if (!abort_ok)
		return SE_OL_CORRUPT;

	/* The route lock owns reader state. The death lease excludes a successor
	 * TASK slot; actual task_free excludes a new exec on this physical task. */
	struct se_route_anchor *route = route_lookup(slot);
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &slot);
	if (!route || !binding)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&route->lock);
	int reader_ok = !task->reader.owned && !task->reader_invocation;
	if (!reader_ok && invocation)
		reader_ok = !se_exec_reader_release_locked(
			&binding->state, task, lease->cookie, invocation);
	bpf_spin_unlock(&route->lock);
	/* The callback-local death lease remains held; recheck the exact TASK
	 * identity before issuing a receipt. Reader state was observed under its
	 * owning route lock and cannot acquire a new owner after task_free. */
	struct se_ol_meta *meta = lease->meta;
	bpf_spin_lock(&meta->lock);
	int done = reader_ok && lease->held == 1 && meta->phase == SE_OL_DEAD &&
		   meta->cookie == lease->cookie &&
		   meta->locator == lease->locator && meta->active_leases &&
		   !meta->cleanup_error && !task->exec.owned &&
		   task->physical_cookie == lease->cookie &&
		   task->scope_slot == slot;
	if (done)
		meta->cleanup_done |= SE_OL_EXEC_DONE;
	else
		meta->cleanup_error = 1;
	bpf_spin_unlock(&meta->lock);
	return done ? SE_OL_OK : SE_OL_CORRUPT;
}

static __attribute__((noinline)) void
real_owner_child_work_death(struct se_of_lease *lease)
{
	/* STALE means no suspended WORK; CONTENDED means a live WORK callback
	 * still owns completion. Neither is a fabricated WORK_DONE receipt. */
	if (se_owk_finish_suspended_death(lease) != SE_OL_CORRUPT)
		return;
	struct se_ol_meta *meta = lease->meta;
	if (!meta)
		return;
	bpf_spin_lock(&meta->lock);
	if (lease->held == 1 && meta->locator == lease->locator &&
	    meta->cookie == lease->cookie && meta->phase == SE_OL_DEAD)
		meta->cleanup_error = 1;
	bpf_spin_unlock(&meta->lock);
}

/* G025: the physical-reuse directory withdrawal is a correctness fix of
 * every build of this final-free program, never a witness option. */
#ifndef SE_OF_WITHDRAW_DIRECTORY
#error "real-map final-free requires the physical-reuse directory withdrawal"
#endif
#ifndef SE_OP_INSERT_RETRY
#error "real-map birth requires the physical-reuse single insert retry"
#endif
/* Exact physical death is the only source of the DEAD transition. This
 * callback settles exec/reader and certifies an empty native owner account.
 * Nonempty native refs remain pending for a future source-owned closer; this
 * callback never refunds a TASK or WORK credit. */
SEC("lsm/task_free")
int BPF_PROG(opaque_real_owner_child_final_free_candidate,
	     struct task_struct *physical)
{
	if (!real_owner_image_configured())
		return 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	real_owner_birth_retire((__u64)physical, 0);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_RECOVERED_INITIAL_TASK_DIAGNOSTIC
	opaque_recovered_initial_retire_physical(physical);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
	real_owner_child_recovery_close(physical);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE
	__u64 failure_key = (__u64)physical;
	(void)bpf_map_delete_elem(&se_failure_handler_frames, &failure_key);
	(void)bpf_map_delete_elem(&se_failure_outer_frames, &failure_key);
#endif
	struct se_of_lease lease = {};
	/* On failure the receipt survives and a reused address is quarantined:
	 * fail-closed, an accepted availability cost. */
	if (se_of_record_death(physical, &lease) == SE_OL_OK) {
		(void)real_owner_child_exec_death(&lease, physical);
		real_owner_child_work_death(&lease);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
		/* No terminal retry can run after final free. Retire only this
		 * exact lease's receipt so a reused task address never inherits
		 * it as pending; any other receipt is left for quarantine. */
		__u64 receipt_key = (__u64)physical;
		const struct se_exec_terminal_receipt *receipt =
			bpf_map_lookup_elem(&se_exec_terminal_receipts,
					    &receipt_key);
		if (receipt && receipt->physical == receipt_key &&
		    receipt->cookie == lease.cookie &&
		    receipt->locator == lease.locator)
			(void)bpf_map_delete_elem(&se_exec_terminal_receipts,
						  &receipt_key);
#endif
		(void)se_of_complete_native_unheld(&lease, physical);
		/* Withdraw the directory entry before this address can be reused
		 * (full/shared_pool_opaque_final_free_candidate.h). Any refusal
		 * leaves the reaper's ordinary withdrawal as the fallback. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
		/* Mirror se_or_task_terminal_guard: a receipt left at this key
		 * keeps the key for its consumer; only the reaper retires it. */
		if (!bpf_map_lookup_elem(&se_exec_terminal_receipts,
					 &receipt_key))
#endif
			(void)se_of_withdraw_directory(&lease, physical);
		(void)se_of_release(&lease, physical);
	}
	return 0;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC
/* Test-only reader-hold injector for the physical-reuse fallback. Take: the
 * product speculative hold (se_ol_hold_observation) on a LIVE, PUBLISHED TASK
 * by its physical key, deliberately never converted or cancelled, so the
 * final-free withdrawal must refuse and leave the reaper path. Release: drop
 * exactly that one hold on the exact slot and cookie. It grants nothing. */
struct opaque_real_reuse_hold_request {
	__u64 physical, cookie;
	__u32 slot, release;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_reuse_hold_request);
} opaque_real_reuse_hold_request SEC(".maps");
SEC("tc")
int opaque_real_reuse_hold(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const struct opaque_real_live_bootstrap_gate *gate =
		opaque_real_live_gate();
	const struct opaque_real_reuse_hold_request *request =
		bpf_map_lookup_elem(&opaque_real_reuse_hold_request, &zero);
	if (!gate || gate->enabled != 1 || !request || !request->physical)
		return 1;
	if (!request->release) {
		__u64 key = request->physical;
		struct se_ol_observation observation = {};
		if (se_ol_observe(&key, &observation) != SE_OL_OK ||
		    se_ol_read_observation(&observation) != SE_OL_OK ||
		    se_ol_hold_observation(&observation) != SE_OL_OK)
			return 2;
		return 0;
	}
	if (request->slot >= SE_OL_TASKS || !request->cookie)
		return 1;
	struct se_ol_meta *meta = meta_lookup(request->slot);
	if (!meta)
		return 1;
	bpf_spin_lock(&meta->lock);
	int exact = meta->cookie == request->cookie && meta->reader_holds;
	if (exact)
		meta->reader_holds--;
	bpf_spin_unlock(&meta->lock);
	return exact ? 0 : 3;
}
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_BEGIN_PROBE
/* A pending receipt blocks a new reader so its exact original invocation
 * cannot be overwritten. Audit still runs, but neither prior trusted roles
 * nor an owned transaction may survive an unobserved successor exec. This
 * helper never consumes or retires the earlier receipt. */
static __attribute__((noinline)) int
real_owner_reader_quarantine_pending(__u64 physical)
{
	struct se_ol_payload_handle owner = {};
	if (!physical || se_ol_task_open(&physical, &owner) != SE_OL_OK)
		return -1;
	struct se_task_state *task = 0;
	int exact = 0;
	if (se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		exact = task->physical_cookie == owner.lease.cookie;
		if (exact) {
			if (!(task->flags & SE_TASK_QUARANTINED)) {
				task->flags |= SE_TASK_QUARANTINED;
				if (task->eligibility_version < ~0ULL - 1)
					task->eligibility_version++;
			}
			if (task->exec.owned)
				se_exec_fault_locked(&task->exec);
		}
		se_op_task_semantic_end(&owner, &task);
	}
	int closed = se_ol_payload_close(&owner) == SE_OL_OK;
	return exact && closed ? 0 : -1;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
/* The source has released its lexical TASK lease and early claim before a
 * tail call. A missing target must reopen and quarantine the exact reader;
 * a copied receipt alone can never authorize another physical generation. */
static __attribute__((noinline)) int
real_owner_policy_abort_handoff(__u64 physical, __u64 bprm)
{
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (!receipt || receipt->physical != physical ||
	    receipt->bprm != bprm || !receipt->cookie || !receipt->locator ||
	    !receipt->invocation || !receipt->scope || !receipt->generation ||
	    receipt->phase != SE_EXEC_TERMINAL_REGISTERED || receipt->reserved)
		return -1;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&physical, &owner) != SE_OL_OK) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC
		real_owner_eval_work_outcome(4);
#endif
		return -1;
	}
	int exact = owner.lease.cookie == receipt->cookie &&
		    owner.lease.locator == receipt->locator;
	__u32 slot = SE_OC_ACCOUNTS;
	struct se_task_state *task = 0;
	if (exact && se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		exact = task->physical_cookie == receipt->cookie &&
			task->scope_cookie == receipt->scope &&
			task->exec.bprm == bprm &&
			task->exec.sequence == receipt->invocation &&
			task->exec.generation == receipt->generation;
		slot = task->scope_slot;
		se_op_task_semantic_end(&owner, &task);
	} else {
		exact = 0;
	}
	struct se_shared_binding *binding =
		exact && slot < SE_OC_ACCOUNTS ?
			bpf_map_lookup_elem(&se_bindings, &slot) :
			0;
	int aborted = binding && se_op_exec_reader_abort_quarantined(
					 &owner, &binding->state, bprm,
					 receipt->invocation) == SE_OL_OK;
	int closed = se_ol_payload_close(&owner) == SE_OL_OK;
	if (aborted && closed)
		(void)bpf_map_delete_elem(&se_exec_terminal_receipts,
					  &physical);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC
	real_owner_eval_work_outcome(aborted && closed ? 3 : 4);
#endif
	return aborted && closed ? 0 : -1;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC
/* Disposable witness only: never consulted for admission or ownership. */
struct opaque_real_continue_witness {
	__u64 physical, bprm, cookie, locator, invocation, scope, generation;
	__u64 first_inode, second_inode, continuations;
	__u64 first_record, first_serial, continued_record, continued_serial;
	__u64 first_dev, second_dev;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_real_continue_witness);
} opaque_real_owner_continue_witness SEC(".maps");
static __attribute__((noinline)) void
real_owner_continue_observe(const struct se_exec_terminal_receipt *receipt,
			    __u64 bprm, int continued, __u64 record,
			    __u64 serial)
{
	__u32 zero = 0;
	struct opaque_real_continue_witness *w =
		bpf_map_lookup_elem(&opaque_real_owner_continue_witness, &zero);
	if (!w || !receipt)
		return;
	__u64 inode = BPF_CORE_READ((struct linux_binprm *)bprm, file, f_inode,
				    i_ino);
	__u64 dev = BPF_CORE_READ((struct linux_binprm *)bprm, file, f_inode,
				  i_sb, s_dev);
	if (continued) {
		w->second_inode = inode;
		w->second_dev = dev;
		w->continued_record = record;
		w->continued_serial = serial;
		w->continuations++;
	} else {
		w->physical = receipt->physical;
		w->bprm = receipt->bprm;
		w->cookie = receipt->cookie;
		w->locator = receipt->locator;
		w->invocation = receipt->invocation;
		w->scope = receipt->scope;
		w->generation = receipt->generation;
		w->first_inode = inode;
		w->first_dev = dev;
		w->second_dev = 0;
		w->first_record = record;
		w->first_serial = serial;
		w->continued_record = w->continued_serial = 0;
		w->second_inode = w->continuations = 0;
	}
}
#endif

/* Build the plain exact receipt in its own lexical frame. The source's
 * TASK-open frame must not retain this 64-byte temporary on the older
 * kernel's deepest payload-open path. */
static __attribute__((noinline)) int
real_owner_policy_register_receipt(const struct se_ol_payload_handle *owner,
				   const struct se_route_claim *claim,
				   __u64 bprm, __u64 invocation)
{
	__u64 physical = (__u64)bpf_get_current_task_btf();
	struct se_exec_terminal_receipt receipt = {
		.physical = physical,
		.bprm = bprm,
		.cookie = owner->lease.cookie,
		.locator = owner->lease.locator,
		.invocation = invocation,
		.scope = claim->scope,
		.generation = claim->generation,
		.phase = SE_EXEC_TERMINAL_REGISTERED,
	};
	if (bpf_map_update_elem(&se_exec_terminal_receipts, &physical, &receipt,
				BPF_NOEXIST)) {
		SE_DEFERRED_STORAGE_REFUSED(0);
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_STORAGE);
		return 0;
	}
	if (real_owner_failure_bind_receipt(&receipt)) {
		(void)bpf_map_delete_elem(&se_exec_terminal_receipts,
					  &physical);
		return 0;
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC
	real_owner_continue_observe(&receipt, bprm, 0, claim->record,
				    claim->serial);
#endif
	return 1;
}

struct real_owner_policy_auth {
	__u64 serial;
	__u32 slot;
	__u32 record;
};

static __attribute__((noinline)) void
real_owner_policy_note_prepared(__u64 physical, __u64 cookie, __u64 invocation)
{
	__u32 zero = 0;
	struct opaque_real_owner_policy_witness *witness =
		bpf_map_lookup_elem(&opaque_real_owner_policy_witness, &zero);
	if (!witness)
		return;
	witness->physical = physical;
	witness->cookie = cookie;
	witness->invocation = invocation;
	__sync_fetch_and_add(&witness->prepared, 1);
}

/* The only source of the original record selector is an exact live TASK
 * semantic borrow. No map-value or semantic pointer escapes this function. */
static __attribute__((noinline)) int
real_owner_policy_authenticate(struct se_ol_payload_handle *owner,
			       const struct se_exec_terminal_receipt *receipt,
			       __u64 bprm, struct real_owner_policy_auth *auth)
{
	if (owner->lease.cookie != receipt->cookie ||
	    owner->lease.locator != receipt->locator)
		return 0;
	struct se_task_state *task = 0;
	if (se_op_task_semantic_begin(owner, &task) != SE_OL_OK)
		return 0;
	int exact = task->physical_cookie == receipt->cookie &&
		    task->scope_cookie == receipt->scope && task->exec.owned &&
		    task->exec.bprm == bprm &&
		    task->exec.sequence == receipt->invocation &&
		    task->exec.generation == receipt->generation &&
		    task->reader.owned &&
		    task->reader_invocation == receipt->invocation &&
		    task->reader.token.task_cookie == receipt->cookie &&
		    task->reader.token.scope == receipt->scope;
	if (exact) {
		auth->slot = task->scope_slot;
		auth->record = task->reader.token.record;
		auth->serial = task->reader.token.serial;
	}
	se_op_task_semantic_end(owner, &task);
	return exact;
}

/* Keep the reopened TASK/policy frame out of the terminal-abort call chain.
 * Only the source-issued receipt and retained reader authorize preparation. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* Failed TASK close after a possible suspension. A separate frame keeps the
 * cleanup ticket off the target -> bridge -> WORK stack chain, which was 528
 * bytes (limit 512) on exact AL2023 6.18 with the ticket in this frame. */
static __attribute__((noinline)) void
real_owner_policy_close_fault(struct se_ol_payload_handle *owner, __u64 bprm,
			      int suspended)
{
	(void)se_op_task_owned_fault(owner, bprm);
	if (suspended) {
		struct se_owk_ticket ticket = {};
		if (se_owk_resume(owner, 1, &ticket) == SE_OL_OK)
			(void)se_owk_done(owner, &ticket);
	}
	/* Best effort under the still-owned handle. The caller also attempts
	 * exact receipt-based cleanup, never a replacement policy proposal. */
	(void)se_ol_payload_close(owner);
}
#endif
static __attribute__((noinline)) int
real_owner_policy_target_core(struct linux_binprm *bprm)
{
	int suspended = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	int closed;
#endif
	__u64 physical = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (!receipt || receipt->physical != physical ||
	    receipt->bprm != (__u64)bprm || !receipt->cookie ||
	    !receipt->locator || !receipt->invocation || !receipt->scope ||
	    !receipt->generation || receipt->reserved ||
	    receipt->phase != SE_EXEC_TERMINAL_REGISTERED)
		return 0;
	struct se_ol_payload_handle owner = {};
	if (real_owner_child_open_parent(&owner) != SE_OL_OK)
		return 0;
	struct real_owner_policy_auth auth = {};
	int exact = real_owner_policy_authenticate(&owner, receipt, (__u64)bprm,
						   &auth);
	/* The original-record index must be scalar-bounded before pointer
	 * arithmetic; a conditional lookup alone does not carry that bound
	 * through old verifier state joins. */
	if (!exact || auth.slot >= SE_OC_ACCOUNTS || auth.record >= 2 ||
	    !auth.serial)
		goto close_owner;
	/* Keep an explicit 0/1 data bound in the emitted BPF after the reject
	 * branch. Rocky 4.18 otherwise loses the relation at the state join. */
	volatile __u64 bounded_record = auth.record;
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &auth.slot);
	__u64 recovered = 0;
	if (binding &&
	    se_op_exec_reader_recover(&owner, &binding->state, (__u64)bprm,
				      &recovered) == SE_OL_OK &&
	    recovered == receipt->invocation) {
		const struct se_snapshot *snapshot =
			&binding->state.records[bounded_record & 1ULL];
		if (snapshot->serial == auth.serial &&
		    snapshot->scope == receipt->scope &&
		    snapshot->generation == receipt->generation) {
			int prepared = real_owner_policy_bridge(
				&owner, receipt->scope, receipt->generation,
				snapshot);
			if (!prepared)
				real_owner_policy_note_prepared(
					physical, owner.lease.cookie,
					recovered);
			else if (prepared == 1)
				suspended = 1;
		}
	}
close_owner:
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* No successor may evaluate after the source failed to release its TASK
	 * lease. A failed close retains that exact handle; it grants no new one. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_POLICY_TASK_CLOSE_FAULT_DIAGNOSTIC
	/* Disposable test: reject only the first post-suspension close without
	 * corrupting metadata or pretending to hold an actual spinlock. */
	if (suspended)
		closed = SE_OL_CORRUPT;
	else
#endif
		closed = se_ol_payload_close(&owner);
	if (closed != SE_OL_OK) {
		real_owner_policy_close_fault(&owner, (__u64)bprm, suspended);
		suspended = 0;
	}
#else
	(void)se_ol_payload_close(&owner);
#endif
	return suspended;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
/* A missing stage target is not allowed to strand the suspended WORK. Reopen
 * the original current TASK and consume precisely its stage-one charge. */
static __attribute__((noinline)) int
real_owner_policy_finish_stage_one(__u64 physical, __u64 bprm)
{
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (!receipt || receipt->physical != physical ||
	    receipt->bprm != bprm || !receipt->cookie || !receipt->locator ||
	    !receipt->scope || receipt->phase != SE_EXEC_TERMINAL_REGISTERED ||
	    receipt->reserved)
		return -1;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&physical, &owner) != SE_OL_OK)
		return -1;
	int exact = owner.lease.cookie == receipt->cookie &&
		    owner.lease.locator == receipt->locator;
	struct se_owk_ticket ticket = {};
	/* Consume the WORK at whichever stage it is suspended. A stage
	 * mismatch is a non-mutating STALE replay in se_owk_resume. */
	int resumed = exact && se_owk_resume(&owner, REAL_OWNER_EVAL_STAGE,
					     &ticket) == SE_OL_OK;
	if (exact && !resumed && REAL_OWNER_EVAL_STAGE != 1) {
		ticket = (struct se_owk_ticket){};
		resumed = se_owk_resume(&owner, 1, &ticket) == SE_OL_OK;
	}
	int closed = resumed && se_owk_done(&owner, &ticket) == SE_OL_OK;
	(void)se_ol_payload_close(&owner);
	return closed ? 0 : -1;
}

#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* The successor claims the exact suspended WORK before looking at its policy
 * view, then releases the nonfinal claim before the stage-one closer. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_real_owner_policy_stage_target_candidate,
	     struct linux_binprm *bprm, int prior)
{
	if (prior)
		return prior;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	real_owner_rule_progress(0, -8);
#endif
	__u64 physical = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (receipt && receipt->physical == physical &&
	    receipt->bprm == (__u64)bprm && receipt->cookie &&
	    receipt->locator && receipt->scope &&
	    receipt->phase == SE_EXEC_TERMINAL_REGISTERED &&
	    !receipt->reserved) {
		__u64 scope = receipt->scope;
		__u64 cookie = receipt->cookie;
		__u64 invocation = receipt->invocation;
		struct se_owk_payload *payload =
			se_owk_suspended_current(scope, 1, 1);
		if (payload) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
			int begun = real_owner_policy_stage_begin(payload);
			real_owner_rule_progress(0, begun);
			payload = 0;
			if (begun == 1)
				bpf_tail_call(ctx,
					      &opaque_real_owner_rule_targets,
					      0);
#else
			if (real_owner_policy_stage_begin(payload))
				real_owner_policy_note_prepared(
					physical, cookie, invocation);
			payload = 0;
#endif
			(void)se_owk_suspended_current(scope, 1, 2);
		}
	}
	(void)real_owner_policy_finish_stage_one(physical, (__u64)bprm);
	(void)real_owner_policy_abort_handoff(physical, (__u64)bprm);
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
/* No map-value pointer survives the first tail call. Reauthenticate the
 * reserved same-task WORK before any matcher read; failure only quarantines
 * this diagnostic Audit execution and closes its exact charge. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_real_owner_rule_target_candidate, struct linux_binprm *bprm,
	     int prior)
{
	if (prior)
		return prior;
	real_owner_rule_progress(1, -8);
	__u64 physical = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (receipt && receipt->physical == physical &&
	    receipt->bprm == (__u64)bprm && receipt->cookie &&
	    receipt->locator && receipt->scope && receipt->invocation &&
	    receipt->phase == SE_EXEC_TERMINAL_REGISTERED &&
	    !receipt->reserved) {
		__u64 scope = receipt->scope;
		__u64 cookie = receipt->cookie;
		__u64 invocation = receipt->invocation;
		int evaluated = real_owner_policy_rule_claimed_eval(scope);
		real_owner_rule_progress(1, evaluated);
		if (evaluated == 1)
			real_owner_policy_note_prepared(physical, cookie,
							invocation);
		(void)se_owk_suspended_current(scope, 1, 2);
	}
	(void)real_owner_policy_finish_stage_one(physical, (__u64)bprm);
	(void)real_owner_policy_abort_handoff(physical, (__u64)bprm);
	return 0;
}
/* Load-only ABI probe. No attachment or policy decision uses this program;
 * it asks the old verifier to accept a typed WORK-resident scalar request
 * through the complete alternative/matcher global-function boundary. */
SEC("tc")
int opaque_real_owner_alt_request_probe(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	struct se_owk_payload *payload =
		bpf_map_lookup_elem(&se_opaque_work_payload, &zero);
	if (!payload)
		return 0;
	struct se_invocation *work = &payload->semantic;
	(void)fe_match_alternative(
		&work->observation.facts, &work->observation.evaluator,
		&work->observation.stage_workspace.alt_request, 0);
	return 0;
}
#endif
#endif /* original Audit-only stage/rule programs */
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* Resume/propose uses new lexical authority, never the suspended-read pointer.
 * Bit 1 means proposal and lexical cleanup succeeded; bit 0 is a policy deny.
 * A clean deny leaves the reader/receipt for the actual failure terminal. */
static __attribute__((noinline)) int
real_owner_policy_propose_finished(__u64 physical, __u64 bprm, __u32 mode)
{
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (!receipt || receipt->physical != physical ||
	    receipt->bprm != bprm || !receipt->cookie || !receipt->locator ||
	    !receipt->scope || receipt->phase != SE_EXEC_TERMINAL_REGISTERED ||
	    receipt->reserved)
		return 0;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&physical, &owner) != SE_OL_OK)
		return 0;
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	int result = 0;
	if (owner.lease.cookie != receipt->cookie ||
	    owner.lease.locator != receipt->locator ||
	    se_owk_resume(&owner, REAL_OWNER_EVAL_STAGE, &ticket) != SE_OL_OK)
		goto close;
	if (se_owk_semantic_open(&owner, &ticket, &semantic, &work) !=
	    SE_OL_OK) {
		(void)se_owk_done(&owner, &ticket);
		goto close;
	}
	if (work->history.transaction.execution_class == mode &&
	    se_owk_exec_propose_reader(&semantic, receipt, physical, 0) ==
		    SE_OL_OK) {
		const struct fe_decision *decision =
			&work->observation.evaluator.decision;
		int error = decision->error != FE_OK &&
			    decision->error != FE_AUDIT_UNKNOWN;
		if (!error)
			result = 2 |
				 (fe_lsm_verdict(mode, 0, 0, decision) != 0);
	}
	/* A clean proposal keeps this WORK for the exec terminal; a failed
	 * suspension faults the ticket and falls back to the class verdict. */
	if ((result & 2) &&
	    se_owk_semantic_suspend(&semantic, &work,
				    REAL_OWNER_TERMINAL_STAGE) != SE_OL_OK)
		result = 0;
	if (semantic.held && work &&
	    se_owk_semantic_done(&semantic, &work) != SE_OL_OK)
		result = 0;
close:
	if (!(result & 2))
		(void)se_op_task_owned_fault(&owner, bprm);
	if (se_ol_payload_close(&owner) != SE_OL_OK) {
		(void)se_op_task_owned_fault(&owner, bprm);
		result = 0;
	}
	return result;
}

/* Failure class comes from the statically reached program, not a relookup of
 * a possibly absent receipt or a newer mutable route. Cleanup remains exact
 * and best-effort; neither a failure nor an Audit allow grants any role. */
static __attribute__((always_inline)) inline long
real_owner_policy_failure(__u64 physical, __u64 bprm, __u32 mode)
{
	(void)real_owner_policy_finish_stage_one(physical, bprm);
	(void)real_owner_policy_abort_handoff(physical, bprm);
	return fe_lsm_verdict(mode, 0, 1, 0);
}

/* Global (independently verified once) failure path for the policy class
 * program. Inlined into the policy program it exceeded 1M processed
 * instructions on exact AL2023 6.18 (g005b-verdict-load-20261109). The
 * arguments are scalars; the class comes from the statically reached
 * program, never a relookup. */
__attribute__((noinline)) long real_owner_policy_failure_global(
	void *ctx __attribute__((btf_decl_tag("arg:ctx"))), __u32 mode)
{
	struct linux_binprm *bprm =
		(struct linux_binprm *)((unsigned long long *)ctx)[0];
	return real_owner_policy_failure((__u64)bpf_get_current_task_btf(),
					 (__u64)bprm, mode == 1 ? 1 : 2);
}

/* Prepare program body: reopen the exact receipt TASK, resume the stage-1
 * WORK, snapshot history/catalogue/roles, suspend to the evaluation stage.
 * Returns 1 only when the WORK is suspended at REAL_OWNER_EVAL_STAGE. */
static __attribute__((noinline)) int real_owner_prepare_frame(__u64 physical)
{
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (!receipt || receipt->physical != physical || !receipt->cookie ||
	    !receipt->locator || !receipt->scope || !receipt->invocation ||
	    receipt->phase != SE_EXEC_TERMINAL_REGISTERED || receipt->reserved)
		return 0;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&physical, &owner) != SE_OL_OK)
		return 0;
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	int result = 0;
	if (owner.lease.cookie != receipt->cookie ||
	    owner.lease.locator != receipt->locator ||
	    se_owk_resume(&owner, 1, &ticket) != SE_OL_OK)
		goto close;
	if (se_owk_semantic_open(&owner, &ticket, &semantic, &work) !=
	    SE_OL_OK) {
		(void)se_owk_done(&owner, &ticket);
		goto close;
	}
	work->observation.facts.actor_image = -1;
	work->observation.facts.target_image = -1;
	work->observation.facts.stdin_pipe = -1;
	if (real_owner_prepare_reader_frame(&semantic, receipt, physical) ==
		    SE_OL_OK &&
	    se_owk_semantic_suspend(&semantic, &work, REAL_OWNER_EVAL_STAGE) ==
		    SE_OL_OK)
		result = 1;
	else if (semantic.held && work)
		(void)se_owk_semantic_done(&semantic, &work);
close:
	if (se_ol_payload_close(&owner) != SE_OL_OK) {
		(void)se_op_task_owned_fault(&owner, receipt->bprm);
		result = 0;
	}
	return result;
}

static __attribute__((always_inline)) inline long
real_owner_prepare_class(unsigned long long *ctx, struct linux_binprm *bprm,
			 __u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
	if (real_owner_prepare_frame((__u64)bpf_get_current_task_btf()) == 1) {
		if (mode == 1)
			bpf_tail_call(ctx, &opaque_real_stage_audit, 0);
		else
			bpf_tail_call(ctx, &opaque_real_stage_strict, 0);
	}
	(void)bprm;
	if (real_owner_policy_failure_global(ctx, mode)) {
		asm volatile("" ::: "memory");
		return -1L;
	}
	return 0;
}

static __attribute__((always_inline)) inline long
real_owner_policy_class(unsigned long long *ctx, struct linux_binprm *bprm,
			__u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
	if (real_owner_policy_target_core(bprm)) {
		if (mode == 1)
			bpf_tail_call(ctx, &opaque_real_prepare_audit, 0);
		else
			bpf_tail_call(ctx, &opaque_real_prepare_strict, 0);
	}
	/* A global function's result is an unknown scalar to the caller; map it
	 * to the two explicit signed-64 LSM verdicts (dead end #25). */
	if (real_owner_policy_failure_global(ctx, mode)) {
		asm volatile("" ::: "memory");
		return -1L;
	}
	return 0;
}

static __attribute__((always_inline)) inline long
real_owner_stage_class(unsigned long long *ctx, struct linux_binprm *bprm,
		       __u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
	__u64 physical = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (receipt && receipt->physical == physical &&
	    receipt->bprm == (__u64)bprm && receipt->cookie &&
	    receipt->locator && receipt->scope && receipt->invocation &&
	    receipt->phase == SE_EXEC_TERMINAL_REGISTERED &&
	    !receipt->reserved) {
		__u64 scope = receipt->scope;
		struct se_owk_payload *payload = se_owk_suspended_current(
			scope, REAL_OWNER_EVAL_STAGE, 1);
		if (payload) {
			int begun = real_owner_policy_stage_begin(payload);
			real_owner_rule_progress(0, begun);
			payload = 0;
			if (begun == 1) {
				if (mode == 1)
					bpf_tail_call(ctx,
						      &opaque_real_rule_audit,
						      0);
				else
					bpf_tail_call(ctx,
						      &opaque_real_rule_strict,
						      0);
			}
			(void)se_owk_suspended_current(
				scope, REAL_OWNER_EVAL_STAGE, 2);
		}
	}
	return real_owner_policy_failure(physical, (__u64)bprm, mode);
}

static __attribute__((always_inline)) inline long
real_owner_rule_class(unsigned long long *ctx, struct linux_binprm *bprm,
		      __u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
	__u64 physical = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	int evaluated = 0;
	__u64 held = 0;
	if (receipt && receipt->physical == physical &&
	    receipt->bprm == (__u64)bprm && receipt->cookie &&
	    receipt->locator && receipt->scope && receipt->invocation &&
	    receipt->phase == SE_EXEC_TERMINAL_REGISTERED &&
	    !receipt->reserved) {
		__u64 scope = receipt->scope;
		evaluated = real_owner_policy_rule_claimed_eval(scope);
		if (evaluated == 2)
			held = scope;
		real_owner_rule_progress(1, evaluated);
		/* Keep the nonfinal reservation across window re-entry: the next
		 * window re-reads it with operation 3. Release only at the end. */
		if (evaluated != 2 &&
		    !se_owk_suspended_current(scope, REAL_OWNER_EVAL_STAGE, 2))
			evaluated = 0;
	}
	if (evaluated == 2) {
		/* Still reserved; the next window re-derives every TASK/charge/WORK
		 * fact through operation 3 before reading the cursor. */
		{
			__u32 zero = 0;
			__u64 *windows = bpf_map_lookup_elem(
				&opaque_real_owner_rule_windows, &zero);
			if (windows)
				__sync_fetch_and_add(windows, 1);
		}
		if (mode == 1)
			bpf_tail_call(ctx, &opaque_real_rule_audit, 0);
		else
			bpf_tail_call(ctx, &opaque_real_rule_strict, 0);
	} else {
		/* Proposal or exact failure cleanup runs on a fresh stack: with the
		 * evaluation window in this frame, propose/cleanup chains exceeded
		 * the 512-byte combined stack on exact AL2023 6.12. */
		if (mode == 1)
			bpf_tail_call(ctx, &opaque_real_finish_audit, 0);
		else
			bpf_tail_call(ctx, &opaque_real_finish_strict, 0);
	}
	/* A missing frozen graph entry (or exhausted tail-call budget) is a
	 * configuration invariant breach. Return the static class verdict;
	 * Strict never allows here. A reservation kept for window re-entry is
	 * released first: se_owk_finish_suspended_death (task_free) and the reap
	 * paths require continuation_reserved clear. The WORK then stays
	 * suspended until task death and the pending receipt quarantines this
	 * task's next admission meanwhile. */
	if (held)
		(void)se_owk_suspended_current(held, REAL_OWNER_EVAL_STAGE, 2);
	(void)physical;
	if (mode == 2) {
		asm volatile("" ::: "memory");
		return -1L;
	}
	return 0;
}

/* Finish program: propose the completed evaluation, or perform the exact
 * failure cleanup and class verdict. propose_finished refuses anything that
 * did not reach a clean FINISHED decision. */
static __attribute__((always_inline)) inline long
real_owner_finish_class(unsigned long long *ctx, struct linux_binprm *bprm,
			__u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
	__u64 physical = (__u64)bpf_get_current_task_btf();
	int result =
		real_owner_policy_propose_finished(physical, (__u64)bprm, mode);
	if (result & 2) {
		if (result & 1) {
			asm volatile("" ::: "memory");
			return -1L;
		}
		return 0;
	}
	return real_owner_policy_failure(physical, (__u64)bprm, mode);
}

#define REAL_OWNER_CLASS_PROGRAM(name, body, mode)                \
	SEC("lsm/bprm_check_security")                            \
	long BPF_PROG(name, struct linux_binprm *bprm, int prior) \
	{                                                         \
		(void)prior;                                      \
		return body(ctx, bprm, mode);                     \
	}
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_policy_audit,
			 real_owner_policy_class, 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_policy_strict,
			 real_owner_policy_class, 2)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_prepare_audit,
			 real_owner_prepare_class, 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_prepare_strict,
			 real_owner_prepare_class, 2)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_stage_audit, real_owner_stage_class,
			 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_stage_strict, real_owner_stage_class,
			 2)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_rule_audit, real_owner_rule_class, 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_rule_strict, real_owner_rule_class,
			 2)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_finish_audit,
			 real_owner_finish_class, 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_finish_strict,
			 real_owner_finish_class, 2)
#undef REAL_OWNER_CLASS_PROGRAM
#endif

#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* This diagnostic always quarantines afterward: it has no evaluator,
 * verdict, event or role proposal. The small wrapper keeps the abort frame
 * disjoint from the policy frame on older verifier stack accounting. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_real_owner_policy_target_candidate,
	     struct linux_binprm *bprm, int prior)
{
	if (prior)
		return prior;
	int suspended = real_owner_policy_target_core(bprm);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
	if (suspended) {
		bpf_tail_call(ctx, &opaque_real_owner_policy_stage_targets, 0);
		(void)real_owner_policy_finish_stage_one(
			(__u64)bpf_get_current_task_btf(), (__u64)bprm);
	}
#else
	(void)suspended;
#endif
	(void)real_owner_policy_abort_handoff((__u64)bpf_get_current_task_btf(),
					      (__u64)bprm);
	return 0; /* Audit-only diagnostic; never grants a policy decision. */
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC
/* Leave the exact source-issued reader/receipt to the real terminal producer.
 * This target is test-only and has no evaluator, verdict or role proposal. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_real_owner_terminal_retain_target,
	     struct linux_binprm *bprm, int prior)
{
	(void)bprm;
	return prior;
}
#endif
#endif
/* Never selected by the product. This diagnostic exercises the exact TASK,
 * original route, snapshot and reader handoff in one verifier-visible LSM
 * callback. It immediately finishes as a failed exec: no policy evaluation,
 * role grant, event, or native Ready claim follows from this probe. */
/* The source's owner/reader frame must return before the tail-call fallback
 * reopens the TASK. Otherwise both stack frames are charged simultaneously. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
/* Begin/recover and terminal registration are separate lexical frames: the
 * old verifier charges every live BPF call stack, not just C local bytes. */
static __attribute__((noinline)) int
real_owner_reader_open_exact(struct se_ol_payload_handle *owner,
			     struct se_route_claim *claim,
			     struct linux_binprm *bprm, __u64 *invocation_out)
{
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &claim->slot);
	*invocation_out = 0;
	int good = binding &&
		   se_op_exec_reader_begin(owner, claim, &binding->state,
					   (__u64)bprm,
					   invocation_out) == SE_OL_OK;
	if (good) {
		__u64 recovered = 0;
		good = se_op_exec_reader_recover(owner, &binding->state,
						 (__u64)bprm,
						 &recovered) == SE_OL_OK &&
		       recovered == *invocation_out;
	}
	return good;
}

/* Bit 0 reports a clean lexical close; bit 1 reports an exact retained
 * reader (Audit only in the original diagnostic). The route claim and TASK
 * lease remain caller-owned. */
static __attribute__((noinline)) int real_owner_reader_finish_exact(
	struct se_ol_payload_handle *owner, struct se_route_claim *claim,
	struct linux_binprm *bprm, __u64 invocation, int good)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &claim->slot);
	if (!binding)
		good = 0;
	if (good &&
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	    (claim->execution_class == 1 || claim->execution_class == 2) &&
#else
	    claim->execution_class == 1 &&
#endif
	    !real_owner_failure_frame_ready(key, (__u64)bprm)) {
		SE_DEFERRED_STORAGE_REFUSED(4);
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_STORAGE);
		(void)se_op_exec_reader_abort_quarantined(
			owner, &binding->state, (__u64)bprm, invocation);
		invocation = 0;
		good = 0;
	}
	int retained =
		good &&
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
		(claim->execution_class == 1 || claim->execution_class == 2);
#else
		claim->execution_class == 1;
#endif
	if (retained && !real_owner_policy_register_receipt(
				owner, claim, (__u64)bprm, invocation)) {
		(void)se_op_exec_reader_abort_quarantined(
			owner, &binding->state, (__u64)bprm, invocation);
		retained = 0;
		invocation = 0;
		good = 0;
	}
	if (binding && invocation && !retained)
		good = se_op_exec_reader_finish_bounded(owner, &binding->state,
							(__u64)bprm, invocation,
							0) == SE_OL_OK &&
		       good;
	if (se_ol_payload_close(owner) != SE_OL_OK)
		good = 0;
	return (good ? 1 : 0) | (retained ? 2 : 0);
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC
static __attribute__((noinline)) int
real_owner_continue_frames(const struct se_exec_terminal_receipt *receipt,
			   __u64 key, __u64 bprm)
{
	const struct se_failure_outer_frame *outer =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	const struct se_failure_handler_frame *handler =
		bpf_map_lookup_elem(&se_failure_handler_frames, &key);
	return outer && handler && outer->physical == key &&
	       outer->depth == 1 && !outer->uncertain && outer->bprm == bprm &&
	       outer->bprm == receipt->bprm &&
	       outer->cookie == receipt->cookie &&
	       outer->locator == receipt->locator &&
	       outer->invocation == receipt->invocation &&
	       outer->scope == receipt->scope &&
	       outer->generation == receipt->generation &&
	       handler->bprm == bprm && handler->depth == 1 &&
	       !handler->uncertain;
}

/* 0: absent/terminal, 1: recovered Audit, 2: strict fault, 3: Audit
 * fault, 4: unknown disposition. REGISTERED never reaches a fresh begin. */
static __attribute__((noinline)) int
real_owner_continue_reader(struct linux_binprm *bprm, int prior_denied)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	if (!receipt || receipt->phase != SE_EXEC_TERMINAL_REGISTERED)
		return 0;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&key, &owner) != SE_OL_OK)
		return 4;
	__u32 slot = SE_OC_ACCOUNTS, mode = 0;
	__u64 record = 0, serial = 0;
	struct se_task_state *task = 0;
	if (se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		if (task->physical_cookie == owner.lease.cookie) {
			slot = task->scope_slot;
			mode = task->exec.execution_class;
			record = task->reader.token.record;
			serial = task->reader.token.serial;
		}
		se_op_task_semantic_end(&owner, &task);
	}
	struct se_shared_binding *binding =
		slot < SE_OC_ACCOUNTS ?
			bpf_map_lookup_elem(&se_bindings, &slot) :
			0;
	__u64 invocation = 0;
	int valid = binding &&
		    se_op_exec_reader_classify(&owner, &binding->state, receipt,
					       key, (__u64)bprm) ==
			    SE_EXEC_READER_CONTINUE &&
		    real_owner_continue_frames(receipt, key, (__u64)bprm) &&
		    se_op_exec_reader_recover(&owner, &binding->state,
					      (__u64)bprm,
					      &invocation) == SE_OL_OK &&
		    invocation == receipt->invocation;
	if (valid && prior_denied)
		valid = se_op_task_note_prior_deny(&owner, (__u64)bprm) ==
			SE_OL_OK;
	if (valid && !prior_denied && mode == 1)
		real_owner_continue_observe(receipt, (__u64)bprm, 1, record,
					    serial);
	if (se_ol_payload_close(&owner) != SE_OL_OK)
		valid = 0;
	if (mode == 2)
		return 2; /* This diagnostic never grants a strict verdict. */
	return mode == 1 ? (valid ? 1 : 3) : 4;
}
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE
/* Source-only physical-exec capsule (full/shared_exec_capsule.h, G005-A).
 * Arrays are sized by the loader to the guest pid_max; maps are private. */
struct se_exec_capsule;
struct se_exec_marker;
static __always_inline struct se_exec_capsule *real_owner_capsule(__u32 tgid);
static __always_inline struct se_exec_marker *real_owner_marker(__u32 pid);
static __always_inline __u64 real_owner_capsule_sequence(void);
static __always_inline void real_owner_capsule_stat(__u32 index);
#define SE_CAP_LOOKUP(tgid) real_owner_capsule(tgid)
#define SE_CAP_MARKER_LOOKUP(pid) real_owner_marker(pid)
#define SE_CAP_NEXT_SEQUENCE() real_owner_capsule_sequence()
#define SE_CAP_STAT(index) real_owner_capsule_stat(index)
#include "shared_exec_capsule.h"
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct se_exec_capsule);
} se_exec_capsules SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct se_exec_marker);
} se_exec_markers SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} se_exec_capsule_sequence SEC(".maps");
struct real_owner_capsule_stats {
	__u64 events[SE_CAP_STATS];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct real_owner_capsule_stats);
} se_exec_capsule_stats SEC(".maps");
static __always_inline struct se_exec_capsule *real_owner_capsule(__u32 tgid)
{
	return bpf_map_lookup_elem(&se_exec_capsules, &tgid);
}
static __always_inline struct se_exec_marker *real_owner_marker(__u32 pid)
{
	return bpf_map_lookup_elem(&se_exec_markers, &pid);
}
static __always_inline __u64 real_owner_capsule_sequence(void)
{
	__u32 zero = 0;
	__u64 *next = bpf_map_lookup_elem(&se_exec_capsule_sequence, &zero);
	if (!next)
		return 0;
	__u64 value = __sync_fetch_and_add(next, 1) + 1;
	return value && value < ~0ULL - 1 ? value : 0;
}
static __always_inline void real_owner_capsule_stat(__u32 index)
{
	__u32 zero = 0;
	struct real_owner_capsule_stats *s =
		bpf_map_lookup_elem(&se_exec_capsule_stats, &zero);
	if (s && index < SE_CAP_STATS)
		__sync_fetch_and_add(&s->events[index], 1);
}
/* Loader attach order is a hard invariant: terminal, entry, begin, then the
 * LSM admission; detach in exact reverse. */
SEC("fexit/bprm_execve")
int BPF_PROG(real_owner_capsule_terminal, struct linux_binprm *bprm, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	(void)se_cap_on_terminal(id >> 32, (__u32)id,
				 (__u64)bpf_get_current_task_btf(), (__u64)bprm,
				 ret);
	return 0;
}
SEC("fentry/bprm_execve")
int BPF_PROG(real_owner_capsule_entry, struct linux_binprm *bprm)
{
	__u64 id = bpf_get_current_pid_tgid();
	se_cap_on_entry((__u32)id, (__u64)bpf_get_current_task_btf(),
			(__u64)bprm);
	return 0;
}
struct linux_binprm___capsule_check {
	unsigned int is_check : 1;
} __attribute__((preserve_access_index));
SEC("fentry/security_bprm_creds_for_exec")
int BPF_PROG(real_owner_capsule_begin, struct linux_binprm *bprm)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 is_check = 0;
	struct linux_binprm___capsule_check *checked = (void *)bprm;
	if (bpf_core_field_exists(checked->is_check))
		is_check = BPF_CORE_READ_BITFIELD_PROBED(checked, is_check);
	(void)se_cap_on_begin(id >> 32, (__u32)id,
			      (__u64)bpf_get_current_task_btf(), (__u64)bprm,
			      is_check);
	return 0;
}
/* Separate frame: the capsule admission's views/tokens/lock sections must
 * not sum with the begin_core claim/TASK frames (dead ends 18/23). The class
 * is the frozen ORIGINAL class; the current cgroup never selects it after
 * the first selected admission of this physical exec. */
static __attribute__((noinline)) int
real_owner_cap_admit(struct linux_binprm *bprm, struct se_route_claim *claim,
		     __u32 *frozen)
{
	__u64 id = bpf_get_current_pid_tgid();
	return se_cap_admit(id >> 32, (__u64)bpf_get_current_task_btf(),
			    (__u64)bprm, bpf_get_current_cgroup_id(), claim,
			    frozen);
}
#endif
static __attribute__((noinline)) int
real_owner_reader_begin_core(struct linux_binprm *bprm, int terminal_fault)
{
	if (!real_owner_image_configured())
		return 0;
	struct se_route_claim claim = {};
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE
	__u32 frozen_class = 0;
	int admission = real_owner_cap_admit(bprm, &claim, &frozen_class);
	if (admission == SE_ROUTE_OWNED &&
	    frozen_class != claim.execution_class) {
		/* Defense in depth: an owned claim must carry the frozen class. */
		(void)real_owner_child_release_claim(&claim);
		return 1;
	}
#else
	int admission = se_route_admit(bpf_get_current_cgroup_id(), &claim);
#endif
	if (admission != SE_ROUTE_OWNED)
		return admission == SE_ROUTE_STRICT_FAULT ||
				       admission == SE_ROUTE_INVARIANT_FAULT ?
			       1 :
			       0;
	__u32 mode = claim.execution_class;
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_ol_payload_handle owner = {};
	/* Do not mutate the TASK transaction while its prior terminal receipt is
	 * waiting for an authenticated consumer. Otherwise a second begin can
	 * replace the exact sequence needed for retry-safe receipt retirement. */
	int pending_terminal = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
	pending_terminal =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key) != 0;
#endif
	int good = !terminal_fault && !pending_terminal &&
		   real_owner_child_open_parent(&owner) == SE_OL_OK;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
	int transfer = 0;
	if (good) {
		__u64 invocation = 0;
		int opened = real_owner_reader_open_exact(&owner, &claim, bprm,
							  &invocation);
		int step = real_owner_reader_finish_exact(&owner, &claim, bprm,
							  invocation, opened);
		good = step & 1;
		transfer = !!(step & 2);
	}
#else
	if (good) {
		struct se_shared_binding *binding =
			bpf_map_lookup_elem(&se_bindings, &claim.slot);
		__u64 invocation = 0;
		good = binding &&
		       se_op_exec_reader_begin(&owner, &claim, &binding->state,
					       (__u64)bprm,
					       &invocation) == SE_OL_OK;
		if (good) {
			__u64 recovered = 0;
			good = se_op_exec_reader_recover(
				       &owner, &binding->state, (__u64)bprm,
				       &recovered) == SE_OL_OK &&
			       recovered == invocation;
		}
		/* The lifecycle variant leaves only a successfully recovered Audit
		 * reader to the actual terminal callback. Strict remains denied here;
		 * this diagnostic has no evaluator and never grants enforcement. */
		int retained = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
		/* An absent or ambiguous outer frame cannot leave a retained Audit
		 * reader with no trustworthy failure terminal. Quarantine history
		 * and release this invocation, but never deny audit execution. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE
		if (good && mode == 1 &&
		    !real_owner_failure_frame_ready(key, (__u64)bprm)) {
			(void)se_op_exec_reader_abort_quarantined(
				&owner, &binding->state, (__u64)bprm,
				invocation);
			invocation = 0;
			good = 0;
		}
#endif
		retained = good && mode == 1;
		if (retained) {
			struct se_exec_terminal_receipt receipt = {
				.physical = key,
				.bprm = (__u64)bprm,
				.cookie = owner.lease.cookie,
				.locator = owner.lease.locator,
				.invocation = invocation,
				.scope = claim.scope,
				.generation = claim.generation,
				.phase = SE_EXEC_TERMINAL_REGISTERED,
			};
			int recorded = !bpf_map_update_elem(
				&se_exec_terminal_receipts, &key, &receipt,
				BPF_NOEXIST);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE
			if (recorded &&
			    real_owner_failure_bind_receipt(&receipt)) {
				(void)bpf_map_delete_elem(
					&se_exec_terminal_receipts, &key);
				recorded = 0;
			}
#endif
			if (!recorded) {
				(void)se_op_exec_reader_abort_quarantined(
					&owner, &binding->state, (__u64)bprm,
					invocation);
				retained = 0;
				invocation = 0; /* no second terminal attempt */
				good = 0;
			}
		}
#endif
		if (invocation && !retained)
			good = se_op_exec_reader_finish_bounded(
				       &owner, &binding->state, (__u64)bprm,
				       invocation, 0) == SE_OL_OK &&
			       good;
		if (se_ol_payload_close(&owner) != SE_OL_OK)
			good = 0;
	}
#endif
	if (claim.owned && real_owner_child_release_claim(&claim))
		good = 0;
	/* This probe has no evaluator. Never allow a selected strict exec even
	 * when its ownership/cleanup diagnostics all succeeded. */
	int result = mode == 2 ? 1 : 0;
	if (pending_terminal || terminal_fault)
		result |= 8;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
	if (transfer)
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
		result |= 2 | (good && (mode == 1 || mode == 2) ? 4 : 0);
#else
		result |= 2 | (good && mode == 1 ? 4 : 0);
#endif
#endif
	return result;
}

SEC("lsm/bprm_check_security")
long BPF_PROG(opaque_real_owner_reader_begin_probe, struct linux_binprm *bprm,
	      int prior)
{
	/* Keep the prior LSM result and our verdict in the signed 64-bit return
	 * domain; a 32-bit negation loses its range on the AL2023 6.12 verifier. */
	__s64 prior_ret = (__s64)ctx[1];
	if (prior_ret) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC
		(void)real_owner_continue_reader(bprm, 1);
#endif
		return prior_ret;
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC
	int continuation = real_owner_continue_reader(bprm, 0);
	if (continuation) {
		if (continuation == 1) {
			bpf_tail_call(ctx, &opaque_real_owner_policy_targets,
				      0);
			(void)real_owner_policy_abort_handoff(
				(__u64)bpf_get_current_task_btf(), (__u64)bprm);
		} else {
			(void)real_owner_reader_quarantine_pending(
				(__u64)bpf_get_current_task_btf());
		}
		if (continuation == 2 ||
		    (continuation == 4 &&
		     (real_owner_reader_begin_core(bprm, 1) & 1))) {
			asm volatile("" ::: "memory");
			return -1L;
		}
		return 0;
	}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PENDING_RECEIPT_DIAGNOSTIC
	(void)real_pending_receipt_inject();
#endif
	int terminal_fault = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	if (real_owner_image_configured())
		terminal_fault = real_owner_birth_qualify(
					 (struct task_struct *)
						 bpf_get_current_task_btf()) <
				 0;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_TERMINAL_DRAIN_DIAGNOSTIC
	/* Keep completion outside the new claim/TASK-open stack frame. */
	if (real_owner_image_configured())
		terminal_fault |= real_owner_source_terminal_drain();
#endif
	int result = real_owner_reader_begin_core(bprm, terminal_fault);
	if (result & 8)
		(void)real_owner_reader_quarantine_pending(
			(__u64)bpf_get_current_task_btf());
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
	if (result & 2) {
		if (result & 4) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
			if (result & 1)
				bpf_tail_call(ctx, &opaque_real_policy_strict,
					      0);
			else
				bpf_tail_call(ctx, &opaque_real_policy_audit,
					      0);
#else
			bpf_tail_call(ctx, &opaque_real_owner_policy_targets,
				      0);
#endif
		}
		/* Missing target or failed lexical close: never retain an unknown
		 * reader as a successful role source. */
		(void)real_owner_policy_abort_handoff(
			(__u64)bpf_get_current_task_btf(), (__u64)bprm);
	}
#endif
	if (result & 1) {
		/* Do not fold the two constant verdicts into a 32-bit negation. */
		asm volatile("" ::: "memory");
		return -1L;
	}
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC
/* AL2023 diagnostic only: the winning success source attempts the existing
 * WORK completion path directly. A failed attempt retains the exact receipt
 * for the existing completion/settlement retry paths. No controller gate is
 * consulted; this does not qualify the hook on other kernels. */
#else
/* Success-side producer for the plain diagnostic mailbox. The callback does
 * not touch the lock-bearing TASK/route/WORK maps: Rocky 4.18 rejects spinlock
 * helpers in tp_btf programs. The receipt is not a release or a verdict. A
 * failed exec still needs a separate terminal; never arm/attach this variant
 * as a product or treat it as a complete lifecycle. */
#endif
SEC("tp_btf/sched_process_exec")
int BPF_PROG(opaque_real_owner_reader_success_probe,
	     struct task_struct *physical, int old_pid,
	     struct linux_binprm *bprm)
{
	(void)old_pid;
	__u64 key = (__u64)physical;
	struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC
	if (receipt &&
	    real_owner_terminal_transition(
		    receipt, key, (__u64)bprm, receipt->cookie,
		    receipt->locator, receipt->invocation, receipt->scope,
		    receipt->generation, SE_EXEC_TERMINAL_SUCCESS)) {
		/* The callee may delete the receipt; do not use its pointer again. */
		(void)real_owner_work_completion_shape(key);
	}
#else
	if (receipt)
		(void)real_owner_terminal_transition(
			receipt, key, (__u64)bprm, receipt->cookie,
			receipt->locator, receipt->invocation, receipt->scope,
			receipt->generation, SE_EXEC_TERMINAL_SUCCESS);
#endif
	return 0;
}
#endif
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_COMPLETION_PROBE
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE)
#error "prepared WORK receipt probe requires the reader and terminal producer"
#endif
/* Never attached or selected. The controller supplies only a physical-key
 * selector; the read-only plain receipt map is written by the actual success
 * tracepoint, never by userspace. This probe cannot invent a terminal. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_work_completion_gate SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_owner_work_completion_selector SEC(".maps");

static __attribute__((noinline)) int
real_owner_work_delete_receipt_exact(__u64 key,
				     const struct se_ol_payload_handle *owner);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
static __attribute__((noinline)) int
real_owner_work_receipt_exact(__u64 key,
			      const struct se_ol_payload_handle *owner);

/* Terminal completion outcomes, read by the attached verdict test. */
#define REAL_OWNER_TERMINAL_RESUMED_COMPLETED 0
#define REAL_OWNER_TERMINAL_RESUMED_FAILED 1
#define REAL_OWNER_TERMINAL_FALLBACK_CHARGED 2
#define REAL_OWNER_TERMINAL_FALLBACK_REFUSED 3
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_terminal_outcomes SEC(".maps");

/* Leaf frame: keeps the key/pointer off the deep completion frame. */
static __attribute__((noinline)) void real_owner_terminal_outcome(__u32 outcome)
{
	__u64 *count =
		bpf_map_lookup_elem(&opaque_real_terminal_outcomes, &outcome);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#endif

static __attribute__((noinline)) int
real_owner_work_complete_active(struct se_ol_payload_handle *owner, __u64 key)
{
	struct se_owk_ticket ticket = {};
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* Complete into the proposed evaluation WORK. Only STALE (no WORK
	 * suspended at this stage) charges a fresh WORK, and only while the
	 * terminal receipt is still exact; CORRUPT or any other result refuses. */
	int resumed = se_owk_resume(owner, REAL_OWNER_TERMINAL_STAGE, &ticket);
	if (resumed != SE_OL_OK) {
		if (resumed != SE_OL_STALE ||
		    !real_owner_work_receipt_exact(key, owner)) {
			real_owner_terminal_outcome(
				REAL_OWNER_TERMINAL_FALLBACK_REFUSED);
			return -1;
		}
		ticket = (struct se_owk_ticket){};
		if (real_owner_child_start_work(owner, &ticket)) {
			real_owner_terminal_outcome(
				REAL_OWNER_TERMINAL_FALLBACK_REFUSED);
			goto abort_work;
		}
		real_owner_terminal_outcome(
			REAL_OWNER_TERMINAL_FALLBACK_CHARGED);
	}
#else
	if (real_owner_child_start_work(owner, &ticket))
		goto abort_work;
#endif
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	if (se_owk_semantic_open(owner, &ticket, &semantic, &work) != SE_OL_OK)
		goto done;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* The snapshot below rewrites history (transaction and view rows); the
	 * reader classify/prepare reset accepted_mask and patch. Only the
	 * prepare-stage catalogue must be emptied for a fresh exact fill. The
	 * evaluation's observation (decision witness) is left intact. */
	if (resumed == SE_OL_OK) {
		semantic.payload->catalogue.scope = 0;
		semantic.payload->catalogue.generation = 0;
		work->history.view.accepted_mask = 0;
	}
#endif
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	struct se_task_state *task = 0;
	if (se_op_task_semantic_begin(owner, &task) != SE_OL_OK)
		goto semantic_done;
	int success = receipt && receipt->phase == SE_EXEC_TERMINAL_SUCCESS;
	if (!se_owk_terminal_receipt_matches(receipt, key, owner, task,
					     success)) {
		se_op_task_semantic_end(owner, &task);
		goto semantic_done;
	}
	__u64 bprm = task->exec.bprm;
	__u64 invocation = task->exec.sequence;
	__u64 generation = task->exec.generation;
	se_exec_snapshot_locked(task, generation, &work->history);
	se_op_task_semantic_end(owner, &task);
	int completed = bprm && invocation && generation &&
			se_owk_catalogue_fill_reader(&semantic) == SE_OL_OK &&
			se_owk_exec_complete_reader(&semantic, bprm, invocation,
						    success) == SE_OL_OK;
	int closed = se_owk_semantic_done(&semantic, &work) == SE_OL_OK;
	int ok = completed && closed &&
		 !real_owner_work_delete_receipt_exact(key, owner);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* The resumed completion's final result; fallback was counted at charge. */
	if (resumed == SE_OL_OK)
		real_owner_terminal_outcome(
			ok ? REAL_OWNER_TERMINAL_RESUMED_COMPLETED :
			     REAL_OWNER_TERMINAL_RESUMED_FAILED);
#endif
	return ok ? 0 : -1;
semantic_done:
	(void)se_owk_semantic_done(&semantic, &work);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	if (resumed == SE_OL_OK)
		real_owner_terminal_outcome(REAL_OWNER_TERMINAL_RESUMED_FAILED);
#endif
	return -1;
done:
	(void)se_owk_done(owner, &ticket);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	if (resumed == SE_OL_OK)
		real_owner_terminal_outcome(REAL_OWNER_TERMINAL_RESUMED_FAILED);
#endif
	return -1;
abort_work:
	if (ticket.held) {
		if (ticket.stage == 0)
			(void)se_owk_abort_building(owner, &ticket);
		else if (ticket.stage == 1 || ticket.stage == 2)
			(void)se_owk_abort(owner, &ticket);
		else if (ticket.stage == 3)
			(void)se_owk_done(owner, &ticket);
	}
	return -1;
}

static __attribute__((noinline)) int
real_owner_work_receipt_exact(__u64 key,
			      const struct se_ol_payload_handle *owner)
{
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	return receipt &&
	       (receipt->phase == SE_EXEC_TERMINAL_SUCCESS ||
		receipt->phase == SE_EXEC_TERMINAL_FAILURE) &&
	       receipt->physical == key &&
	       receipt->cookie == owner->lease.cookie &&
	       receipt->locator == owner->lease.locator;
}

static __attribute__((noinline)) int
real_owner_work_delete_receipt_exact(__u64 key,
				     const struct se_ol_payload_handle *owner)
{
	if (!real_owner_work_receipt_exact(key, owner))
		return -1;
	return bpf_map_delete_elem(&se_exec_terminal_receipts, &key);
}

/* The observation/lease stack frame ends before the WORK completion frame. */
static __attribute__((noinline)) int
real_owner_work_open_key(__u64 key, struct se_ol_payload_handle *owner)
{
	return se_ol_task_open(&key, owner);
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC
struct opaque_real_terminal_race_witness {
	__u64 attempts;
	__u64 commits;
	__u64 inflight;
	__u64 overlap;
	__u64 authenticated;
	__u64 auth_inflight;
	__u64 auth_overlap;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_real_terminal_race_witness);
} opaque_real_terminal_race_witness SEC(".maps");

/* A contender has already opened the exact TASK and validated the terminal
 * receipt before entering this bounded test-only rendezvous. */
static __attribute__((noinline)) void real_owner_terminal_auth_enter(void)
{
	__u32 zero = 0;
	struct opaque_real_terminal_race_witness *witness =
		bpf_map_lookup_elem(&opaque_real_terminal_race_witness, &zero);
	if (!witness)
		return;
	__sync_fetch_and_add(&witness->authenticated, 1);
	__u64 entered = __sync_add_and_fetch(&witness->auth_inflight, 1);
	if (entered > 1)
		__sync_fetch_and_add(&witness->auth_overlap, 1);
	for (__u32 spin = 0; spin < 4096; spin++) {
		volatile __u64 tick = bpf_ktime_get_ns();
		(void)tick;
		if (*(volatile __u64 *)&witness->auth_inflight > 1)
			break;
	}
}
static __attribute__((noinline)) void real_owner_terminal_auth_exit(void)
{
	__u32 zero = 0;
	struct opaque_real_terminal_race_witness *witness =
		bpf_map_lookup_elem(&opaque_real_terminal_race_witness, &zero);
	if (witness)
		__sync_fetch_and_sub(&witness->auth_inflight, 1);
}
#endif

static __attribute__((noinline)) int real_owner_work_completion_shape(__u64 key)
{
	int result = -1;
	struct se_ol_payload_handle owner = {};
	if (real_owner_work_open_key(key, &owner) != SE_OL_OK)
		return -1;
	if (!real_owner_work_receipt_exact(key, &owner))
		goto close;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC
	real_owner_terminal_auth_enter();
#endif
	result = real_owner_work_complete_active(&owner, key);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC
	real_owner_terminal_auth_exit();
#endif
close:
	/* A removed receipt is not permission to advance after a leaked lease. */
	if (se_ol_payload_close(&owner) != SE_OL_OK)
		return -2;
	return result;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC
SEC("tc")
int opaque_real_owner_terminal_race_complete(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const __u32 *armed = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_gate, &zero);
	const __u64 *selected = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_selector, &zero);
	if (!armed || *armed != 1 || !selected || !*selected)
		return 0;
	struct opaque_real_terminal_race_witness *witness =
		bpf_map_lookup_elem(&opaque_real_terminal_race_witness, &zero);
	if (witness) {
		__sync_fetch_and_add(&witness->attempts, 1);
		__u64 entered = __sync_add_and_fetch(&witness->inflight, 1);
		if (entered > 1)
			__sync_fetch_and_add(&witness->overlap, 1);
	}
	int done = real_owner_work_completion_shape(*selected) == 0;
	if (witness) {
		if (done)
			__sync_fetch_and_add(&witness->commits, 1);
		__sync_fetch_and_sub(&witness->inflight, 1);
	}
	return 0;
}
#endif

SEC("tc")
int opaque_real_owner_work_completion_probe(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const __u32 *armed = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_gate, &zero);
	const __u64 *selected = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_selector, &zero);
	if (armed && *armed == 1 && selected && *selected)
		(void)real_owner_work_completion_shape(*selected);
	return 0;
}

/* Separate bounded retry program: a postcommit fault must never rerun the
 * accepted-role patch. An owned transaction is intentionally NOT handled by
 * this entrypoint and keeps its receipt for the normal WORK consumer. */
static __attribute__((noinline)) int real_owner_work_retry_shape(__u64 key)
{
	int result = -1;
	struct se_ol_payload_handle owner = {};
	if (real_owner_work_open_key(key, &owner) != SE_OL_OK)
		return -1;
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	if (real_owner_work_receipt_exact(key, &owner) && receipt &&
	    se_owk_exec_settle_committed_reader(&owner, receipt, key) ==
		    SE_OL_OK)
		result = real_owner_work_delete_receipt_exact(key, &owner);
	if (se_ol_payload_close(&owner) != SE_OL_OK)
		return -2;
	return result;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_TERMINAL_DRAIN_DIAGNOSTIC
/* Deferred current-task drain only, not a complete failure lifecycle: an
 * idle task can still retain the failed invocation's reader. Kretprobes only
 * certify the terminal; these LSM sources may touch the lock-bearing maps.
 * REGISTERED is deliberately retained: same-bprm continuation is separate. */
static __attribute__((noinline)) int real_owner_source_terminal_drain(void)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	if (!receipt)
		return 0;
	if (!key || receipt->physical != key || !receipt->bprm ||
	    !receipt->cookie || !receipt->locator || !receipt->invocation ||
	    !receipt->scope || !receipt->generation || receipt->reserved ||
	    (receipt->phase != SE_EXEC_TERMINAL_SUCCESS &&
	     receipt->phase != SE_EXEC_TERMINAL_FAILURE))
		return -1;
	/* Retry first: a committed role patch must never be applied twice.
	 * -2 means lexical close failed, so absence alone cannot authorize a
	 * successor. Neither completion nor another retry may hide that fault. */
	int result = real_owner_work_retry_shape(key);
	if (result == -2)
		return -1;
	if (result) {
		result = real_owner_work_completion_shape(key);
		if (result == -2)
			return -1;
		if (result)
			result = real_owner_work_retry_shape(key);
	}
	if (result || bpf_map_lookup_elem(&se_exec_terminal_receipts, &key))
		return -1;
	return 0;
}
#endif

SEC("tc")
int opaque_real_owner_work_retry_probe(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const __u32 *armed = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_gate, &zero);
	const __u64 *selected = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_selector, &zero);
	if (armed && *armed == 1 && selected && *selected)
		(void)real_owner_work_retry_shape(*selected);
	return 0;
}
#endif
char LICENSE[] SEC("license") = "GPL";
