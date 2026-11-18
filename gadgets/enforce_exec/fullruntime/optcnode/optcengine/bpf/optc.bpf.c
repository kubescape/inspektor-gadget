// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
//
// E1: the option C state model on the D4 reference engine's skeleton, deciding
// with the real fullpolicy evaluator (fullpolicy/bpf/evaluator.h, ABI3
// development semantics, scalar-token global matcher). Built twice: the real
// evaluator (bpf_loop) and the compat variant (-DFE_BOUNDED_LOOP_CANDIDATE,
// bounded loops in place of bpf_loop). One CO-RE object per variant.
//
// Hooks (LSM only for the decision, begin, commit and fork; the two tp_btf
// programs only count births and exits for the oracle's quiescence check):
//   lsm/task_alloc            inheritance: binding, committed roles (UNKNOWN
//                             included) and recorded exe facts; R11 for forks
//   lsm/bprm_creds_for_exec   once per exec: reset the pending record, freeze
//                             generation and class; capture the root anchor
//   lsm/bprm_check_security   once per pass: anchor + reachability (R31),
//                             facts via bpf_d_path, evaluate, accumulate
//   lsm/bprm_committed_creds  commit, with generation revalidation (R6 c)
//   tp_btf/sched_process_fork, tp_btf/sched_process_exit: counters only
// There is no syscall-exit program and no failure tracking (R9 dropped).
//
// Contract (005 §7, R1-R11, R31):
//   - Strict deny -> EPERM; Audit never blocks once classified.
//   - A fault before classification (no binding, injected fault, the frozen
//     generation unreadable at begin) denies in every mode.
//   - A fault after classification follows the frozen class: Strict-capable
//     (class 2) denies, audit-only (class 1) allows and reports.
//   - An untracked task in a bound cgroup (no record): Strict denies, Audit
//     allows and reports (R11), by the binding's published class.
//   - Path facts are UNKNOWN until the binding's anchor is captured, when the
//     task's root is not the anchor, when the file is unreachable from it,
//     deleted, or on a kernel-internal mount (R31).

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
struct fm_blob;
static inline const struct fm_blob *oc_blob(unsigned int slot, unsigned long long cookie, unsigned int key);
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) oc_blob((slot), (cookie), (key))
#define FM_BLOB_LOOKUP(context, key)                                                  \
	oc_blob(((const struct fm_global_token *)(context))->slot,                    \
		((const struct fm_global_token *)(context))->cookie, (key))
#if defined(OC_REAL_STAGED) || defined(FE_BOUNDED_LOOP_CANDIDATE)
// Staged variants: the same evaluator through its continuation API
// (fe_stage_begin / advance / finish, evaluator_stage_candidate.h; same
// decision as fe_evaluate, the evaluator's own parity test), one window of
// 16 rules per program invocation (tail-call re-entry while rules remain).
// The monolithic fe_evaluate exceeds the 8-frame call depth with bounded
// loops and the combined stack with bpf_loop (measured).
#ifdef FE_BOUNDED_LOOP_CANDIDATE
// The rule step is inlined into each window (an existing evaluator knob):
// with two stage programs clang would otherwise keep it out of line, one
// frame too many for the 8-frame call depth (measured: 9 on 5.15).
#define FE_RULE_STEP_INLINE_DIAGNOSTIC 1
// The header is re-looked up per rule, not carried in the context: 8 bytes
// less in the stage program's frame (the 8-call chain must fit 512 bytes).
#define FE_STAGE_RELOOKUP_HEADER_CANDIDATE 1
// The product's old-kernel window knobs (opaque_real_owner_child_candidate
// .bpf.c): one rule per advance, 16 advances per invocation, the rule match
// and the matcher's instruction window inlined, the matcher's run state in
// the work area. Measured on Ubuntu 5.15 (E1 diag5 "D"): 537K instructions,
// call depth 7; without them the 5.15 verifier loses the matched-rules
// bound (invalid map-value access) or the stack chain exceeds 512 bytes.
#define FE_STAGE_RULES 1U
#define OC_ADVANCES 16
#define FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC 1
#define FM_WORK_RUN_STATE_DIAGNOSTIC 1
#define FM_STAGE_INLINE_INSTRUCTION_WINDOW 1
#endif
#define OC_STAGED 1
#include "evaluator_stage_candidate.h"
#else
// Re-look the header up per rule instead of carrying it in the evaluation
// context (an existing evaluator knob the product uses): 8 bytes less in
// the frame that calls fe_evaluate.
#define FE_STAGE_RELOOKUP_HEADER_CANDIDATE 1
#include "evaluator.h"
#endif
// G004 parity: the product's stdin-is-pipe fact (enforce_exec/full/stdio.h),
// the same reads and the same UNKNOWN cases.
#include "stdio.h"
// G004 parity: the product's per-class filesystem facts
// (enforce_exec/full/filesystem.h): tmpfs, overlay and deleted from the exec
// file itself. The memfd class needs the product's anon-inode marking hook,
// which option C does not attach: no file is marked, so memfd stays UNKNOWN
// for tmpfs/hugetlbfs files (as for an unmarked file on the product) and is
// known false elsewhere.
#define FULL_FS_SHARED_MARK(inode) ((void)(inode))
#define FULL_FS_SHARED_READ(inode) 0
#include "filesystem.h"

#if defined(FE_BOUNDED_LOOP_CANDIDATE)
#define OC_VARIANT 2 // compat: bounded loops, staged
#elif defined(OC_REAL_STAGED)
#define OC_VARIANT 3 // real evaluator (bpf_loop), staged
#else
#define OC_VARIANT 1 // real evaluator (bpf_loop), monolithic fe_evaluate
#endif

#define OC_EPERM 1
#define OC_SIGKILL 9
#define OC_ROWS 8
#define OC_REACH_STEPS 64
#define OC_ENAMETOOLONG 36
#define OC_MNT_NS_INTERNAL ((unsigned long)-22L)

enum oc_counter {
	OC_C_EXECS = 0, // execs that reached bprm_creds_for_exec as tracked tasks
	OC_C_DECISIONS, // classified decisions (every pass)
	OC_C_ALLOW,
	OC_C_DENY, // Strict deny, blocked
	OC_C_WOULD_DENY, // Audit deny, not blocked
	OC_C_FAULT_DENY, // fault, blocked (before classification, or class 2)
	OC_C_UNKNOWN_EXEC, // untracked task in a bound cgroup tried to exec
	OC_C_UNKNOWN_FORK, // untracked task in a bound cgroup tried to fork
	OC_C_BIRTHS,
	OC_C_ADOPTED,
	OC_C_EXITS,
	OC_C_COMMITS, // bprm_committed_creds of a tracked exec
	OC_C_RESERVED_FAIL, // always 0: no failure tracking
	OC_C_RESERVED_ABORT, // always 0
	OC_C_STALE_PENDING, // always 0: a failed exec's record is simply reset
	OC_C_EVENT_LOST,
	OC_C_STORAGE_FAIL,
	OC_C_FAULT_ALLOW, // fault after classification under class 1: allowed, reported
	OC_C_GEN_MISMATCH, // commits whose frozen generation was no longer current
	OC_C_KILLED, // compromise-8 alternative: SIGKILL at commit (Strict)
	OC_C_REEVAL_DENY_REPORTED, // compromise-8 alternative under audit-only class: reported
	OC_C_ANCHOR_CAPTURED,
	OC_C_PATH_UNKNOWN, // passes whose target path fact is UNKNOWN
	OC_C_ROOT_MISMATCH,
	OC_C_UNREACHABLE,
	OC_C_DELETED,
	OC_C_NO_ANCHOR,
	OC_C_INTERNAL_MOUNT,
	OC_C_UNCERTAIN_COMMIT, // commits that set at least one role UNKNOWN from an uncertain bit
	OC_C_CEILING, // forks refused (or left untracked) at the R12 task ceiling
	OC_C_ANCHOR_REFUSED, // review C4: the init exec'd after Bind, or the bind deadline passed
	OC_C_NESTED_UNKNOWN, // untracked tasks in a cgroup below a bound one (R11)
	OC_C_INIT_IN_WORKLOAD, // review N1: the init already ran a file of its own mount namespace
	OC_C_MAX,
};

enum oc_gauge { OC_G_PENDING = 0, OC_G_LIVE, OC_G_MAX };

enum oc_event_kind {
	OC_EV_DECISION = 1,
	OC_EV_FAULT = 2,
	OC_EV_COMMIT = 3,
};

enum oc_fault {
	OC_FAULT_NONE = 0,
	OC_FAULT_UNKNOWN_TASK = 1,
	OC_FAULT_INJECTED = 2,
	OC_FAULT_NO_BINDING = 3,
	OC_FAULT_NO_GENERATION = 4,
	OC_FAULT_STORAGE = 5,
	OC_FAULT_NO_PENDING = 6,
	OC_FAULT_EVALUATOR = 7,
	OC_FAULT_STAGE = 8, // a rule-window tail call failed or the window cap was hit
	OC_FAULT_CEILING = 9, // R12: the binding's tracked-task ceiling
};

// Why a pass's target path fact is UNKNOWN (0: known).
enum oc_path_reason {
	OC_PR_KNOWN = 0,
	OC_PR_NO_ANCHOR = 1,
	OC_PR_ROOT_MISMATCH = 2,
	OC_PR_UNREACHABLE = 3,
	OC_PR_INTERNAL = 4,
	OC_PR_DELETED = 5,
	OC_PR_D_PATH = 6,
	OC_PR_TOO_LONG = 7,
	OC_PR_WALK_UNKNOWN = 8,
	OC_PR_NO_FILE = 9,
};

// Commit flags.
#define OC_CF_GEN_MISMATCH 1
#define OC_CF_KILLED 2
#define OC_CF_REEVAL_DENY 4
#define OC_CF_KNOWN_DENY 8
#define OC_CF_FAULT 16
#define OC_CF_UNCERTAIN 32

// Deliberate bugs for the negative controls (E7-style). 0 is the engine.
enum oc_mutant {
	OC_MUT_NONE = 0,
	OC_MUT_AUDIT_BLOCKS = 1,
	OC_MUT_FAULT_ALLOWS = 2,
	OC_MUT_NO_ANCHOR_CHECK = 3, // trust bpf_d_path from the task's own root
	OC_MUT_NO_REVALIDATE = 4, // commit the proposal even if the generation changed
	OC_MUT_NO_RESET = 5, // keep the previous exec's proposal at exec begin
	OC_MUT_NO_UNCERTAIN = 6, // commit proposals despite uncertain bits
	OC_MUT_NO_INHERIT = 7, // children start with every role UNKNOWN
	OC_MUT_SKIP_INTERP_PASS = 8,
	OC_MUT_ANCHOR_RECAPTURE = 9, // the anchor is rewritten at every init exec
	OC_MUT_WALK_EXHAUST_ALLOWS = 10, // an exhausted reachability walk counts as reachable
	OC_MUT_NO_BRACKET = 11, // the d_seq / mount-event brackets are ignored
	OC_MUT_STAGE_FAULT_ALLOWS = 12, // a stage fault allows under Strict
	OC_MUT_REEVAL_NO_KILL = 13, // the compromise-8 re-evaluation never kills
	OC_MUT_ONLY_PROPOSED_UNKNOWN = 14, // a generation mismatch blanks only proposed policies
	OC_MUT_R11_ALLOWS = 15, // an untracked task is allowed under Strict
	OC_MUT_NO_ROOT_CHECK = 16, // the anchor / task-root comparison is skipped
	OC_MUT_NO_REACH_CHECK = 17, // the reachability walk is skipped
	OC_MUT_NO_DELETED_CHECK = 18, // the unlinked check is skipped
	// G003
	OC_MUT_ACTOR_FIRST_PASS = 19, // E2: the recorded exe facts are the first pass's
	OC_MUT_ANCESTOR_SKIP_UNKNOWN = 20, // E2: an ancestor with unknown exe facts ends the walk as complete
	OC_MUT_ANCESTOR_OFF = 21, // E2: no ancestors, complete
	OC_MUT_NO_FREEZE = 22, // E3: a pass reads the binding's current generation
	OC_MUT_RETIRED_ALLOWS = 23, // E3: a retired frozen generation allows under Strict
	OC_MUT_WITNESS_OFF = 24, // E4: the witness never latches
	OC_MUT_GUARD_OFF = 25, // E4: the exec-receipt guard never kills
	OC_MUT_GUARD_AUDIT_KILLS = 26, // E4: the guard kills in audit-only bindings too
	OC_MUT_GUARD_ANY_RECEIPT = 27, // E4: any receipt of the task passes (not bound to this exec)
	OC_MUT_REEVAL_NO_ROLES = 28, // review R2: the re-evaluation sees no roles
	OC_MUT_KEEP_BLOCKED_WORK = 29, // review R4: a blocked exec keeps its work area
	// G004
	OC_MUT_EVAL_ERROR_ALLOWS = 30, // E3-2: an evaluation error allows under Strict
	OC_MUT_RECEIPT_UNDECIDED = 31, // E4-1: the receipt is written for an undecided exec
	OC_MUT_ANCHOR_TID_ONLY = 32, // R6: the anchor source is matched by tid only
	OC_MUT_NO_CEILING = 33, // R12: the task ceiling is ignored
	OC_MUT_SEED_ALL_POLICIES = 34, // R1: rows seeded for every policy, never reclaimed
	// G004 review 1
	OC_MUT_REEVAL_KILL_UNCHECKED = 35, // C5: a refused re-evaluation kill counts as KILLED, no latch
	OC_MUT_LATE_ANCHOR = 36, // C4: the anchor is captured whatever the init did since Bind
	OC_MUT_LEAF_CGROUP_ONLY = 37, // R11: only the task's own cgroup is looked up
	// G004 review 2
	OC_MUT_EXE_ANY_MOUNT = 38, // N1: the init's pre-exec image may be on its own mount namespace
};

// Test switches exist only in the test object (-DOC_TEST_BUILD); the product
// object is compiled without them (review R6).
#ifdef OC_TEST_BUILD
const volatile __u32 oc_mutant = 0;
#define OC_MUT(m) (oc_mutant == (m))
#define OC_TEST_SWITCH(x) (x)
#else
#define OC_MUT(m) 0
// Review M2: test switches (fault injection, test flags) are 0 in the
// product object.
#define OC_TEST_SWITCH(x) 0
#endif
// Compromise-8 alternative on (1) or off (0, baseline: roles UNKNOWN only).
const volatile __u32 oc_reeval = 1;
// The per-CPU work area's key, as a map value: a stack key would cost the
// frame that calls fe_evaluate the bytes its call chain does not have.
const volatile __u32 oc_zero_key = 0;
// Rule-window invocations allowed per pass (staged variants). 16 windows of
// 16 rules walk the compiler's 256-rule maximum; with the entry hop that is
// 17 of the kernel's 33 tail calls. Publication refuses a policy needing more
// (engine.go Limits). Lowered only by the negative-control tests.
#ifdef OC_TEST_BUILD
const volatile __u32 oc_stage_cap = 16;
#else
#define oc_stage_cap 16U
#endif

struct oc_binding {
	__u64 gen; // current generation (0: none)
	__u32 fault_inject;
	__u32 class; // published execution class of gen (R11, storage faults)
	__u32 init_tid; // the seeded init (the anchor's source)
	// Test-only: write a foreign owner stamp at prepare, so the next window
	// entry sees it (the owner check must make that a stage fault).
	__u32 test_clobber_stamp;
	__u64 init_start; // review R6: the init's start time (USER_HZ ticks)
	__u32 role_mask; // review R1: role-bearing policy indexes of gen
	__u32 max_tasks; // R12 ceiling of tracked tasks (0: none)
	__u32 test_flags; // OC_TEST_BUILD only: OC_TF_*
	__u32 pad3;
};

// Test-only binding flags (ignored by the product object).
#define OC_TF_RETIRE_AFTER_WINDOW 1 // review E3-2: blobs vanish after window 1
#define OC_TF_BRACKET_FAIL 2 // review R5: the mount-event bracket reads changed
#define OC_TF_KILL_FAIL 4 // review C5: the re-evaluation's SIGKILL is refused

// Tracked tasks per binding (R12 ceiling), kept by BPF only.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __s64);
} oc_btasks SEC(".maps");

// The agent's tgid: its own forks and execs (the start canary) are watched.
const volatile __u32 oc_agent_tgid = 0;

// The binding's root anchor (R31): written only by BPF, once, at the seeded
// init's first bprm_creds_for_exec.
struct oc_anchor {
	__u64 root_ino;
	__u32 root_mnt_id, root_dev, mntns, init_tid;
	__u64 captured_ns;
};

struct oc_blob_key {
	__u64 gen;
	__u32 key;
	__u32 pad;
};

struct oc_row {
	__u64 uid, epoch, role; // role 0: no row
	__u32 known, pad; // 0: UNKNOWN
};

struct oc_task {
	__u64 binding;
	__u64 exec_id;
	__u32 counted, is_init;
	struct oc_row rows[OC_ROWS];
	struct fe_path exe_path; // recorded exe facts (final pass), length 0: UNKNOWN
	// pending record
	__u32 p_active, p_passes;
	__u64 p_gen;
	__u32 p_class, p_policies;
	__u32 p_known_deny, p_fault, p_writes, p_uncertain, p_grants, p_conflicts;
	__u32 p_enforced_writes, p_global_unknown;
	__u64 p_uids[8], p_epochs[8], p_witness[8];
	struct fe_path p_target; // facts of the latest pass
	__u64 p_dev, p_ino;
	__u32 p_uid, p_reason;
	__u32 p_nonce, p_decided; // p_decided: passes that reached oc_finish
	__s32 p_stdin; // the latest pass's stdin-is-pipe fact (-1: UNKNOWN)
	__u32 p_fs_mask, p_fs_known; // the latest pass's fs classes (per-class known)
	__u32 p_pad;
};

struct oc_event {
	__u32 kind;
	__u32 fault;
	__u64 cgroup;
	__u64 gen;
	__u64 exec_id;
	__u64 dev;
	__u64 ino;
	__u32 pid;
	__u32 tid;
	__u32 mode;
	__u32 deny;
	__u32 blocked;
	__u32 pass;
	__u32 outcome; // commit flags
	__s32 ret;
	__u32 error, audit_unknown;
	__u32 path_reason, class;
	__u64 roles[OC_ROWS];
	__u32 known_mask, variant;
	struct fe_path path;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct oc_binding);
} oc_bindings SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct oc_anchor);
} oc_anchors SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
	__uint(max_entries, 65536);
	__type(key, struct oc_blob_key);
	__type(value, struct fm_blob);
} oc_blobs SEC(".maps");

struct oc_adopt {
	__u64 cgroup;
	__u32 is_init, pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct oc_adopt);
} oc_adopt SEC(".maps");

// Review C4: a binding's init, registered at Bind (before any policy): its
// cgroup, and its execs since Bind (sched_process_exec). The anchor is
// captured only at the init's FIRST exec since Bind; a later one, or a
// capture closed by the agent (bind deadline), never captures.
struct oc_init {
	__u64 cgroup;
	__u32 execs, closed;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct oc_init);
} oc_inits SEC(".maps");

// The number of bindings (written by the agent): no ancestor walk while 0.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} oc_nbind SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct oc_task);
} oc_tasks SEC(".maps");

struct oc_work {
	struct fe_facts facts;
	struct fe_scratch scratch;
	// The evaluator's blob token lives here, not on the stack: the frame
	// that calls fe_evaluate must stay small enough for the evaluator's
	// call chain to fit the 512-byte combined stack.
	struct fm_global_token tok;
	// Owner stamp (F1): the task's exec id, the pass and a per-use nonce,
	// written at prepare and re-checked at every window entry, at finish
	// and at the commit's re-evaluation. A mismatch is a stage fault.
	__u64 owner_exec;
	__u32 owner_pass, owner_nonce;
	__u32 c_flags, c_reclass; // a commit's state across its tail calls
	__u32 c_test_kill_fail, c_pad; // test build: the re-evaluation kill is refused
#ifdef OC_STAGED
	__u32 stage_calls, pad2; // rule-window invocations of this pass
	struct fe_stage_cursor cursor;
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
	struct fe_alt_request alt;
#endif
#endif
};

// The work area of an exec in flight lives in the exec'ing task's own
// storage (F1: a per-CPU area could be overwritten by another exec that
// preempts this one on the same CPU). Created at exec begin, deleted at
// commit; a failed exec's area is reused by the task's next exec.
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct oc_work);
} oc_works SEC(".maps");

static __always_inline struct oc_work *oc_work_get(void)
{
	return bpf_task_storage_get(&oc_works, bpf_get_current_task_btf(), 0, 0);
}

// ------------------------------------------------------------ E4 witness
//
// Per-task marks in task storage (S1 review F2, N1): the LSM hook marks the
// task, the tracepoint (which keeps firing when ftrace is off and every BPF
// LSM program is silent) checks and clears the mark. No counts are compared
// and there is no global map to fill: a mark lives and dies with its task.
// Node-wide: every fork and exec, bound or not. The exec mark is bound to the
// exec (its bprm and the self_exec_id it will have after begin_new_exec).
// The receipt (set at bprm_committed_creds) lets the guard tell a decided
// exec from one the engine never saw.
struct oc_mark {
	__u64 exec_bprm, receipt_bprm;
	__u32 exec_seq, receipt_seq;
	__u32 forked, pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct oc_mark);
} oc_marks SEC(".maps");

enum oc_wcell {
	OC_W_ARMED = 0, // set by the agent once the start canary saw its marks
	OC_W_LATCHED, // sticky: an exec or fork the LSM hooks did not see
	OC_W_EXEC_UNMARKED,
	OC_W_FORK_UNMARKED,
	OC_W_GUARD_KILLS,
	OC_W_MARK_FAIL, // a mark could not be stored (counted, never latched)
	OC_W_EXEC_SEEN, // marked execs the tracepoint confirmed (canary)
	OC_W_FORK_SEEN,
	OC_W_LSM_ALLOC, // runs of each LSM program (the canary needs all four)
	OC_W_LSM_CREDS,
	OC_W_LSM_CHECK,
	OC_W_LSM_COMMIT,
	OC_W_SIGNAL_FAIL, // a guard kill that bpf_send_signal refused (latches)
	OC_W_UNDECIDED, // a committed exec with a pass bprm_check never decided (latches)
	OC_W_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, OC_W_MAX);
	__type(key, __u32);
	__type(value, __u64);
} oc_witness SEC(".maps");

static __always_inline __u64 oc_wget(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&oc_witness, &idx);

	return v ? *v : 0;
}

static __always_inline void oc_wadd(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&oc_witness, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline void oc_wlatch(__u32 cell)
{
	__u32 one = OC_W_LATCHED;
	__u64 *v;

	oc_wadd(cell);
	if (OC_MUT(OC_MUT_WITNESS_OFF) || !oc_wget(OC_W_ARMED))
		return;
	v = bpf_map_lookup_elem(&oc_witness, &one);
	if (v)
		*v = 1;
}

// Review (open question, child cgroups): the binding that governs an
// UNTRACKED task: its own cgroup's, else the nearest bound ancestor's (a
// systemd-style sub-cgroup of a container is the container's). Bounded:
// OC_CG_LEVELS ancestors; a task deeper than that below the root, on a node
// with bindings, gets oc_deep (Strict: UNKNOWN, denied). *cg is the bound
// cgroup (0 for oc_deep).
#define OC_CG_LEVELS 32
static __always_inline void oc_count(__u32 idx);
static struct oc_binding oc_deep = { .class = 2 };

static __always_inline struct oc_binding *oc_bound_cgroup(__u64 *cg)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct oc_binding *b;
	__u32 zero = 0, *n;
	int level = 0;

	*cg = bpf_get_current_cgroup_id();
	b = bpf_map_lookup_elem(&oc_bindings, cg);
	if (b || OC_MUT(OC_MUT_LEAF_CGROUP_ONLY))
		return b;
	n = bpf_map_lookup_elem(&oc_nbind, &zero);
	if (!n || !*n)
		return NULL;
	if (BPF_CORE_READ_INTO(&level, t, cgroups, dfl_cgrp, level) || level < 0) {
		*cg = 0;
		return &oc_deep;
	}
	if (level > OC_CG_LEVELS) {
		*cg = 0;
		return &oc_deep;
	}
	for (int i = 1; i <= OC_CG_LEVELS; i++) {
		__u64 id;

		if (i > level)
			break;
		id = bpf_get_current_ancestor_cgroup_id(level - i);
		b = bpf_map_lookup_elem(&oc_bindings, &id);
		if (b) {
			*cg = id;
			oc_count(OC_C_NESTED_UNKNOWN);
			return b;
		}
	}
	return NULL;
}

// The witness and guard watch the tasks enforcement depends on (review
// E4-4: no node-wide allocation a foreign fork bomb could exhaust): tracked
// tasks, tasks in bound cgroups, and the agent's own children (the canary).
static __always_inline int oc_watched(struct task_struct *t, int tracked)
{
	__u64 cg;

	if (tracked)
		return 1;
	if (oc_bound_cgroup(&cg))
		return 1;
	if (!oc_agent_tgid)
		return 0;
	return BPF_CORE_READ(t, tgid) == oc_agent_tgid || BPF_CORE_READ(t, real_parent, tgid) == oc_agent_tgid;
}

static __always_inline __u32 oc_self_exec_id(struct task_struct *t)
{
	__u64 id = 0;

	bpf_core_read(&id, bpf_core_field_size(t->self_exec_id), &t->self_exec_id);
	return (__u32)id;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, OC_C_MAX);
	__type(key, __u32);
	__type(value, __u64);
} oc_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, OC_G_MAX);
	__type(key, __u32);
	__type(value, __s64);
} oc_gauges SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 23);
} oc_events SEC(".maps");

static inline const struct fm_blob *oc_blob(unsigned int slot, unsigned long long cookie, unsigned int key)
{
	struct oc_blob_key k = { .gen = cookie, .key = key };

	if (slot != 0 || !cookie || key >= FM_MAX_ENTRIES)
		return 0;
	return bpf_map_lookup_elem(&oc_blobs, &k);
}

static __always_inline void oc_count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&oc_counters, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline void oc_gauge(__u32 idx, __s64 delta)
{
	__s64 *v = bpf_map_lookup_elem(&oc_gauges, &idx);

	if (v)
		__sync_fetch_and_add(v, delta);
}

static __always_inline struct oc_event *oc_event_reserve(__u32 kind)
{
	struct oc_event *e = bpf_ringbuf_reserve(&oc_events, sizeof(*e), 0);
	__u64 pt;

	if (!e) {
		oc_count(OC_C_EVENT_LOST);
		return NULL;
	}
	__builtin_memset(e, 0, sizeof(*e));
	pt = bpf_get_current_pid_tgid();
	e->kind = kind;
	e->pid = pt >> 32;
	e->tid = (__u32)pt;
	e->variant = OC_VARIANT;
	return e;
}

static __always_inline void oc_fault_event(__u64 cgroup, __u32 fault, struct oc_task *s, __u32 blocked)
{
	struct oc_event *e = oc_event_reserve(OC_EV_FAULT);

	if (!e)
		return;
	e->cgroup = cgroup;
	e->fault = fault;
	e->deny = 1;
	e->blocked = blocked;
	if (s) {
		e->exec_id = s->exec_id;
		e->gen = s->p_gen;
		e->pass = s->p_passes;
		e->class = s->p_class;
	}
	bpf_ringbuf_submit(e, 0);
}

// ------------------------------------------------------------ evaluator

#ifdef OC_STAGED

// Tail-call split (staged variants): each rule window runs in a program
// invocation of its own (the 5.15 verifier refuses one program that holds
// the whole evaluation: over 1M instructions), re-entering itself while
// rules remain: 256 rules need 16 windows, within the 33 tail calls. The stage programs are loaded,
// never attached; each array holds programs of its own hook only.
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} oc_check_stages SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} oc_commit_stages SEC(".maps");

__noinline int oc_stage_begin(struct oc_work *w)
{
	if (!w)
		return -1;
	__builtin_memset(&w->cursor, 0, sizeof(w->cursor));
	return fe_stage_begin(&w->tok, &w->facts, &w->scratch, &w->cursor);
}

// One window of FE_STAGE_RULES rules: 1 rules remain, 0 ready, -1 error.
// Inline in the stage program: one window per invocation, as in the
// evaluator's staged probe.
#ifndef OC_ADVANCES
#define OC_ADVANCES 1
#endif
static __always_inline int oc_stage_run(struct oc_work *w)
{
#if OC_ADVANCES > 1
#pragma clang loop unroll(disable)
	for (int k = 0; k < OC_ADVANCES; k++) {
#else
	{
#endif
		if (w->cursor.state != FE_STAGE_ACTIVE)
			return 0;
		if (fe_stage_advance(&w->tok, &w->facts, &w->scratch, &w->cursor
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
				     ,
				     &w->alt
#endif
				     ) != 0) {
			if (!w->scratch.decision.error)
				w->scratch.decision.error = FE_INVALID;
			for (int j = 0; j < 8; j++)
				w->scratch.decision.proposed_roles[j] = 0;
			return -1;
		}
	}
	return w->cursor.state == FE_STAGE_ACTIVE ? 1 : 0;
}

__noinline int oc_stage_finish(struct oc_work *w)
{
	if (!w)
		return -1;
	return fe_stage_finish(&w->tok, &w->scratch, &w->cursor);
}
#else
#define OC_EVALUATE(w) fe_evaluate(&(w)->tok, &(w)->facts, &(w)->scratch)
#endif

// ------------------------------------------------------------ R31 anchoring

// The current task's root identity: 0, or -1 unreadable.
static __always_inline int oc_task_root(struct task_struct *task, __u64 *ino, __u32 *mnt_id, __u32 *dev, __u32 *mntns)
{
	struct vfsmount *vfs = 0;
	struct dentry *dentry = 0;
	int id = 0;
	unsigned long i_ino = 0;
	__u32 s_dev = 0;
	unsigned int inum = 0;

	if (BPF_CORE_READ_INTO(&vfs, task, fs, root.mnt) || BPF_CORE_READ_INTO(&dentry, task, fs, root.dentry) || !vfs ||
	    !dentry)
		return -1;
	struct mount *mnt = (void *)vfs - bpf_core_field_offset(struct mount, mnt);
	if (BPF_CORE_READ_INTO(&id, mnt, mnt_id) || BPF_CORE_READ_INTO(&i_ino, dentry, d_inode, i_ino) ||
	    BPF_CORE_READ_INTO(&s_dev, dentry, d_sb, s_dev) || BPF_CORE_READ_INTO(&inum, task, nsproxy, mnt_ns, ns.inum) ||
	    !i_ino || !inum)
		return -1;
	*ino = i_ino;
	*mnt_id = (__u32)id;
	*dev = s_dev;
	*mntns = inum;
	return 0;
}

// fs_struct seq: seqcount_spinlock_t (<= 6.17) or seqlock_t (6.18+).
struct oc_seqcount___l {
	unsigned int sequence;
} __attribute__((preserve_access_index));
struct oc_seqcount_spin___l {
	struct oc_seqcount___l seqcount;
} __attribute__((preserve_access_index));
struct oc_seqlock___l {
	struct oc_seqcount_spin___l seqcount;
} __attribute__((preserve_access_index));
struct fs_struct___oc_seqcount {
	struct oc_seqcount_spin___l seq;
} __attribute__((preserve_access_index));
struct fs_struct___oc_seqlock {
	struct oc_seqlock___l seq;
} __attribute__((preserve_access_index));

// Odd (1) when unreadable: never a stable value.
static __always_inline __u32 oc_fs_seq(struct task_struct *task)
{
	void *fs = 0;
	unsigned int seq = 1;

	if (BPF_CORE_READ_INTO(&fs, task, fs) || !fs)
		return 1;
	if (bpf_core_field_exists(((struct fs_struct___oc_seqlock *)0)->seq.seqcount.seqcount.sequence)) {
		if (BPF_CORE_READ_INTO(&seq, (struct fs_struct___oc_seqlock *)fs, seq.seqcount.seqcount.sequence))
			return 1;
	} else if (bpf_core_field_exists(((struct fs_struct___oc_seqcount *)0)->seq.seqcount.sequence)) {
		if (BPF_CORE_READ_INTO(&seq, (struct fs_struct___oc_seqcount *)fs, seq.seqcount.sequence))
			return 1;
	} else {
		return 1;
	}
	asm volatile("" ::: "memory");
	return seq;
}

// 1 rooted at the anchor, 0 not, -1 unknown.
static __always_inline int oc_rooted(struct task_struct *task, const struct oc_anchor *a)
{
	__u64 ino = 0;
	__u32 mnt_id = 0, dev = 0, mntns = 0;

	if (oc_task_root(task, &ino, &mnt_id, &dev, &mntns))
		return -1;
	return ino == a->root_ino && mnt_id == a->root_mnt_id && dev == a->root_dev && mntns == a->mntns;
}

static __always_inline __u64 oc_mount_event(struct task_struct *task)
{
	__u64 event = 0;

	// Review M4: no event field means no bracket: UNKNOWN (0), never a
	// constant that would make every walk look unchanged.
	if (!bpf_core_field_exists(struct mnt_namespace, event))
		return 0;
	if (BPF_CORE_READ_INTO(&event, task, nsproxy, mnt_ns, event))
		return 0;
	return event + 1;
}

// 1 reachable from the current root; 0 not; 2 kernel-internal mount; -1
// unknown. d_path's own walk (prepend_path), bounded.
static __always_inline int oc_reachable(struct task_struct *task, struct file *file, int force_change)
{
	struct dentry *dentry = 0, *root_dentry = 0;
	struct vfsmount *root_mnt = 0, *vfs = 0;
	struct mount *mnt;
	__u64 before = oc_mount_event(task);
	int result = -1;

	if (!before || BPF_CORE_READ_INTO(&root_dentry, task, fs, root.dentry) ||
	    BPF_CORE_READ_INTO(&root_mnt, task, fs, root.mnt) || BPF_CORE_READ_INTO(&dentry, file, f_path.dentry) ||
	    BPF_CORE_READ_INTO(&vfs, file, f_path.mnt) || !root_dentry || !root_mnt || !dentry || !vfs)
		return -1;
	mnt = (void *)vfs - bpf_core_field_offset(struct mount, mnt);
	for (int i = 0; i < OC_REACH_STEPS; i++) {
		struct vfsmount *cur = (void *)mnt + bpf_core_field_offset(struct mount, mnt);
		struct dentry *mnt_root = 0, *up = 0;
		unsigned int seq = 0, again = 1;

		if (dentry == root_dentry && cur == root_mnt) {
			result = 1;
			break;
		}
		if (BPF_CORE_READ_INTO(&mnt_root, cur, mnt_root)) {
			result = -1;
			break;
		}
		if (dentry == mnt_root) {
			struct mount *parent = BPF_CORE_READ(mnt, mnt_parent);

			if (!parent || parent == mnt) {
				unsigned long ns = (unsigned long)BPF_CORE_READ(mnt, mnt_ns);

				result = ns == OC_MNT_NS_INTERNAL ? 2 : 0;
				break;
			}
			dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = parent;
			continue;
		}
		if ((BPF_CORE_READ_INTO(&seq, dentry, d_seq.seqcount.sequence) || (seq & 1)) &&
		    !OC_MUT(OC_MUT_NO_BRACKET)) {
			result = -1;
			break;
		}
		up = BPF_CORE_READ(dentry, d_parent);
		if ((BPF_CORE_READ_INTO(&again, dentry, d_seq.seqcount.sequence) || again != seq) &&
		    !OC_MUT(OC_MUT_NO_BRACKET)) {
			result = -1;
			break;
		}
		if (!up || up == dentry) {
			result = 0;
			break;
		}
		dentry = up;
		if (i == OC_REACH_STEPS - 1 && OC_MUT(OC_MUT_WALK_EXHAUST_ALLOWS))
			result = 1; // mutant: an exhausted walk counts as reachable
	}
	// force_change (test build, review R5): the bracket reads a changed
	// mount tree, deterministically.
	if ((oc_mount_event(task) != before || force_change) && !OC_MUT(OC_MUT_NO_BRACKET))
		return -1;
	return result;
}

// 1 unlinked, 0 linked, -1 unreadable.
static __always_inline int oc_unlinked(struct file *file)
{
	struct dentry *dentry = 0, *parent = 0;
	void *pprev = 0;

	if (BPF_CORE_READ_INTO(&dentry, file, f_path.dentry) || !dentry || BPF_CORE_READ_INTO(&parent, dentry, d_parent) ||
	    BPF_CORE_READ_INTO(&pprev, dentry, d_hash.pprev))
		return -1;
	return !pprev && parent != dentry;
}

// Review N1: is the task still running the container runtime's image, i.e.
// a file NOT on a mount of its own mount namespace (the host runc/crun
// binary, runc's sealed memfd clone)? After its entrypoint exec the init
// runs a file of the container's mounts. 1 outside (runtime), 0 inside
// (workload), and 0 when unreadable (fail closed).
static __always_inline int oc_exe_outside_ns(struct task_struct *task)
{
	struct file *exe = 0;
	struct vfsmount *vm = 0;
	struct mnt_namespace *mns = 0, *tns = 0;
	struct mount *m;

	if (BPF_CORE_READ_INTO(&exe, task, mm, exe_file) || !exe || BPF_CORE_READ_INTO(&vm, exe, f_path.mnt) || !vm ||
	    BPF_CORE_READ_INTO(&tns, task, nsproxy, mnt_ns) || !tns)
		return 0;
	m = (void *)vm - bpf_core_field_offset(struct mount, mnt);
	if (BPF_CORE_READ_INTO(&mns, m, mnt_ns))
		return 0;
	return mns != tns;
}

// ------------------------------------------------------------ task records

static __always_inline void oc_btasks_add(__u64 binding, __s64 d)
{
	__s64 *v = bpf_map_lookup_elem(&oc_btasks, &binding), zero = 0;

	if (!v) {
		bpf_map_update_elem(&oc_btasks, &binding, &zero, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&oc_btasks, &binding);
	}
	if (v)
		__sync_fetch_and_add(v, d);
}

static __always_inline __s64 oc_btasks_get(__u64 binding)
{
	__s64 *v = bpf_map_lookup_elem(&oc_btasks, &binding);

	return v ? *v : 0;
}

// Rows are seeded only for the generation's role-bearing policies (review
// R1: a policy that neither writes nor tests roles takes no row).
static __always_inline void oc_seed_rows(struct oc_task *s, __u64 gen, __u32 role_mask)
{
	struct fm_global_token tok = { .slot = 0, .cookie = gen };
	const struct fe_header *h = FE_HEADER_LOOKUP(&tok);
	__u32 n;

	for (int i = 0; i < OC_ROWS; i++) {
		s->rows[i].uid = 0;
		s->rows[i].epoch = 0;
		s->rows[i].role = 0;
		s->rows[i].known = 0;
	}
	if (!h)
		return;
	n = h->policies;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= n)
			break;
		const struct fe_policy *p = FE_POLICY_LOOKUP(&tok, i);

		if (!p || (!(role_mask & (1U << i)) && !OC_MUT(OC_MUT_SEED_ALL_POLICIES)))
			continue;
		s->rows[i].uid = p->uid;
		s->rows[i].epoch = p->root_epoch;
		s->rows[i].role = p->root_role;
		s->rows[i].known = p->root_role != 0;
	}
}

// The current task's record, adopting it first if the agent asked for it.
static __always_inline struct oc_task *oc_current(void)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct oc_task *s;
	struct oc_adopt *want;
	struct oc_binding *b;
	__u64 cg;
	__u32 tid;

	s = bpf_task_storage_get(&oc_tasks, t, 0, 0);
	if (s)
		return s;
	tid = (__u32)bpf_get_current_pid_tgid();
	want = bpf_map_lookup_elem(&oc_adopt, &tid);
	if (!want)
		return NULL;
	cg = bpf_get_current_cgroup_id();
	b = bpf_map_lookup_elem(&oc_bindings, &cg);
	if (want->cgroup != cg || !b)
		return NULL;
	s = bpf_task_storage_get(&oc_tasks, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!s) {
		oc_count(OC_C_STORAGE_FAIL);
		return NULL;
	}
	s->binding = cg;
	s->counted = 1;
	s->is_init = want->is_init;
	s->exe_path.length = 0; // seeded init: UNKNOWN (R15)
	oc_seed_rows(s, b->gen, b->role_mask);
	bpf_map_delete_elem(&oc_adopt, &tid);
	oc_count(OC_C_ADOPTED);
	oc_gauge(OC_G_LIVE, 1);
	oc_btasks_add(cg, 1);
	return s;
}

// ------------------------------------------------------------ fork

SEC("lsm/task_alloc")
int BPF_PROG(oc_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
	struct oc_task *ps, *cs;
	struct oc_binding *b;
	struct oc_mark *m;
	__u64 cg;

	oc_wadd(OC_W_LSM_ALLOC);
	ps = oc_current();
	// E4: every watched fork.
	if (oc_watched(bpf_get_current_task_btf(), ps != 0)) {
		m = bpf_task_storage_get(&oc_marks, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (m)
			m->forked = 1;
		else
			oc_wadd(OC_W_MARK_FAIL);
	}
	if (!ps) {
		b = oc_bound_cgroup(&cg);
		if (!b)
			return 0;
		// R11: untracked task in a bound cgroup (or below one).
		oc_count(OC_C_UNKNOWN_FORK);
		oc_fault_event(cg, OC_FAULT_UNKNOWN_TASK, NULL, b->class != 1);
		if (b->class == 1)
			return 0;
		return -OC_EPERM;
	}
	// R12: the binding's tracked-task ceiling. At the ceiling a Strict
	// binding refuses the fork; an audit-only one lets an untracked child
	// through (R11 then reports it).
	b = bpf_map_lookup_elem(&oc_bindings, &ps->binding);
	if (b && b->max_tasks && oc_btasks_get(ps->binding) >= b->max_tasks && !OC_MUT(OC_MUT_NO_CEILING)) {
		oc_count(OC_C_CEILING);
		oc_fault_event(ps->binding, OC_FAULT_CEILING, ps, b->class != 1);
		if (b->class == 1)
			return 0;
		return -OC_EPERM;
	}
	cs = bpf_task_storage_get(&oc_tasks, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cs) {
		oc_count(OC_C_STORAGE_FAIL);
		b = bpf_map_lookup_elem(&oc_bindings, &ps->binding);
		oc_fault_event(ps->binding, OC_FAULT_STORAGE, NULL, !b || b->class != 1);
		if (b && b->class == 1)
			return 0; // the child is untracked: R11 applies to it
		return -OC_EPERM;
	}
	cs->binding = ps->binding;
	cs->exec_id = 0;
	cs->counted = 0;
	cs->is_init = 0;
	cs->p_active = 0;
	if (OC_MUT(OC_MUT_NO_INHERIT)) {
		for (int i = 0; i < OC_ROWS; i++) {
			cs->rows[i] = ps->rows[i];
			cs->rows[i].known = 0;
		}
	} else {
		for (int i = 0; i < OC_ROWS; i++)
			cs->rows[i] = ps->rows[i];
	}
	__builtin_memcpy(&cs->exe_path, &ps->exe_path, sizeof(cs->exe_path));
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(oc_sched_fork, struct task_struct *parent, struct task_struct *child)
{
	struct oc_mark *m = bpf_task_storage_get(&oc_marks, child, 0, 0);
	struct oc_task *cs;
	int watched = oc_watched(parent, bpf_task_storage_get(&oc_tasks, parent, 0, 0) != 0);

	// E4: task_alloc must have seen this watched fork.
	if (!watched) {
		if (m)
			m->forked = 0;
	} else if (!m || !m->forked) {
		oc_wlatch(OC_W_FORK_UNMARKED);
	} else {
		m->forked = 0;
		oc_wadd(OC_W_FORK_SEEN);
	}
	cs = bpf_task_storage_get(&oc_tasks, child, 0, 0);
	if (!cs || cs->counted)
		return 0;
	cs->counted = 1;
	oc_count(OC_C_BIRTHS);
	oc_gauge(OC_G_LIVE, 1);
	oc_btasks_add(cs->binding, 1);
	return 0;
}

// E4: the exec witness and the exec-receipt guard (D2 F7, adapted). Runs
// after the point of no return and before the new image's first user
// instruction; tracepoints keep firing when ftrace is off.
//   witness: an exec whose bprm_creds_for_exec did not mark it latches.
//   guard:   an exec of a task governed by a Strict-capable binding (its
//            record's binding, or, untracked, the bound cgroup it is in)
//            without this exec's commit receipt is killed (SIGKILL).
SEC("tp_btf/sched_process_exec")
int BPF_PROG(oc_sched_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct oc_mark *m = bpf_task_storage_get(&oc_marks, p, 0, 0);
	__u32 seq = oc_self_exec_id(p);
	struct oc_task *s = bpf_task_storage_get(&oc_tasks, p, 0, 0);
	struct oc_binding *b;
	__u64 cg;
	int receipt = 0;
	long sig;
	__u32 ptid = BPF_CORE_READ(p, pid);
	struct oc_init *ini = bpf_map_lookup_elem(&oc_inits, &ptid);

	// Review C4: count a registered init's execs since Bind.
	if (ini)
		__sync_fetch_and_add(&ini->execs, 1);
	if (!oc_watched(p, s != 0)) {
		if (m)
			m->exec_bprm = 0;
		return 0;
	}
	if (!m || m->exec_bprm != (__u64)bprm || m->exec_seq != seq) {
		oc_wlatch(OC_W_EXEC_UNMARKED);
	} else {
		oc_wadd(OC_W_EXEC_SEEN);
	}
	if (m) {
		receipt = OC_MUT(OC_MUT_GUARD_ANY_RECEIPT) ?
				  m->receipt_bprm != 0 :
				  m->receipt_bprm == (__u64)bprm && m->receipt_seq == seq;
		m->exec_bprm = 0;
		if (!OC_MUT(OC_MUT_GUARD_ANY_RECEIPT))
			m->receipt_bprm = 0;
	}
	if (receipt || OC_MUT(OC_MUT_GUARD_OFF))
		return 0;
	if (s) {
		cg = s->binding;
		b = bpf_map_lookup_elem(&oc_bindings, &cg);
	} else {
		b = oc_bound_cgroup(&cg);
	}
	if (!b || (b->class != 2 && !OC_MUT(OC_MUT_GUARD_AUDIT_KILLS)))
		return 0;
	// Review E4-3: a kill counts only if the signal was queued; a refused
	// one latches the witness.
	sig = bpf_send_signal(OC_SIGKILL);
	if (sig == 0)
		oc_wadd(OC_W_GUARD_KILLS);
	else
		oc_wlatch(OC_W_SIGNAL_FAIL);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(oc_sched_exit, struct task_struct *p)
{
	struct oc_task *s = bpf_task_storage_get(&oc_tasks, p, 0, 0);

	if (s && s->counted) {
		s->counted = 0;
		oc_count(OC_C_EXITS);
		oc_gauge(OC_G_LIVE, -1);
		oc_btasks_add(s->binding, -1);
	}
	return 0;
}

// ------------------------------------------------------------ exec begin

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(oc_bprm_creds, struct linux_binprm *bprm, int prior)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct oc_task *s;
	struct oc_binding *b;
	struct oc_mark *m;
	__u64 cg;

	oc_wadd(OC_W_LSM_CREDS);
	s = oc_current();
	// E4: every watched exec, bound to this exec.
	if (oc_watched(task, s != 0)) {
		m = bpf_task_storage_get(&oc_marks, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (m) {
			m->exec_bprm = (__u64)bprm;
			m->exec_seq = oc_self_exec_id(task) + 1;
		} else {
			oc_wadd(OC_W_MARK_FAIL);
		}
	}
	if (prior)
		return prior;
	if (!s) {
		b = oc_bound_cgroup(&cg);
		if (!b)
			return 0;
		oc_count(OC_C_UNKNOWN_EXEC);
		oc_fault_event(cg, OC_FAULT_UNKNOWN_TASK, NULL, b->class != 1);
		if (b->class == 1 || OC_MUT(OC_MUT_R11_ALLOWS))
			return 0;
		return -OC_EPERM;
	}
	oc_count(OC_C_EXECS);
	s->exec_id++;
	if (!OC_MUT(OC_MUT_NO_RESET) || !s->p_active) {
		s->p_known_deny = 0;
		s->p_fault = 0;
		s->p_writes = 0;
		s->p_uncertain = 0;
		s->p_grants = 0;
		s->p_conflicts = 0;
		s->p_enforced_writes = 0;
		s->p_global_unknown = 0;
		for (int i = 0; i < 8; i++)
			s->p_witness[i] = 0;
	}
	s->p_active = 1;
	s->p_passes = 0;
	s->p_decided = 0;
	s->p_class = 0;
	s->p_gen = 0;
	s->p_target.length = 0;
	s->p_reason = OC_PR_NO_FILE;
	b = bpf_map_lookup_elem(&oc_bindings, &s->binding);
	if (!b) {
		s->p_fault = 1;
		oc_count(OC_C_FAULT_DENY);
		oc_fault_event(s->binding, OC_FAULT_NO_BINDING, s, 1);
		return -OC_EPERM;
	}
	// Mutant: a fault before classification is ignored (the exec is then
	// classified and decided as if nothing had happened).
	if (OC_TEST_SWITCH(b->fault_inject) && !OC_MUT(OC_MUT_FAULT_ALLOWS)) {
		s->p_fault = 1;
		oc_count(OC_C_FAULT_DENY);
		oc_fault_event(s->binding, OC_FAULT_INJECTED, s, 1);
		return -OC_EPERM;
	}
	s->p_gen = b->gen;
	{
		struct fm_global_token tok = { .slot = 0, .cookie = b->gen };
		fm_u32 policies = 0, writers = 0;
		int class = fe_execution_class(&tok, b->gen, &policies, &writers);
		const struct fe_policy *p;

		if (class != 1 && class != 2) {
			s->p_fault = 1;
			oc_count(OC_C_FAULT_DENY);
			oc_fault_event(s->binding, OC_FAULT_NO_GENERATION, s, 1);
			return -OC_EPERM;
		}
		s->p_class = class;
		s->p_policies = policies;
		for (__u32 i = 0; i < 8; i++) {
			s->p_uids[i] = 0;
			s->p_epochs[i] = 0;
			if (i >= policies)
				continue;
			p = FE_POLICY_LOOKUP(&tok, i);
			if (!p)
				continue;
			s->p_uids[i] = p->uid;
			s->p_epochs[i] = p->root_epoch;
		}
	}
	// R31: the anchor, from the seeded init's first exec, once. The init is
	// the task the binding names (b->init_tid, F8), not merely a task that
	// came in through an adopt entry marked init.
	if (s->is_init && b->init_tid && b->init_tid == (__u32)bpf_get_current_pid_tgid() &&
	    (OC_MUT(OC_MUT_ANCHOR_TID_ONLY) ||
	     BPF_CORE_READ(task, group_leader, start_boottime) / (1000000000ULL / 100) == b->init_start)) {
		struct oc_anchor a = {};
		int recapture = OC_MUT(OC_MUT_ANCHOR_RECAPTURE);
		__u32 itid = (__u32)bpf_get_current_pid_tgid();
		struct oc_init *ini = bpf_map_lookup_elem(&oc_inits, &itid);
		// Review C4: only the init's first exec since Bind captures
		// (a late bind, or an init that exec'd before the policy,
		// never anchors; the binding stays NotReady).
		int fresh = ini && ini->cgroup == s->binding && !ini->execs && !ini->closed;

		// Review N1: and the init has not started its workload: its
		// current (pre-exec) image is still the runtime's, from outside
		// its mount namespace. A late bind of a running workload never
		// anchors, whatever it did before Bind.
		if (fresh && !OC_MUT(OC_MUT_EXE_ANY_MOUNT) && !oc_exe_outside_ns(task)) {
			fresh = 0;
			oc_count(OC_C_INIT_IN_WORKLOAD);
		}

		if (!recapture && !fresh && !OC_MUT(OC_MUT_LATE_ANCHOR) &&
		    !bpf_map_lookup_elem(&oc_anchors, &s->binding)) {
			oc_count(OC_C_ANCHOR_REFUSED);
			if (ini)
				ini->closed = 1;
		} else if ((recapture || !bpf_map_lookup_elem(&oc_anchors, &s->binding)) &&
		    !oc_task_root(task, &a.root_ino, &a.root_mnt_id, &a.root_dev, &a.mntns)) {
			a.init_tid = (__u32)bpf_get_current_pid_tgid();
			a.captured_ns = bpf_ktime_get_ns();
			if (!bpf_map_update_elem(&oc_anchors, &s->binding, &a, recapture ? BPF_ANY : BPF_NOEXIST))
				oc_count(OC_C_ANCHOR_CAPTURED);
		}
	}
	// The exec's work area (F1). Classified already: a failure follows the
	// class at the first pass (no work area -> class fault there).
	if (!bpf_task_storage_get(&oc_works, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE))
		oc_count(OC_C_STORAGE_FAIL);
	return 0;
}

// ------------------------------------------------------------ decision

// E2 (R16): the ancestors' recorded exe facts, nearest first, read from each
// ancestor's task record through real_parent (no kfunc, no live exe read).
// The chain is complete at the edge of the workload (a parent with no record
// of this binding), at the binding's init (recorded as the last link) or at
// the idle task; a member ancestor whose exe facts are UNKNOWN makes the whole
// fact UNKNOWN; more than 16 keeps the known prefix, incomplete.
static __noinline void oc_ancestors(struct oc_task *s, struct fe_facts *f, struct task_struct *task)
{
	struct task_struct *t = task;
	__u32 count = 0;
	int complete = 0, failed = 0;

	f->ancestor_count = 0;
	f->ancestors_complete = 0;
	if (OC_MUT(OC_MUT_ANCESTOR_OFF)) {
		f->ancestors_complete = 1;
		return;
	}
	for (__u32 i = 0; i < 16; i++) {
		struct task_struct *p = t->real_parent;
		struct oc_task *ps;

		if (!p || p == t) {
			complete = 1;
			break;
		}
		ps = bpf_task_storage_get(&oc_tasks, p, 0, 0);
		if (!ps || ps->binding != s->binding) {
			complete = 1; // the workload's edge
			break;
		}
		if (!ps->exe_path.length || ps->exe_path.length > 255) {
			if (OC_MUT(OC_MUT_ANCESTOR_SKIP_UNKNOWN)) {
				complete = 1;
				break;
			}
			failed = 1;
			break;
		}
		__builtin_memcpy(&f->ancestors[i & 15], &ps->exe_path, sizeof(f->ancestors[0]));
		count = i + 1;
		if (ps->is_init) {
			complete = 1;
			break;
		}
		t = p;
	}
	if (failed) {
		count = 0;
		complete = 0;
	}
	f->ancestor_count = count;
	f->ancestors_complete = complete;
}

// Fill the facts of one pass (target, actor, uid, roles). Returns the path
// reason of the target fact.
// A static subprogram: its frame is not on the evaluator's call chain, which
// must fit the 512-byte combined stack.
static __noinline __u32 oc_collect(struct linux_binprm *bprm, struct oc_task *s, struct fe_facts *f,
				   struct task_struct *task)
{
	struct file *file = bprm->file;
	const struct oc_anchor *a;
	__u32 reason = OC_PR_KNOWN, seq;
	long n;

	f->actor_image = -1;
	f->target_image = -1;
	f->target_path.length = 0;
	f->actor_path.length = 0;
	f->fs_mask = 0;
	f->fs_known = 0;
	f->stdin_pipe = full_stdin_pipe(task);
	s->p_stdin = f->stdin_pipe;
	{
		struct full_fs_facts fs = full_file_filesystem(file);

		f->fs_mask = fs.mask & fs.known;
		f->fs_known = fs.known;
		s->p_fs_mask = f->fs_mask;
		s->p_fs_known = f->fs_known;
	}
	f->ancestor_count = 0;
	f->ancestors_complete = 0;
	f->argc = 0;
	f->argv_bytes = 0;
	f->argv_complete = 0;
	f->uid_known = 0;
	f->effective_uid = 0;
	f->role_count = 0;

	// R22: effective UID before the exec's own transition (current's creds).
	{
		unsigned int euid = 0;

		if (!BPF_CORE_READ_INTO(&euid, task, cred, euid.val)) {
			f->effective_uid = euid;
			f->uid_known = 1;
		}
	}
	// R15: the actor's recorded exe facts.
	__builtin_memcpy(&f->actor_path, &s->exe_path, sizeof(f->actor_path));
	if (f->actor_path.length > 255)
		f->actor_path.length = 0;
	oc_ancestors(s, f, task);
	// Committed roles, valid for the frozen generation's (uid, epoch).
	{
		__u32 count = 0;

		for (__u32 i = 0; i < 8; i++) {
			if (i >= s->p_policies)
				break;
			for (int j = 0; j < OC_ROWS; j++) {
				if (!s->rows[j].known || !s->rows[j].role || s->rows[j].uid != s->p_uids[i] ||
				    s->rows[j].epoch != s->p_epochs[i])
					continue;
				if (count < 8) {
					f->roles[count & 7].policy_uid = s->rows[j].uid;
					f->roles[count & 7].role = s->rows[j].role;
					count++;
				}
				break;
			}
		}
		f->role_count = count;
	}
	if (!file)
		return OC_PR_NO_FILE;
	a = bpf_map_lookup_elem(&oc_anchors, &s->binding);
	seq = oc_fs_seq(task);
	if (!OC_MUT(OC_MUT_NO_ANCHOR_CHECK) && !OC_MUT(OC_MUT_NO_ROOT_CHECK)) {
		if (!a)
			return OC_PR_NO_ANCHOR;
		if ((seq & 1) || oc_rooted(task, a) != 1)
			return OC_PR_ROOT_MISMATCH;
	}
	n = bpf_d_path(&bprm->file->f_path, (char *)f->target_path.bytes, sizeof(f->target_path.bytes));
	if (n == -OC_ENAMETOOLONG || n > 256)
		return OC_PR_TOO_LONG;
	if (n <= 1 || f->target_path.bytes[0] != '/')
		return OC_PR_D_PATH;
	if (!OC_MUT(OC_MUT_NO_ANCHOR_CHECK)) {
		if (!OC_MUT(OC_MUT_NO_REACH_CHECK)) {
			int force = 0;
#ifdef OC_TEST_BUILD
			{
				struct oc_binding *tb = bpf_map_lookup_elem(&oc_bindings, &s->binding);

				force = tb && (tb->test_flags & OC_TF_BRACKET_FAIL);
			}
#endif
			int r = oc_reachable(task, file, force);

			if (r == 0)
				return OC_PR_UNREACHABLE;
			if (r == 2)
				return OC_PR_INTERNAL;
			if (r != 1)
				return OC_PR_WALK_UNKNOWN;
		}
		if (!OC_MUT(OC_MUT_NO_DELETED_CHECK) && oc_unlinked(file) != 0)
			return OC_PR_DELETED;
		// Close the bracket after the last path read.
		if (!OC_MUT(OC_MUT_NO_ROOT_CHECK) &&
		    (oc_fs_seq(task) != seq || !a || oc_rooted(task, a) != 1))
			return OC_PR_ROOT_MISMATCH;
	}
	f->target_path.length = (n - 1) & 0xff;
	return reason;
}

static __always_inline void oc_reason_count(__u32 reason)
{
	switch (reason) {
	case OC_PR_KNOWN:
		return;
	case OC_PR_NO_ANCHOR:
		oc_count(OC_C_NO_ANCHOR);
		break;
	case OC_PR_ROOT_MISMATCH:
		oc_count(OC_C_ROOT_MISMATCH);
		break;
	case OC_PR_UNREACHABLE:
		oc_count(OC_C_UNREACHABLE);
		break;
	case OC_PR_INTERNAL:
		oc_count(OC_C_INTERNAL_MOUNT);
		break;
	case OC_PR_DELETED:
		oc_count(OC_C_DELETED);
		break;
	default:
		break;
	}
	oc_count(OC_C_PATH_UNKNOWN);
}

// Accumulate one pass's decision into the pending record (the product's
// se_exec_propose_locked, without the pool bookkeeping).
// Global (verified once): its many exit states would otherwise multiply into
// the rest of the pass (the 5.15 verifier ran out of budget).
__noinline int oc_propose(struct oc_task *s, const struct fe_decision *d, int error)
{
	if (!s || !d)
		return 0;
	__u32 n = s->p_policies > 8 ? 8 : s->p_policies;
	__u32 valid = (1U << n) - 1;
	__u32 writes = FE_ROLE_WRITES(d->audit_unknown);
	__u32 uncertain = FE_ROLE_UNCERTAIN(d->audit_unknown);

	if (error || (d->audit_unknown & ~FE_UNCERTAINTY_VALID_MASK) ||
	    ((writes | uncertain | (d->audit_unknown & 255U) | d->enforced_writes | d->role_conflicts) & ~valid) ||
	    ((d->audit_unknown & FE_AUDIT_UNCERTAIN_FALLBACK) && (!d->deny || d->mode != 1))) {
		s->p_fault = 1;
		s->p_uncertain |= valid;
		s->p_grants = 0;
		return 0;
	}
	if (d->deny && !(d->audit_unknown & FE_AUDIT_UNCERTAIN_FALLBACK)) {
		s->p_known_deny = 1;
		s->p_grants = 0;
		return 0;
	}
	s->p_writes |= writes;
	s->p_uncertain |= uncertain;
	s->p_enforced_writes |= d->enforced_writes;
	s->p_conflicts |= d->role_conflicts;
	if (d->audit_unknown & (FE_AUDIT_GLOBAL_SUPPRESS | FE_AUDIT_UNCERTAIN_FALLBACK))
		s->p_global_unknown = 1;
	for (__u32 i = 0; i < 8; i++) {
		__u64 role = d->known_role_witnesses[i] ? d->known_role_witnesses[i] : d->proposed_roles[i];

		if (i >= n)
			break;
		if (d->proposed_roles[i]) {
			s->p_writes |= 1U << i;
			s->p_grants |= 1U << i;
		}
		if (!role)
			continue;
		if (s->p_witness[i] && s->p_witness[i] != role) {
			s->p_conflicts |= 1U << i;
			s->p_uncertain |= 1U << i;
		} else {
			s->p_witness[i] = role;
		}
	}
	if (s->p_global_unknown)
		s->p_uncertain |= s->p_writes;
	s->p_grants &= ~s->p_uncertain;
	if (s->p_enforced_writes & s->p_conflicts) {
		s->p_fault = 1;
		s->p_uncertain |= valid;
		s->p_grants = 0;
	}
	return 0;
}

// The decision event of one pass (a static subprogram: off the evaluator's
// stack chain).
static __noinline void oc_decision_event(struct oc_task *s, struct oc_work *w, __u32 packed)
{
	__u32 pass = packed & 0xff, deny = (packed >> 8) & 1, blocked = (packed >> 9) & 1, mode = (packed >> 10) & 3,
	      reason = (packed >> 12) & 0xff;
	struct oc_event *e;

	e = oc_event_reserve(OC_EV_DECISION);
	if (e) {
		e->cgroup = s->binding;
		e->gen = s->p_gen;
		e->exec_id = s->exec_id;
		e->dev = s->p_dev;
		e->ino = s->p_ino;
		e->mode = mode;
		e->deny = deny;
		e->blocked = blocked;
		e->pass = pass;
		e->error = w->scratch.decision.error;
		e->audit_unknown = w->scratch.decision.audit_unknown;
		e->path_reason = reason;
		e->class = s->p_class;
		__builtin_memcpy(&e->path, &w->facts.target_path, sizeof(e->path));
		bpf_ringbuf_submit(e, 0);
	}
}

// Facts of one pass into the work area and the pending record. 1 when the
// frozen generation is no longer readable (R6 b), else 0.
static __noinline int oc_prepare(struct linux_binprm *bprm, struct oc_task *s, struct oc_work *w,
				 struct task_struct *task)
{
	struct inode *inode;
	__u32 reason = oc_collect(bprm, s, &w->facts, task);
	struct fm_global_token tok = { .slot = 0, .cookie = s->p_gen };

	oc_reason_count(reason);
	inode = BPF_CORE_READ(bprm, file, f_inode);
	s->p_ino = BPF_CORE_READ(inode, i_ino);
	s->p_dev = BPF_CORE_READ(inode, i_sb, s_dev);
	s->p_reason = reason;
	if (!OC_MUT(OC_MUT_ACTOR_FIRST_PASS) || s->p_passes == 1)
		__builtin_memcpy(&s->p_target, &w->facts.target_path, sizeof(s->p_target));
	s->p_uid = w->facts.effective_uid;
	// Owner stamp (F1): this task, this exec, this pass, a fresh nonce.
	s->p_nonce = bpf_get_prandom_u32();
	w->owner_exec = s->exec_id;
	w->owner_pass = s->p_passes - 1;
	w->owner_nonce = s->p_nonce;
	{
		struct oc_binding *b = bpf_map_lookup_elem(&oc_bindings, &s->binding);

#ifdef OC_TEST_BUILD
		if (b && b->test_clobber_stamp)
			w->owner_nonce = s->p_nonce ^ 1;
#else
		(void)b;
#endif
	}
	return FE_HEADER_LOOKUP(&tok) ? 0 : 1;
}

// 1 when the work area holds this task's current pass (or, pass ~0, its
// commit re-evaluation).
static __always_inline int oc_owner_ok(const struct oc_task *s, const struct oc_work *w, __u32 pass)
{
	return w->owner_exec == s->exec_id && w->owner_pass == pass && w->owner_nonce == s->p_nonce;
}

// Accumulate, count and report one evaluated pass. Returns 1 to block.
static __noinline int oc_finish(struct oc_task *s, struct oc_work *w, int ret)
{
	__u32 pass = s->p_passes - 1, reason = s->p_reason, deny, blocked, mode;
	int error = ret < 0;
	long verdict;

	oc_propose(s, &w->scratch.decision, error);
	verdict = fe_lsm_verdict(s->p_class, 0, error, &w->scratch.decision);
	if (error && OC_MUT(OC_MUT_EVAL_ERROR_ALLOWS))
		verdict = 0;
	s->p_decided++;
	deny = w->scratch.decision.deny || error;
	blocked = verdict != 0;
	if (OC_MUT(OC_MUT_AUDIT_BLOCKS) && deny)
		blocked = 1;
	mode = w->scratch.decision.mode;
	oc_count(OC_C_DECISIONS);
	if (!deny)
		oc_count(OC_C_ALLOW);
	else if (blocked)
		oc_count(OC_C_DENY);
	else
		oc_count(OC_C_WOULD_DENY);
	oc_decision_event(s, w, (pass & 0xff) | (deny << 8) | (blocked << 9) | ((mode & 3) << 10) | ((reason & 0xff) << 12));
	return blocked ? 1 : 0;
}

static __noinline int oc_stage_fault_s(struct oc_task *s);

// A global function: verified once, not once per state that reaches it from
// the end of a rule window (the 5.15 verifier ran out of budget otherwise).
__noinline int oc_finish_current(int ret)
{
	struct oc_task *s = bpf_task_storage_get(&oc_tasks, bpf_get_current_task_btf(), 0, 0);
	struct oc_work *w = oc_work_get();

	if (!s)
		return 1; // vanished mid-pass: fail closed
	if (!w || !oc_owner_ok(s, w, s->p_passes - 1))
		return oc_stage_fault_s(s);
	return oc_finish(s, w, ret);
}

// A rule window that cannot run (empty stage slot, tail call refused, window
// cap reached, foreign owner stamp): the pass is never decided. It is a fault
// after classification (F5): Strict denies, Audit allows and reports.
static __noinline int oc_stage_fault_s(struct oc_task *s)
{
	s->p_fault = 1;
	oc_fault_event(s->binding, OC_FAULT_STAGE, s, s->p_class != 1);
	if (s->p_class == 1 || OC_MUT(OC_MUT_STAGE_FAULT_ALLOWS)) {
		oc_count(OC_C_FAULT_ALLOW);
		return 0;
	}
	oc_count(OC_C_FAULT_DENY);
	return 1;
}

// A fault after classification follows the frozen class. Returns 1 to block.
static __noinline int oc_class_fault(struct oc_task *s, __u32 fault)
{
	s->p_fault = 1;
	oc_fault_event(s->binding, fault, s, s->p_class != 1);
	if (s->p_class == 1) {
		oc_count(OC_C_FAULT_ALLOW);
		return 0;
	}
	oc_count(OC_C_FAULT_DENY);
	return 1;
}

#ifdef OC_STAGED
// Global: verified once.
__noinline int oc_stage_fault(void)
{
	struct oc_task *s = bpf_task_storage_get(&oc_tasks, bpf_get_current_task_btf(), 0, 0);

	if (!s)
		return 1;
	return oc_stage_fault_s(s);
}
#endif

SEC("lsm/bprm_check_security")
int BPF_PROG(oc_bprm_check, struct linux_binprm *bprm, int prior)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct oc_task *s;
	struct oc_work *w;
	__u32 pass;
	int blocked;

	oc_wadd(OC_W_LSM_CHECK);
	if (prior)
		return prior;
	s = bpf_task_storage_get(&oc_tasks, task, 0, 0);
	if (!s) {
		__u64 cg;
		struct oc_binding *b = oc_bound_cgroup(&cg);

		// Untracked: decided at exec begin (R11). An audit-only binding
		// let it through; nothing to evaluate it with.
		if (!b || b->class == 1 || OC_MUT(OC_MUT_R11_ALLOWS))
			return 0;
		return -OC_EPERM;
	}
	if (!s->p_active) {
		// No exec begin for this exec: before classification.
		oc_count(OC_C_FAULT_DENY);
		oc_fault_event(s->binding, OC_FAULT_NO_PENDING, s, 1);
		return -OC_EPERM;
	}
	pass = s->p_passes++;
	// F9: no fact of an earlier pass survives into this one.
	if (!OC_MUT(OC_MUT_ACTOR_FIRST_PASS) || pass == 0)
		s->p_target.length = 0;
	if (OC_MUT(OC_MUT_NO_FREEZE)) {
		struct oc_binding *nb = bpf_map_lookup_elem(&oc_bindings, &s->binding);

		if (nb)
			s->p_gen = nb->gen;
	}
	s->p_reason = OC_PR_NO_FILE;
	s->p_dev = 0;
	s->p_ino = 0;
	if (OC_MUT(OC_MUT_SKIP_INTERP_PASS) && pass > 0)
		return 0;
	w = oc_work_get();
	if (!w)
		blocked = oc_class_fault(s, OC_FAULT_STORAGE);
	else if (oc_prepare(bprm, s, w, task))
		blocked = OC_MUT(OC_MUT_RETIRED_ALLOWS) ? 0 : oc_class_fault(s, OC_FAULT_NO_GENERATION);
	else {
		w->tok.slot = 0;
		w->tok.reserved = 0;
		w->tok.cookie = s->p_gen;
		// Nothing of this frame stays live across the evaluator: the
		// finish step looks the record and the work area up again.
#ifdef OC_STAGED
		if (oc_stage_begin(w))
			blocked = oc_finish_current(-1);
		else {
			w->stage_calls = 0;
			bpf_tail_call(ctx, &oc_check_stages, 0);
			// Reached only if the tail call failed.
			blocked = oc_stage_fault();
		}
#else
		blocked = oc_finish_current(OC_EVALUATE(w));
#endif
	}
	// Review R4: a blocked exec fails; its work area is not kept until the
	// task's next exec.
	if (blocked && !OC_MUT(OC_MUT_KEEP_BLOCKED_WORK))
		bpf_task_storage_delete(&oc_works, task);
	// Two literal returns: verifiers before 6.1x reject "r0 = -r0" as an
	// unbounded LSM return value.
	barrier_var(blocked);
	if (blocked)
		return -OC_EPERM;
	return 0;
}

// ------------------------------------------------------------ commit

// Compromise-8 alternative: the final pass's recorded facts, for a
// re-evaluation under the current generation, with the task's committed
// roles that are valid for that generation's (uid, epoch) (F2). Called
// before the roles are made UNKNOWN. Returns the generation's class, or 0
// when it cannot be classified (an evaluation error). Global: verified once.
__noinline __u32 oc_reeval_prepare(struct oc_task *s, struct oc_work *w, __u64 gen)
{
	struct fm_global_token tok = { .slot = 0, .cookie = gen };
	fm_u32 policies = 0, writers = 0;
	struct fe_facts *f;
	__u32 count = 0;
	int class;

	if (!s || !w)
		return 0;
	f = &w->facts;
	class = fe_execution_class(&tok, gen, &policies, &writers);
	if (class != 1 && class != 2)
		return 0;
	f->actor_image = -1;
	f->target_image = -1;
	f->fs_mask = s->p_fs_mask; // the final pass's
	f->fs_known = s->p_fs_known;
	f->stdin_pipe = s->p_stdin; // the final pass's
	f->ancestor_count = 0;
	f->ancestors_complete = 0;
	f->argc = 0;
	f->argv_bytes = 0;
	f->argv_complete = 0;
	f->effective_uid = s->p_uid;
	f->uid_known = 1;
	for (__u32 i = 0; i < 8; i++) {
		const struct fe_policy *p;

		if (i >= policies)
			break;
		p = FE_POLICY_LOOKUP(&tok, i);
		if (!p)
			continue;
		for (int j = 0; j < OC_ROWS; j++) {
			if (!s->rows[j].known || !s->rows[j].role || s->rows[j].uid != p->uid ||
			    s->rows[j].epoch != p->root_epoch)
				continue;
			if (count < 8) {
				f->roles[count & 7].policy_uid = s->rows[j].uid;
				f->roles[count & 7].role = s->rows[j].role;
				count++;
			}
			break;
		}
	}
	f->role_count = OC_MUT(OC_MUT_REEVAL_NO_ROLES) ? 0 : count;
	__builtin_memcpy(&f->target_path, &s->p_target, sizeof(f->target_path));
	__builtin_memcpy(&f->actor_path, &s->exe_path, sizeof(f->actor_path));
	if (f->target_path.length > 255)
		f->target_path.length = 0;
	if (f->actor_path.length > 255)
		f->actor_path.length = 0;
	s->p_nonce = bpf_get_prandom_u32();
	w->owner_exec = s->exec_id;
	w->owner_pass = ~0U;
	w->owner_nonce = s->p_nonce;
	return class;
}

// The re-evaluation's outcome (F2): the real verdict of N+1's decision under
// N+1's class. Kill iff that verdict blocks (Strict: SIGKILL, past the point
// of no return); a deny that would not block (audit-mode, or an audit-only
// class) is reported. An evaluation error is a deny under the class. Global.
__noinline __u32 oc_reeval_apply(struct oc_work *w, int ret)
{
	long verdict;
	int deny;

	if (!w)
		return 0;
	verdict = fe_lsm_verdict(w->c_reclass, 0, ret < 0, &w->scratch.decision);
	deny = ret < 0 || w->scratch.decision.deny;
	if (verdict != 0 && !OC_MUT(OC_MUT_REEVAL_NO_KILL)) {
		// Review C5: KILLED only if the signal was queued; a refused one
		// latches the witness (the receipt is already written, so the
		// guard would not catch the straddler).
		long sig = bpf_send_signal(OC_SIGKILL);

		if (OC_TEST_SWITCH(w->c_test_kill_fail))
			sig = -1;
		if (sig == 0 || OC_MUT(OC_MUT_REEVAL_KILL_UNCHECKED)) {
			oc_count(OC_C_KILLED);
			return OC_CF_REEVAL_DENY | OC_CF_KILLED;
		}
		oc_wlatch(OC_W_SIGNAL_FAIL);
		return OC_CF_REEVAL_DENY;
	}
	if (deny) {
		oc_count(OC_C_REEVAL_DENY_REPORTED);
		return OC_CF_REEVAL_DENY;
	}
	return 0;
}

// Apply a successful exec's proposal: uncertain policies become UNKNOWN,
// granted ones take the proposed role. A grant for a (uid, epoch) the task
// has no row for allocates one, replacing a row of the same uid's older epoch
// first (F3: a role policy published after the task was adopted). Global.
// The row for (uid, epoch): an exact match, else the uid's row of another
// epoch, else an empty row; -1 when there is no room. Global: verified once.
__noinline int oc_row_for(struct oc_task *s, __u64 uid, __u64 epoch)
{
	if (!s)
		return -1;
	for (int j = 0; j < OC_ROWS; j++)
		if (s->rows[j].uid == uid && s->rows[j].epoch == epoch)
			return j;
	for (int j = 0; j < OC_ROWS; j++)
		if (s->rows[j].uid == uid)
			return j;
	for (int j = 0; j < OC_ROWS; j++)
		if (!s->rows[j].uid)
			return j;
	// Review R1: reclaim a row whose policy is not in the frozen generation.
	if (OC_MUT(OC_MUT_SEED_ALL_POLICIES))
		return -1;
	for (int j = 0; j < OC_ROWS; j++) {
		int live = 0;

		for (__u32 i = 0; i < 8; i++)
			if (i < s->p_policies && s->p_uids[i] == s->rows[j].uid)
				live = 1;
		if (!live)
			return j;
	}
	return -1;
}

__noinline __u32 oc_commit_roles(struct oc_task *s)
{
	__u32 n, uncertain, grants, flags = 0;

	if (!s)
		return 0;
	n = s->p_policies > 8 ? 8 : s->p_policies;
	uncertain = OC_MUT(OC_MUT_NO_UNCERTAIN) ? 0 : s->p_uncertain;
	grants = s->p_grants;
	for (__u32 i = 0; i < 8; i++) {
		__u32 slot;

		if (i >= n)
			break;
		if (!((uncertain | grants) & (1U << i)) || !s->p_uids[i])
			continue;
		slot = oc_row_for(s, s->p_uids[i], s->p_epochs[i]);
		if ((__u32)slot >= OC_ROWS)
			continue; // no room (-1): the role stays absent, i.e. UNKNOWN
		slot &= OC_ROWS - 1;
		s->rows[slot].uid = s->p_uids[i];
		s->rows[slot].epoch = s->p_epochs[i];
		if (uncertain & (1U << i)) {
			s->rows[slot].known = 0;
			flags |= OC_CF_UNCERTAIN;
		} else if (s->p_witness[i]) {
			s->rows[slot].role = s->p_witness[i];
			s->rows[slot].known = 1;
		} else {
			s->rows[slot].known = 0;
		}
	}
	return flags;
}

// Record the final pass's facts as the exe facts and emit the commit event.
// Global (verified once); s is a task-storage value.
__noinline int oc_commit_finish(struct oc_task *s, __u32 flags, __u32 reclass)
{
	struct oc_event *e;

	if (!s)
		return 0;
	__builtin_memcpy(&s->exe_path, &s->p_target, sizeof(s->exe_path));
	e = oc_event_reserve(OC_EV_COMMIT);
	if (!e)
		return 0;
	e->cgroup = s->binding;
	e->gen = s->p_gen;
	e->exec_id = s->exec_id;
	e->dev = s->p_dev;
	e->ino = s->p_ino;
	e->pass = s->p_passes;
	e->outcome = flags;
	e->class = reclass ? reclass : s->p_class;
	e->path_reason = s->p_reason;
	for (int i = 0; i < OC_ROWS; i++) {
		e->roles[i] = s->rows[i].role;
		if (s->rows[i].known)
			e->known_mask |= 1U << i;
	}
	__builtin_memcpy(&e->path, &s->p_target, sizeof(e->path));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("lsm/bprm_committed_creds")
int BPF_PROG(oc_bprm_committed, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct oc_task *s = bpf_task_storage_get(&oc_tasks, task, 0, 0);
	struct oc_binding *b;
	__u32 flags = 0, reclass = 0;
	__u64 cur = 0;

	oc_wadd(OC_W_LSM_COMMIT);
	// E4-1: an exec with no pass (bprm_check never ran: every exec runs
	// it before any binary handler), or a pass that neither reached
	// oc_finish nor faulted, was not decided by the check hook (detached,
	// silenced): latch.
	if (s && s->p_active && (!s->p_passes || s->p_passes != s->p_decided) && !s->p_fault)
		oc_wlatch(OC_W_UNDECIDED);
	if (!s || !s->p_active)
		return 0;
	s->p_active = 0;
	oc_count(OC_C_COMMITS);
	{
		// E4: the receipt of a DECIDED exec (every pass reached
		// oc_finish: review E4-1), bound to this exec.
		struct oc_mark *m = bpf_task_storage_get(&oc_marks, task, 0, 0);

		if (m && ((s->p_passes && s->p_decided == s->p_passes) || OC_MUT(OC_MUT_RECEIPT_UNDECIDED))) {
			m->receipt_bprm = (__u64)bprm;
			m->receipt_seq = oc_self_exec_id(task);
		}
	}
	b = bpf_map_lookup_elem(&oc_bindings, &s->binding);
	if (b)
		cur = b->gen;
	if (!OC_MUT(OC_MUT_NO_REVALIDATE) && (!b || cur != s->p_gen)) {
		// R6 c: never evaluated under the current generation. Every
		// role-bearing policy of the binding becomes UNKNOWN for this
		// task, whatever the deny flag says. The re-evaluation (if on)
		// is prepared first: it sees the roles valid for N+1 (F2).
		struct oc_work *w = oc_reeval && b && cur ? oc_work_get() : 0;

		flags |= OC_CF_GEN_MISMATCH;
		oc_count(OC_C_GEN_MISMATCH);
		if (w) {
			reclass = oc_reeval_prepare(s, w, cur);
			w->c_reclass = reclass ? reclass : b->class; // never an assumed class
			w->c_test_kill_fail = OC_TEST_SWITCH(b->test_flags & OC_TF_KILL_FAIL);
		}
		for (int i = 0; i < OC_ROWS; i++)
			if (!OC_MUT(OC_MUT_ONLY_PROPOSED_UNKNOWN) || (s->p_writes & (1U << (i & 7))))
				s->rows[i].known = 0;
		if (w) {
			int ret = -1;

			if (reclass) {
				w->tok.slot = 0;
				w->tok.reserved = 0;
				w->tok.cookie = cur;
#ifdef OC_STAGED
				ret = oc_stage_begin(w);
				if (!ret) {
					w->c_flags = flags;
					w->stage_calls = 0;
					bpf_tail_call(ctx, &oc_commit_stages, 0);
					ret = -1; // the tail call failed
				}
#else
				ret = OC_EVALUATE(w);
#endif
			}
			flags |= oc_reeval_apply(w, ret);
			reclass = w->c_reclass;
		}
	} else if (s->p_fault) {
		flags |= OC_CF_FAULT;
		for (int i = 0; i < OC_ROWS; i++)
			s->rows[i].known = 0;
	} else if (s->p_known_deny) {
		flags |= OC_CF_KNOWN_DENY;
	} else {
		flags |= oc_commit_roles(s);
		if (flags & OC_CF_UNCERTAIN)
			oc_count(OC_C_UNCERTAIN_COMMIT);
	}
	oc_commit_finish(s, flags, reclass);
	bpf_task_storage_delete(&oc_works, task);
	return 0;
}

#ifdef OC_STAGED
// The rule windows of one pass (oc_check_stages[0]); re-enters itself while
// rules remain, then finishes the decision. Each entry re-checks the owner.
SEC("lsm/bprm_check_security")
int BPF_PROG(oc_check_stage, struct linux_binprm *bprm, int prior)
{
	struct oc_task *s = bpf_task_storage_get(&oc_tasks, bpf_get_current_task_btf(), 0, 0);
	struct oc_work *w = oc_work_get();
	int r, blocked;

	if (!s || !w || !oc_owner_ok(s, w, s->p_passes - 1) || ++w->stage_calls > oc_stage_cap) {
		blocked = oc_stage_fault();
		goto out;
	}
	r = oc_stage_run(w);
#ifdef OC_TEST_BUILD
	{
		// Review E3-2: the generation's blobs vanish after the first
		// window, deterministically (a retire between windows).
		struct oc_binding *tb = bpf_map_lookup_elem(&oc_bindings, &s->binding);

		if (r == 1 && tb && (tb->test_flags & OC_TF_RETIRE_AFTER_WINDOW))
			w->tok.cookie = ~0ULL;
	}
#endif
	if (r == 1) {
		bpf_tail_call(ctx, &oc_check_stages, 0);
		// Reached only if the re-entry failed (tail-call limit).
		blocked = oc_stage_fault();
		goto out;
	}
	if (r == 0)
		r = oc_stage_finish(w);
	blocked = oc_finish_current(r);
out:
	if (blocked && !OC_MUT(OC_MUT_KEEP_BLOCKED_WORK))
		bpf_task_storage_delete(&oc_works, bpf_get_current_task_btf());
	barrier_var(blocked);
	if (blocked)
		return -OC_EPERM;
	return 0;
}

// The re-evaluation windows of a commit (oc_commit_stages[0]).
SEC("lsm/bprm_committed_creds")
int BPF_PROG(oc_commit_stage, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct oc_task *s = bpf_task_storage_get(&oc_tasks, task, 0, 0);
	struct oc_work *w = oc_work_get();
	__u32 flags;
	int r;

	if (!s || !w)
		return 0;
	if (!oc_owner_ok(s, w, ~0U) || ++w->stage_calls > oc_stage_cap)
		r = -1; // foreign stamp or window cap: the re-evaluation errs
	else
		r = oc_stage_run(w);
	if (r == 1) {
		bpf_tail_call(ctx, &oc_commit_stages, 0);
		r = -1;
	}
	if (r == 0)
		r = oc_stage_finish(w);
	flags = w->c_flags | oc_reeval_apply(w, r);
	oc_commit_finish(s, flags, w->c_reclass);
	bpf_task_storage_delete(&oc_works, task);
	return 0;
}
#endif

char LICENSE[] SEC("license") = "GPL";
