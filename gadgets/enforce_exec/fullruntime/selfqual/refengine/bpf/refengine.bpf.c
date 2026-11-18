// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
//
// Reference exec-enforcement engine for the D4 self-qualification prototype.
//
// This is NOT the shared product engine. It is the smallest engine that
// implements the enforce_exec fail-closed contract on stable kernel ABI only
// (BPF LSM hooks + BTF tracepoints + CO-RE), so that the self-qualification
// runner has something to admit on stock kernels, where the product engine's
// pinned objects and failure frames do not exist.
//
// Contract:
//   - Strict deny -> EPERM.
//   - Audit never blocks once classified; reports would_deny.
//   - A fault before classification denies in every mode.
//   - An untracked task in a bound cgroup is unknown: denied in every mode.
//   - One exec reads one generation (frozen at its first binfmt pass).
//
// Hooks: lsm/task_alloc, lsm/bprm_check_security, tp_btf/sched_process_fork,
// tp_btf/sched_process_exec, tp_btf/sched_process_exit, tp_btf/sys_exit.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define RQ_EPERM 1
#define RQ_CLONE_THREAD 0x00010000

enum rq_mode { RQ_MODE_AUDIT = 1, RQ_MODE_STRICT = 2 };

enum rq_counter {
	RQ_C_EXECS = 0, // execs that reached the decision hook (first pass)
	RQ_C_DECISIONS, // classified decisions (every pass)
	RQ_C_ALLOW,
	RQ_C_DENY, // strict deny -> EPERM
	RQ_C_WOULD_DENY, // audit deny, not blocked
	RQ_C_FAULT_DENY, // fault before classification -> EPERM in every mode
	RQ_C_UNKNOWN_EXEC, // untracked task in a bound cgroup tried to exec
	RQ_C_UNKNOWN_FORK, // untracked task in a bound cgroup tried to fork
	RQ_C_BIRTHS, // tracked children that started running
	RQ_C_ADOPTED,
	RQ_C_EXITS, // tracked tasks that exited
	RQ_C_EXEC_OK, // pending record settled by a completed exec
	RQ_C_EXEC_FAIL, // pending record settled by a failed execve return
	RQ_C_EXEC_ABORT, // pending record settled by task exit mid-exec
	RQ_C_STALE_PENDING, // a new exec found a pending record of another exec
	RQ_C_EVENT_LOST,
	RQ_C_STORAGE_FAIL,
	RQ_C_MAX,
};

enum rq_gauge {
	RQ_G_PENDING = 0, // execs between decision and outcome ("gate")
	RQ_G_LIVE, // tracked live tasks
	RQ_G_MAX,
};

enum rq_event_kind {
	RQ_EV_DECISION = 1,
	RQ_EV_FAULT = 2,
	RQ_EV_OUTCOME = 3,
};

enum rq_fault {
	RQ_FAULT_NONE = 0,
	RQ_FAULT_UNKNOWN_TASK = 1,
	RQ_FAULT_INJECTED = 2,
	RQ_FAULT_NO_BINDING = 3,
	RQ_FAULT_NO_GENERATION = 4,
	RQ_FAULT_STORAGE = 5,
};

enum rq_outcome { RQ_OUT_OK = 1, RQ_OUT_FAIL = 2, RQ_OUT_ABORT = 3 };

// Deliberate bugs, selected at load time by the negative-control tests only.
// 0 is the real engine.
enum rq_mutant {
	RQ_MUT_NONE = 0,
	RQ_MUT_AUDIT_BLOCKS = 1,
	RQ_MUT_FAULT_ALLOWS = 2,
	RQ_MUT_UNKNOWN_ALLOWED = 3,
	RQ_MUT_SKIP_INTERP_PASS = 4,
	RQ_MUT_NO_FREEZE = 5,
	RQ_MUT_CGROUP_ESCAPE = 6,
	RQ_MUT_FDPATH_BYPASS = 7,
	RQ_MUT_THREAD_BYPASS = 8,
	RQ_MUT_NO_FAIL_RECONCILE = 9,
	RQ_MUT_DENY_NO_EVENT = 10,
	RQ_MUT_VFORK_UNTRACKED_ALLOWED = 11,
	RQ_MUT_RARE_BYPASS = 12, // allows 1 denied exec in rq_rare_n
	RQ_MUT_NO_ABORT_RECONCILE = 13,
};

const volatile __u32 rq_mutant = 0;
const volatile __u32 rq_rare_n = 1024;

struct rq_binding {
	__u64 gen;
	__u32 fault_inject;
	__u32 pad;
};

struct rq_gen_key {
	__u64 cgroup;
	__u64 gen;
};

struct rq_gen_meta {
	__u32 mode;
	__u32 default_deny;
};

struct rq_rule_key {
	__u64 cgroup;
	__u64 gen;
	__u64 dev;
	__u64 ino;
};

struct rq_rule {
	__u32 allow;
};

struct rq_task {
	__u64 cgroup; // the binding this task's lineage belongs to
	__u64 exec_gen;
	__u64 exec_id;
	__u64 bprm;
	__u32 pending;
	__u32 passes;
	__u32 counted; // RQ_G_LIVE holds this task
	__u32 pad;
};

struct rq_event {
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
	__u32 outcome;
	__s32 ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct rq_binding);
} rq_bindings SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct rq_gen_key);
	__type(value, struct rq_gen_meta);
} rq_gens SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct rq_rule_key);
	__type(value, struct rq_rule);
} rq_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} rq_adopt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct rq_task);
} rq_tasks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RQ_C_MAX);
	__type(key, __u32);
	__type(value, __u64);
} rq_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RQ_G_MAX);
	__type(key, __u32);
	__type(value, __s64);
} rq_gauges SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} rq_events SEC(".maps");

static __always_inline void rq_count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&rq_counters, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline void rq_gauge(__u32 idx, __s64 delta)
{
	__s64 *v = bpf_map_lookup_elem(&rq_gauges, &idx);

	if (v)
		__sync_fetch_and_add(v, delta);
}

static __always_inline struct rq_event *rq_event_reserve(__u32 kind)
{
	struct rq_event *e = bpf_ringbuf_reserve(&rq_events, sizeof(*e), 0);
	__u64 pt;

	if (!e) {
		rq_count(RQ_C_EVENT_LOST);
		return NULL;
	}
	__builtin_memset(e, 0, sizeof(*e));
	pt = bpf_get_current_pid_tgid();
	e->kind = kind;
	e->pid = pt >> 32;
	e->tid = (__u32)pt;
	return e;
}

static __always_inline void rq_fault_event(__u64 cgroup, __u32 fault, struct rq_task *s)
{
	struct rq_event *e = rq_event_reserve(RQ_EV_FAULT);

	if (!e)
		return;
	e->cgroup = cgroup;
	e->fault = fault;
	e->deny = 1;
	e->blocked = 1;
	if (s) {
		e->exec_id = s->exec_id;
		e->gen = s->exec_gen;
		e->pass = s->passes;
	}
	bpf_ringbuf_submit(e, 0);
}

static __always_inline void rq_outcome_event(struct rq_task *s, __u32 outcome, long ret)
{
	struct rq_event *e = rq_event_reserve(RQ_EV_OUTCOME);

	if (!e)
		return;
	e->cgroup = s->cgroup;
	e->gen = s->exec_gen;
	e->exec_id = s->exec_id;
	e->pass = s->passes;
	e->outcome = outcome;
	e->ret = (__s32)ret;
	bpf_ringbuf_submit(e, 0);
}

// rq_current returns the current task's tracking state, adopting it first if
// the agent asked for it. Adoption is honoured only while the task really is
// in the bound cgroup the agent named.
static __always_inline struct rq_task *rq_current(void)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct rq_task *s;
	__u64 *want, cg;
	__u32 tid;

	s = bpf_task_storage_get(&rq_tasks, t, 0, 0);
	if (s)
		return s;
	tid = (__u32)bpf_get_current_pid_tgid();
	want = bpf_map_lookup_elem(&rq_adopt, &tid);
	if (!want)
		return NULL;
	cg = bpf_get_current_cgroup_id();
	if (*want != cg || !bpf_map_lookup_elem(&rq_bindings, &cg))
		return NULL;
	s = bpf_task_storage_get(&rq_tasks, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!s) {
		rq_count(RQ_C_STORAGE_FAIL);
		return NULL;
	}
	s->cgroup = cg;
	s->counted = 1;
	bpf_map_delete_elem(&rq_adopt, &tid);
	rq_count(RQ_C_ADOPTED);
	rq_gauge(RQ_G_LIVE, 1);
	return s;
}

static __always_inline void rq_settle(struct rq_task *s, __u32 counter, __u32 outcome, long ret)
{
	if (!s->pending)
		return;
	rq_outcome_event(s, outcome, ret);
	s->pending = 0;
	s->bprm = 0;
	rq_gauge(RQ_G_PENDING, -1);
	rq_count(counter);
}

SEC("lsm/task_alloc")
int BPF_PROG(rq_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
	struct rq_task *ps = rq_current(), *cs;
	__u64 cg;

	if (!ps) {
		cg = bpf_get_current_cgroup_id();
		if (!bpf_map_lookup_elem(&rq_bindings, &cg))
			return 0;
		if (rq_mutant == RQ_MUT_UNKNOWN_ALLOWED)
			return 0;
		// Unknown task in a bound cgroup: no lineage, so nothing it creates
		// may run. Threads of an unknown task are refused as well.
		rq_count(RQ_C_UNKNOWN_FORK);
		rq_fault_event(cg, RQ_FAULT_UNKNOWN_TASK, NULL);
		return -RQ_EPERM;
	}
	if (rq_mutant == RQ_MUT_VFORK_UNTRACKED_ALLOWED && (clone_flags & 0x00004000 /* CLONE_VFORK */))
		return 0;
	cs = bpf_task_storage_get(&rq_tasks, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cs) {
		rq_count(RQ_C_STORAGE_FAIL);
		rq_fault_event(ps->cgroup, RQ_FAULT_STORAGE, NULL);
		return -RQ_EPERM;
	}
	cs->cgroup = ps->cgroup;
	cs->exec_gen = 0;
	cs->exec_id = 0;
	cs->bprm = 0;
	cs->pending = 0;
	cs->passes = 0;
	cs->counted = 0;
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(rq_sched_fork, struct task_struct *parent, struct task_struct *child)
{
	struct rq_task *cs = bpf_task_storage_get(&rq_tasks, child, 0, 0);

	if (!cs || cs->counted)
		return 0;
	cs->counted = 1;
	rq_count(RQ_C_BIRTHS);
	rq_gauge(RQ_G_LIVE, 1);
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(rq_bprm_check, struct linux_binprm *bprm)
{
	struct rq_task *s = rq_current();
	struct rq_gen_key gk = {};
	struct rq_rule_key rk = {};
	struct rq_binding *b;
	struct rq_gen_meta *meta;
	struct rq_rule *rule;
	struct rq_event *e;
	struct inode *inode;
	__u64 cg, gen;
	__u32 pass, deny, mode, blocked;

	cg = bpf_get_current_cgroup_id();
	if (!s) {
		if (!bpf_map_lookup_elem(&rq_bindings, &cg))
			return 0; // not ours
		if (rq_mutant == RQ_MUT_UNKNOWN_ALLOWED || rq_mutant == RQ_MUT_VFORK_UNTRACKED_ALLOWED)
			return 0;
		rq_count(RQ_C_UNKNOWN_EXEC);
		rq_fault_event(cg, RQ_FAULT_UNKNOWN_TASK, NULL);
		return -RQ_EPERM;
	}
	if (rq_mutant == RQ_MUT_CGROUP_ESCAPE && !bpf_map_lookup_elem(&rq_bindings, &cg))
		return 0;

	if (!s->pending || s->bprm != (__u64)bprm) {
		if (s->pending) {
			// The previous exec's outcome was never observed.
			rq_count(RQ_C_STALE_PENDING);
			rq_gauge(RQ_G_PENDING, -1);
		}
		b = bpf_map_lookup_elem(&rq_bindings, &s->cgroup);
		s->pending = 1;
		s->bprm = (__u64)bprm;
		s->exec_id++;
		s->passes = 0;
		s->exec_gen = b ? b->gen : 0;
		rq_gauge(RQ_G_PENDING, 1);
		rq_count(RQ_C_EXECS);
	}
	pass = s->passes++;

	b = bpf_map_lookup_elem(&rq_bindings, &s->cgroup);
	if (!b) {
		rq_count(RQ_C_FAULT_DENY);
		rq_fault_event(s->cgroup, RQ_FAULT_NO_BINDING, s);
		return -RQ_EPERM;
	}
	if (b->fault_inject) {
		rq_count(RQ_C_FAULT_DENY);
		rq_fault_event(s->cgroup, RQ_FAULT_INJECTED, s);
		if (rq_mutant == RQ_MUT_FAULT_ALLOWS)
			return 0;
		return -RQ_EPERM;
	}
	gen = rq_mutant == RQ_MUT_NO_FREEZE ? b->gen : s->exec_gen;
	gk.cgroup = s->cgroup;
	gk.gen = gen;
	meta = bpf_map_lookup_elem(&rq_gens, &gk);
	if (!meta) {
		rq_count(RQ_C_FAULT_DENY);
		rq_fault_event(s->cgroup, RQ_FAULT_NO_GENERATION, s);
		return -RQ_EPERM;
	}
	mode = meta->mode;

	if (rq_mutant == RQ_MUT_SKIP_INTERP_PASS && pass > 0)
		return 0;
	if (rq_mutant == RQ_MUT_FDPATH_BYPASS && BPF_CORE_READ(bprm, fdpath))
		return 0;
	if (rq_mutant == RQ_MUT_THREAD_BYPASS) {
		__u64 pt = bpf_get_current_pid_tgid();

		if ((__u32)pt != (__u32)(pt >> 32))
			return 0;
	}

	inode = BPF_CORE_READ(bprm, file, f_inode);
	rk.cgroup = s->cgroup;
	rk.gen = gen;
	rk.ino = BPF_CORE_READ(inode, i_ino);
	rk.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	rule = bpf_map_lookup_elem(&rq_rules, &rk);
	deny = rule ? !rule->allow : meta->default_deny;

	if (deny && rq_mutant == RQ_MUT_RARE_BYPASS && rq_rare_n && bpf_get_prandom_u32() % rq_rare_n == 0)
		deny = 0;

	blocked = deny && (mode != RQ_MODE_AUDIT || rq_mutant == RQ_MUT_AUDIT_BLOCKS);

	rq_count(RQ_C_DECISIONS);
	if (!deny)
		rq_count(RQ_C_ALLOW);
	else if (mode == RQ_MODE_AUDIT)
		rq_count(RQ_C_WOULD_DENY);
	else
		rq_count(RQ_C_DENY);

	if (!(rq_mutant == RQ_MUT_DENY_NO_EVENT && deny)) {
		e = rq_event_reserve(RQ_EV_DECISION);
		if (e) {
			e->cgroup = s->cgroup;
			e->gen = gen;
			e->exec_id = s->exec_id;
			e->dev = rk.dev;
			e->ino = rk.ino;
			e->mode = mode;
			e->deny = deny;
			e->blocked = blocked;
			e->pass = pass;
			bpf_ringbuf_submit(e, 0);
		}
	}
	// Two literal returns: verifiers before 6.1x reject "r0 = -r0" as an
	// unbounded LSM return value.
	barrier_var(blocked);
	if (blocked)
		return -RQ_EPERM;
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(rq_sched_exec, struct task_struct *p)
{
	struct rq_task *s = bpf_task_storage_get(&rq_tasks, p, 0, 0);

	if (s)
		rq_settle(s, RQ_C_EXEC_OK, RQ_OUT_OK, 0);
	return 0;
}

// A failed execve returns to user space through the syscall exit path. A
// completed exec settles in sched_process_exec before it gets here, so any
// pending record left at a syscall exit is a failed exec.
SEC("tp_btf/sys_exit")
int BPF_PROG(rq_sys_exit, struct pt_regs *regs, long ret)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct rq_task *s = bpf_task_storage_get(&rq_tasks, t, 0, 0);

	if (!s || !s->pending)
		return 0;
	if (rq_mutant == RQ_MUT_NO_FAIL_RECONCILE)
		return 0;
	rq_settle(s, RQ_C_EXEC_FAIL, RQ_OUT_FAIL, ret);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(rq_sched_exit, struct task_struct *p)
{
	struct rq_task *s = bpf_task_storage_get(&rq_tasks, p, 0, 0);

	if (!s)
		return 0;
	if (rq_mutant != RQ_MUT_NO_ABORT_RECONCILE)
		rq_settle(s, RQ_C_EXEC_ABORT, RQ_OUT_ABORT, 0);
	if (s->counted) {
		s->counted = 0;
		rq_count(RQ_C_EXITS);
		rq_gauge(RQ_G_LIVE, -1);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
