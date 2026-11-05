#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
static __u64 accepted(__u64 uid)
{
	return uid > 0 && uid <= 2 ? 2 : 0;
}
#define ER_ACCEPTED_EPOCH(uid) accepted(uid)
#include "epoch_roles.h"
struct fm_blob;
static const struct fm_blob *fixture_blob(void *, unsigned int);
#define FM_BLOB_LOOKUP(context, key) fixture_blob(context, key)
#include "evaluator.h"
static const struct fm_blob *fixture_blob(void *context, unsigned int key)
{
	return context && key < 13 ? &((const struct fm_blob *)context)[key] :
				     0;
}
#define EO_FAULT_STATE 8
#define EO_FAULT_GATE 16
#define EO_QUARANTINED 2
struct task_struct {
	int unused;
};
struct linux_binprm {
	int unused;
};
struct eo_exec_tx {
	__u64 bprm, cgroup, generation, owner_cookie;
	__u32 owned, slot, suppress, checks;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	__u32 execution_class, role_uncertain_mask, role_write_mask;
	__u32 global_deny_unknown, known_deny_seen, policy_count;
	__u32 enforced_write_mask, role_conflict_mask;
#endif
	struct er_row pending[8];
};
struct eo_task {
	int lock;
	__u32 flags;
	struct er_state committed;
	struct eo_exec_tx exec;
};
struct eo_config {
	__u64 cookie, cgroup;
	__u32 gate_slot;
};
struct eo_work {
	__u64 a_epoch, authority;
	struct er_work merge;
	struct er_state source;
	struct er_candidate candidate;
};
static struct eo_task task;
static struct eo_config config;
static struct fe_header head;
static struct eo_work work;
static int locked;
static struct linux_binprm bprm;
struct eo_health {
	__u64 authority_version, faults;
};
static struct eo_health health;
static __u64 gate;
static int leaves;
static struct eo_health *eo_status(void)
{
	return &health;
}
static __u64 *eo_gate(__u32 slot)
{
	assert(slot == config.gate_slot);
	return &gate;
}
static void fg_leave_owned(__u64 *value, __u32 owned, __u64 *faults)
{
	(void)value;
	(void)faults;
	assert(!locked);
	leaves += owned;
}
static int hard_fault, invalid_rows, mutate_exec_snapshot;
static __u64 fault_generation, fault_bits;
static struct eo_config *eo_config(void)
{
	return &config;
}
static void *bpf_get_current_task_btf(void)
{
	return &task;
}
static struct eo_task *eo_lookup_task(void *current)
{
	(void)current;
	return &task;
}
static const void *eo_blob(int slot, int key)
{
	(void)slot;
	(void)key;
	assert(!locked);
	return &head;
}
static void bpf_spin_lock(int *lock)
{
	(void)lock;
	assert(!locked);
	locked = 1;
}
static void bpf_spin_unlock(int *lock)
{
	(void)lock;
	assert(locked);
	locked = 0;
}
static void eo_clear_pending(struct eo_exec_tx *tx)
{
	memset(tx->pending, 0, sizeof(tx->pending));
}
static void eo_exec_suppress(void)
{
	assert(!locked);
	task.exec.suppress = 1;
	eo_clear_pending(&task.exec);
}
static void eo_quarantine(struct eo_task *s)
{
	assert(!locked);
	s->flags |= 2;
	hard_fault = 1;
}
static void eo_fault(int bit)
{
	assert(!locked);
	hard_fault |= bit;
}
static void eo_data_fault(__u64 generation, __u64 bit)
{
	assert(!locked);
	fault_generation = generation;
	fault_bits |= bit;
}
static struct eo_work *eo_get_work(void)
{
	assert(!locked);
	return &work;
}
static void eo_put_work(struct eo_work *w)
{
	(void)w;
	assert(!locked);
}
static int eo_load_candidate(struct eo_work *w, int slot, int mask)
{
	(void)slot;
	(void)mask;
	assert(!locked);
	w->a_epoch = head.generation;
	return 0;
}
static int eo_validate_exec_task(struct eo_task *s, struct eo_work *w)
{
	assert(!locked);
	if (mutate_exec_snapshot) {
		s->exec.checks++;
		mutate_exec_snapshot = 0;
	}
	er_snapshot(&w->merge, &s->committed, w->authority);
	return invalid_rows ? -1 : er_prepare(&w->merge, &w->candidate);
}
/* ACTUAL_ROLE_FACTS */
/* ACTUAL_PROPOSAL */
/* ACTUAL_COMPLETION */
static void reset(void)
{
	memset(&task, 0, sizeof(task));
	memset(&work, 0, sizeof(work));
	config = (struct eo_config){ 99, 123, 4 };
	head.generation = 7;
	head.policies = 1;
	health = (struct eo_health){ .authority_version = 1 };
	leaves = 0;
	work.authority = 1;
	task.flags = 1;
	task.committed.version = 2;
	task.committed.rows[0] = er_known_row(1, 2, 777);
	task.exec = (struct eo_exec_tx){ .bprm = (__u64)&bprm,
					 .cgroup = 123,
					 .generation = 7,
					 .owner_cookie = 99,
					 .owned = 1,
					 .slot = 4 };
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	task.exec.execution_class = 2;
	task.exec.policy_count = 1;
#endif
	work.candidate.count = 1;
	work.candidate.active[0] = (struct er_authority){ 1, 2, 777, 0, 0 };
	hard_fault = invalid_rows = locked = mutate_exec_snapshot = 0;
	fault_generation = fault_bits = 0;
}
static void preserved(void)
{
	assert(task.flags == 1);
	assert(task.committed.version == 2);
	assert(task.committed.rows[0].role == 777);
	assert(!hard_fault);
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
static void fixture_set_rule(struct fm_blob *blob, struct fe_rule rule)
{
	memcpy(blob, &rule, sizeof(rule));
}
#endif
int main(void)
{
	for (__u32 error = 1; error <= 3; error++) {
		reset();
		struct fe_decision d = { .error = error };
		task.exec.pending[0] = er_known_row(1, 2, 42);
		assert(eo_exec_propose(&bprm, &d) == -1);
		preserved();
		assert(task.exec.suppress && !task.exec.pending[0].uid);
		assert(fault_generation == 7 && fault_bits == (1ULL << error));
	}
	reset();
	struct fe_decision d = { .deny = 1 };
	assert(!eo_exec_propose(&bprm, &d));
	preserved();
	assert(task.exec.suppress && !fault_generation);
	reset();
	d = (struct fe_decision){ .proposed_roles = { 10 },
				  .enforced_writes = 1 };
	assert(!eo_exec_propose(&bprm, &d));
	preserved();
	assert(task.exec.pending[0].role == 10);
	d.proposed_roles[0] = 20;
	assert(eo_exec_propose(&bprm, &d) == -1);
	preserved();
	assert(task.exec.suppress && !task.exec.pending[0].uid &&
	       fault_generation == 7 && fault_bits == (1ULL << 3));
	// A later revision/attempt retains committed actor role and can propose again.
	task.exec.suppress = 0;
	task.exec.generation = head.generation = 8;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	task.exec.role_uncertain_mask = task.exec.role_write_mask = 0;
	task.exec.enforced_write_mask = task.exec.role_conflict_mask = 0;
#endif
	d.proposed_roles[0] = 30;
	assert(!eo_exec_propose(&bprm, &d));
	preserved();
	assert(task.exec.pending[0].role == 30 && fault_generation == 7);
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	// A later interpreter check must cancel an earlier known proposal globally
	// when an unknown audit deny could have suppressed that grant.
	reset();
	d = (struct fe_decision){ .proposed_roles = { 10 } };
	assert(!eo_exec_propose(&bprm, &d));
	d = (struct fe_decision){ .error = FE_AUDIT_UNKNOWN,
				  .audit_unknown = FE_AUDIT_GLOBAL_SUPPRESS |
						   1U };
	assert(!eo_exec_propose(&bprm, &d));
	preserved();
	assert(task.exec.suppress && !er_role_known(&task.exec.pending[0]));
	d = (struct fe_decision){ .proposed_roles = { 20 } };
	assert(!eo_exec_propose(&bprm, &d));
	assert(!er_role_known(&task.exec.pending[0]));

	// Audit-local uncertainty clears only the affected pending UID and cannot
	// resurrect that UID on a later interpreter check of this same exec.
	reset();
	work.candidate.count = head.policies = task.exec.policy_count = 2;
	work.candidate.active[1] = (struct er_authority){ 2, 2, 888, 0, 0 };
	d = (struct fe_decision){ .proposed_roles = { 10, 20 } };
	assert(!eo_exec_propose(&bprm, &d));
	d = (struct fe_decision){ .error = FE_AUDIT_UNKNOWN,
				  .audit_unknown = 1 | (1U << 8) | (1U << 16) };
	assert(!eo_exec_propose(&bprm, &d));
	preserved();
	assert(!task.exec.suppress && !er_role_known(&task.exec.pending[0]) &&
	       task.exec.pending[1].role == 20);
	d = (struct fe_decision){ .proposed_roles = { 30, 20 } };
	assert(!eo_exec_propose(&bprm, &d));
	assert(!er_role_known(&task.exec.pending[0]) &&
	       task.exec.pending[1].role == 20);

	// Successful causal uncertainty publishes UNKNOWN with factual identity and
	// last-known diagnostic role, while the independent UID's known grant commits.
	task.committed.rows[1] = er_known_row(2, 2, 888);
	assert(!eo_finish_exec((struct task_struct *)&task, &bprm, 1));
	assert(task.committed.rows[0].uid == 1 &&
	       task.committed.rows[0].epoch == 2 &&
	       task.committed.rows[0].role == 777 &&
	       task.committed.rows[0].knowledge == ER_ROLE_UNKNOWN);
	assert(task.committed.rows[1].role == 20 &&
	       task.committed.rows[1].knowledge == ER_ROLE_KNOWN);
	assert(!task.exec.owned && leaves == 1);
	assert(!eo_finish_exec((struct task_struct *)&task, &bprm, 1) &&
	       leaves == 1);

	// UNKNOWN diagnostic old role must never become an authoritative fact.
	struct er_state retained = task.committed;
	reset();
	task.committed = retained;
	task.exec.policy_count = head.policies = work.candidate.count = 2;
	work.candidate.active[1] = (struct er_authority){ 2, 2, 888, 0, 0 };
	struct fe_facts facts;
	memset(&facts, 0xa5, sizeof(facts));
	assert(!eo_fill_roles(&facts));
	assert(facts.role_count == 1 && facts.roles[0].policy_uid == 2 &&
	       facts.roles[0].role == 20);
	assert(!facts.roles[1].policy_uid && !facts.roles[1].role);
	// A new independently known transition can repair only that UID knowledge.
	d = (struct fe_decision){ .proposed_roles = { 30 } };
	assert(!eo_exec_propose(&bprm, &d));
	assert(!eo_finish_exec((struct task_struct *)&task, &bprm, 1));
	assert(task.committed.rows[0].knowledge == ER_ROLE_KNOWN &&
	       task.committed.rows[0].role == 30);
	assert(task.committed.rows[1].role == 20);

	// Unknown global deny makes only causal role-writers UNKNOWN on success.
	reset();
	task.committed.rows[1] = er_known_row(2, 2, 888);
	d = (struct fe_decision){ .proposed_roles = { 10 } };
	assert(!eo_exec_propose(&bprm, &d));
	d = (struct fe_decision){ .error = FE_AUDIT_UNKNOWN,
				  .audit_unknown = FE_AUDIT_GLOBAL_SUPPRESS |
						   1U };
	assert(!eo_exec_propose(&bprm, &d));
	assert(!eo_finish_exec((struct task_struct *)&task, &bprm, 1));
	assert(task.committed.rows[0].role == 777 &&
	       task.committed.rows[0].knowledge == ER_ROLE_UNKNOWN);
	assert(task.committed.rows[1].role == 888 &&
	       task.committed.rows[1].knowledge == ER_ROLE_KNOWN);

	// An audit-local known conflict across interpreter checks must not inherit
	// another UID's enforcement class or discard that independent UID's grant.
	for (int reverse = 0; reverse < 2; reverse++) {
		reset();
		work.candidate.count = head.policies = task.exec.policy_count =
			2;
		work.candidate.active[1] =
			(struct er_authority){ 2, 2, 888, 0, 0 };
		task.committed.rows[1] = er_known_row(2, 2, 888);
		d = (struct fe_decision){ .proposed_roles = { reverse ? 20 : 10,
							      40 },
					  .enforced_writes = 2 };
		assert(!eo_exec_propose(&bprm, &d));
		d.proposed_roles[0] = reverse ? 10 : 20;
		assert(!eo_exec_propose(&bprm, &d));
		assert(!task.exec.suppress &&
		       !er_role_known(&task.exec.pending[0]) &&
		       task.exec.pending[1].role == 40);
		assert(!eo_finish_exec((struct task_struct *)&task, &bprm, 1));
		assert(task.committed.rows[0].knowledge == ER_ROLE_UNKNOWN &&
		       task.committed.rows[0].role == 777);
		assert(task.committed.rows[1].knowledge == ER_ROLE_KNOWN &&
		       task.committed.rows[1].role == 40);
	}
	for (int conflict = 0; conflict < 2; conflict++) {
		reset();
		d = (struct fe_decision){ .proposed_roles = { 10 } };
		assert(!eo_exec_propose(&bprm, &d));
		if (conflict) {
			d.proposed_roles[0] = 20;
			assert(!eo_exec_propose(&bprm, &d));
		} else {
			d = (struct fe_decision){ .error = FE_AUDIT_UNKNOWN,
						  .audit_unknown = 1 |
								   (1U << 8) |
								   (1U << 16) };
			assert(!eo_exec_propose(&bprm, &d));
		}
		d = (struct fe_decision){ .proposed_roles = { 30 },
					  .enforced_writes = 1 };
		assert(eo_exec_propose(&bprm, &d) == -1);
		assert(!er_role_known(&task.exec.pending[0]));
	}

	// Compose the real evaluator with the real owner proposal function. A known
	// audit role lost from grantable output by same-call uncertainty must still
	// be a comparison witness on the next interpreter check.
	for (int known = 0; known < 2; known++) {
		reset();
		struct fm_blob blobs[13] = {};
		struct fe_header program_head =
			(struct fe_header){ .generation = 7,
					    .policies = 1,
					    .rule_base = 9,
					    .rules = known ? 2 : 1 };
		struct fe_policy program_policy = {
			.uid = 1, .root_role = 777, .mode = 1, .root_epoch = 2
		};
		memcpy(&blobs[1], &program_policy, sizeof(program_policy));
		struct fe_rule known_rule = { .mode = 1,
					      .actor_image = -1,
					      .target_image = -1,
					      .stdin_pipe = -1,
					      .set_role = 10 };
		struct fe_rule unknown_rule = { .mode = 1,
						.actor_image = -1,
						.target_image = -1,
						.stdin_pipe = -1,
						.set_role = 20,
						.uid = { 12, 1 } };
		struct fe_rule enforced_rule = { .mode = 2,
						 .actor_image = -1,
						 .target_image = -1,
						 .stdin_pipe = -1,
						 .set_role = 30 };
		fixture_set_rule(&blobs[9], known ? known_rule : unknown_rule);
		fixture_set_rule(&blobs[10], unknown_rule);
		struct fe_facts facts = {};
		struct fe_scratch scratch = {};
		memcpy(&blobs[0], &program_head, sizeof(program_head));
		assert(!fe_evaluate(blobs, &facts, &scratch));
		assert(!scratch.decision.proposed_roles[0]);
		assert(scratch.decision.known_role_witnesses[0] ==
		       (known ? 10 : 0));
		assert(!eo_exec_propose(&bprm, &scratch.decision));
		fixture_set_rule(&blobs[9], enforced_rule);
		program_head.rules = 1;
		memcpy(&blobs[0], &program_head, sizeof(program_head));
		assert(!fe_evaluate(blobs, &facts, &scratch));
		assert(eo_exec_propose(&bprm, &scratch.decision) ==
		       (known ? -1 : 0));
		// Equivalent single-call union must have exactly the same conflict disposition.
		program_head.rules = known ? 3 : 2;
		fixture_set_rule(&blobs[9], known ? known_rule : unknown_rule);
		fixture_set_rule(&blobs[10],
				 known ? unknown_rule : enforced_rule);
		fixture_set_rule(&blobs[11], enforced_rule);
		memcpy(&blobs[0], &program_head, sizeof(program_head));
		assert(fe_evaluate(blobs, &facts, &scratch) ==
		       (known ? -1 : 0));
	}

	// A changed transaction snapshot refuses publication, rather than committing
	// stale pending roles or releasing ownership twice.
	reset();
	d = (struct fe_decision){ .proposed_roles = { 10 } };
	assert(!eo_exec_propose(&bprm, &d));
	struct er_state snapshot_before = task.committed;
	mutate_exec_snapshot = 1;
	assert(!eo_finish_exec((struct task_struct *)&task, &bprm, 1));
	assert(hard_fault && !memcmp(&task.committed, &snapshot_before,
				     sizeof(snapshot_before)));
	assert(!task.exec.owned && leaves == 1);

	// Failed exec or a known semantic deny preserves every committed byte.
	for (int deny = 0; deny < 2; deny++) {
		reset();
		struct er_state before = task.committed;
		d = (struct fe_decision){ .error = FE_AUDIT_UNKNOWN,
					  .audit_unknown = 1 | (1U << 8) |
							   (1U << 16) };
		assert(!eo_exec_propose(&bprm, &d));
		if (deny) {
			d = (struct fe_decision){ .deny = 1 };
			assert(!eo_exec_propose(&bprm, &d));
		}
		assert(!eo_finish_exec((struct task_struct *)&task, &bprm,
				       deny));
		assert(!memcmp(&task.committed, &before, sizeof(before)) &&
		       leaves == 1);
	}

#endif
	// Transaction identity/epoch mismatch and missing accepted rows remain hard.
	for (int failure = 0; failure < 7; failure++) {
		reset();
		d = (struct fe_decision){ .proposed_roles = { 10 } };
		switch (failure) {
		case 0:
			task.exec.bprm++;
			break;
		case 1:
			task.exec.owner_cookie++;
			break;
		case 2:
			task.exec.slot++;
			break;
		case 3:
			task.exec.generation++;
			break;
		case 4:
			task.exec.cgroup++;
			break;
		case 5:
			task.exec.pending[0] = er_known_row(1, 3, 10);
			break;
		case 6:
			invalid_rows = 1;
			break;
		}
		assert(eo_exec_propose(&bprm, &d) == -1);
		assert(hard_fault && (task.flags & 2) && task.exec.suppress &&
		       !fault_generation);
		assert(task.committed.rows[0].role == 777);
	}
	return 0;
}
