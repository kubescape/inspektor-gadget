/* SPDX-License-Identifier: GPL-2.0 */
/* Persistent-owner commands. Native owns proc/cgroup pins, frozen admin nonce,
 * closed/drained admission and the two-phase map publication transaction. */
#ifndef FULL_OWNER_CONTROL_H
#define FULL_OWNER_CONTROL_H
static __always_inline int eo_control_gate(const struct eo_config *c)
{
	if (c->gate_slot >= 65536)
		return 0;
	__u32 slot = c->gate_slot;
	__u64 *gate = bpf_map_lookup_elem(&eo_gates, &slot);
	return gate && __sync_val_compare_and_swap(gate, 0, 0) == FG_CLOSED;
}
static __always_inline int eo_control_version(struct eo_health *h)
{
	__u64 version =
		__sync_val_compare_and_swap(&h->authority_version, 0, 0);
	if (version >= ER_UNKNOWN - 1) {
		eo_fault(EO_FAULT_VERSION);
		return 0;
	}
	__sync_lock_test_and_set(&h->authority_version, version + 1);
	return 1;
}
static __always_inline int eo_control_movement(int entering)
{
	struct eo_health *h = eo_status();
	if (!h || !h->movement_armed || h->retired || h->movement_fault)
		return 0;
	__u64 sequence =
		__sync_val_compare_and_swap(&h->movement_sequence, 0, 0);
	// Both outer operations are serialized by cgroup_mutex. Unexpected nesting
	// or any potential wrap is permanent failure, never a fresh even sequence.
	if (sequence >= ER_UNKNOWN - 1 || ((sequence & 1) != (!entering))) {
		h->movement_fault = 1;
		eo_fault(EO_FAULT_STATE);
		return 0;
	}
	__sync_fetch_and_add(&h->movement_sequence, 1);
	return 0;
}
SEC("fentry/cgroup_migrate") int BPF_PROG(eo_migrate_enter)
{
	return eo_control_movement(1);
}
SEC("fexit/cgroup_migrate") int BPF_PROG(eo_migrate_exit)
{
	return eo_control_movement(0);
}
SEC("fentry/cgroup_update_dfl_csses") int BPF_PROG(eo_reconfigure_enter)
{
	return eo_control_movement(1);
}
SEC("fexit/cgroup_update_dfl_csses") int BPF_PROG(eo_reconfigure_exit)
{
	return eo_control_movement(0);
}
SEC("fexit/cgroup_kn_lock_live")
int BPF_PROG(eo_movement_arm, struct kernfs_node *kn, bool drain,
	     struct cgroup *result)
{
	__u32 zero = 0;
	struct eo_command *command = bpf_map_lookup_elem(&eo_commands, &zero);
	if (!command || !eo_admin_authorized(command))
		return 0;
	struct eo_health *h = eo_status();
	if (!h || h->retired || h->movement_armed || !result ||
	    (__u64)result >= ~4095ULL)
		return 0;
	// Successful return still owns cgroup_mutex, draining earlier operations
	// whose function entry preceded attachment. Native uses a rejected negative-PID
	// cgroup.procs write and requires the authorized receipt (no hierarchy mutation).
	h->movement_sequence = 0;
	h->movement_fault = 0;
	__sync_lock_test_and_set(&h->movement_armed, 1);
	return 0;
}
static __always_inline int eo_control_root(const struct eo_config *c,
					   const struct eo_command *command,
					   int authorize)
{
	struct task_struct *task = bpf_task_from_pid(c->init_host_pid);
	if (!task)
		return EO_BAD_IDENTITY;
	int result = EO_BAD_IDENTITY;
	struct eo_task *state = eo_lookup_task(task);
	struct eo_anchor *anchor = eo_root();
	struct eo_health *h = eo_status();
	__u64 cgroup = 0;
	if (!anchor || !h || task->pid != task->tgid)
		goto out;
	// Authorization always proves the exact inventoried physical task. A later
	// zero-cookie check proves only continuity of the already-pinned group token:
	// de_thread may replace the leader's task/cookie without replacing that token.
	// Never mint task storage or initialize the anchor from this check path.
	if (authorize && !command->root_cookie)
		goto out;
	if (command->root_cookie &&
	    (!state || state->cookie != command->root_cookie))
		goto out;
	if (BPF_CORE_READ_INTO(&cgroup, task, cgroups, dfl_cgrp, kn, id) ||
	    cgroup != c->cgroup)
		goto out;
	__u64 group = eo_group(task);
	if (!group)
		goto out;
	if (authorize) {
		if (anchor->group) {
			if (anchor->group != group ||
			    anchor->cookie != command->root_cookie)
				goto out;
		} else {
			anchor->group = group;
			anchor->cookie = command->root_cookie;
			h->root_cookie = command->root_cookie;
		}
	}
	h->root_match = anchor->group == group;
	result = h->root_match ? EO_OK : EO_BAD_IDENTITY;
out:
	bpf_task_release(task);
	return result;
}
// kind0 inventories physical identities only; kind1 stages AND validates;
// kind2 validates without adoption or role initialization. Never hold a task
// spinlock while invoking any helper or caller-supplied role operation.
static __noinline int eo_control_inventory(const struct eo_config *c,
					   struct eo_work *w, __u32 mask,
					   int kind)
{
	struct eo_health *h = eo_status();
	if (!h)
		return EO_BAD_STORAGE;
	__u32 valid_roles = 0;
	if (kind) {
		if (!w)
			return EO_BAD_STORAGE;
		valid_roles = w->candidate.count;
		if (valid_roles > ER_ACTIVE)
			return EO_BAD_ROLES;
	}
	h->count = 0;
	if (!h->movement_armed || h->movement_fault)
		return EO_MOVEMENT;
	__u64 sequence =
		__sync_val_compare_and_swap(&h->movement_sequence, 0, 0);
	if (sequence & 1)
		return EO_MOVEMENT;
	struct cgroup *group = bpf_cgroup_from_id(c->cgroup);
	if (!group)
		return EO_BAD_IDENTITY;
	struct bpf_iter_css_task iterator;
	int status = EO_LIMIT;
	if (bpf_iter_css_task_new(&iterator, &group->self, 0)) {
		status = EO_BAD_ITERATOR;
		goto destroy;
	}
	for (__u32 index = 0; index <= EO_TASKS; index++) {
		struct task_struct *task = bpf_iter_css_task_next(&iterator);
		if (!task) {
			status = EO_OK;
			break;
		}
		if (index >= EO_TASKS || index >= c->task_limit)
			break;
		struct eo_task *state = eo_get_task(task);
		if (!state) {
			status = (h->faults & EO_FAULT_CAPACITY) ?
					 EO_LIMIT :
					 EO_BAD_STORAGE;
			break;
		}
		if (kind) {
			if (!w) {
				status = EO_BAD_STORAGE;
				break;
			}
			if (kind == 1 && !eo_lineage(task, state)) {
				status = EO_LINEAGE;
				break;
			}
			if (kind == 1 && eo_stage_task(task, state, w, mask)) {
				status = EO_BAD_ROLES;
				break;
			}
			if (eo_validate_task(state, w)) {
				status = EO_BAD_ROLES;
				break;
			}
		}
		struct eo_row *row = bpf_map_lookup_elem(&eo_rows, &index);
		if (!row) {
			status = EO_BAD_STORAGE;
			break;
		}
		__u32 flags;
		bpf_spin_lock(&state->lock);
		flags = state->flags;
		bpf_spin_unlock(&state->lock);
		row->cookie = state->cookie;
		row->tid = task->pid;
		row->tgid = task->tgid;
		row->flags = flags;
		row->valid_roles = valid_roles;
		h->count = index + 1;
	}
destroy:
	bpf_iter_css_task_destroy(&iterator);
	bpf_cgroup_release(group);
	if (h->movement_fault ||
	    __sync_val_compare_and_swap(&h->movement_sequence, 0, 0) !=
		    sequence)
		return EO_MOVEMENT;
	if (kind && h->faults)
		return EO_BAD_ROLES;
	if (kind && status == EO_OK) {
		struct eo_phase *phase = eo_phase_state();
		if (!phase)
			return EO_BAD_STORAGE;
		// Record the SAME sequence checked above, never a later reread which could
		// silently bless a migration occurring after the completed inventory.
		phase->validated_movement_sequence = sequence;
	}
	return status;
}
static __always_inline __u64 eo_control_generation(__u32 slot)
{
	const struct fm_blob *blob = eo_blob(slot, 0);
	if (!blob)
		return 0;
	return ((const struct fe_header *)blob)->generation;
}
static __always_inline int eo_control_accepted(__u64 generation)
{
	const struct fm_blob *blob = eo_blob(0, 0);
	if (!blob)
		return 0;
	const struct fe_header *header = (const void *)blob;
	if (header->generation != generation || header->policies > 8)
		return 0;
	__u32 count = header->policies;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= count)
			break;
		blob = eo_blob(0, 1 + i);
		if (!blob)
			return 0;
		const struct fe_policy *policy = (const void *)blob;
		if (!policy->uid || !policy->root_epoch ||
		    policy->root_epoch == ER_UNKNOWN ||
		    eo_accepted_epoch(policy->uid) != policy->root_epoch)
			return 0;
	}
	return 1;
}
static __always_inline int eo_control_receipt(struct eo_health *h,
					      struct eo_phase *phase)
{
	__u64 current =
		__sync_val_compare_and_swap(&h->movement_sequence, 0, 0);
	return h->movement_armed && !h->movement_fault && !(current & 1) &&
	       current == phase->validated_movement_sequence;
}
SEC("syscall") int eo_command(void *unused)
{
	__u32 zero = 0;
	struct eo_command *input = bpf_map_lookup_elem(&eo_commands, &zero);
	if (!input || !eo_admin_authorized(input))
		return EO_BAD_COMMAND;
	if (!eo_local_types())
		return EO_BAD_CONFIG;
	struct eo_command command = *input;
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	struct eo_phase *phase = eo_phase_state();
	if (!c || !h || !phase)
		return EO_BAD_STORAGE;
	if (__sync_val_compare_and_swap(&phase->busy, 0, 1))
		return EO_RETRY;
	int result = EO_BAD_CONFIG;
	struct eo_work *work = 0;
	if (c->abi != EO_ABI || !c->cookie || !c->cgroup || !c->init_host_pid ||
	    !c->task_limit || c->task_limit > EO_TASKS || c->gate_slot >= 65536)
		goto done;
	result = EO_BAD_COMMAND;
	if (h->retired || phase->state == EO_STOPPED)
		goto done;
	if (command.operation != EO_INVENTORY &&
	    command.operation != EO_ROOT_CHECK && !eo_control_gate(c)) {
		result = EO_RETRY;
		goto done;
	}
	if (command.operation == EO_INVENTORY) {
		result = eo_control_inventory(c, 0, 0, 0);
		goto done;
	}
	if (command.operation == EO_ROOT_AUTHORIZE ||
	    command.operation == EO_ROOT_CHECK) {
		h->root_match = 0;
		result = eo_control_root(
			c, &command, command.operation == EO_ROOT_AUTHORIZE);
		goto done;
	}
	if (command.operation == EO_RETIRE) {
		struct eo_anchor *anchor = eo_root();
		if (!anchor) {
			result = EO_BAD_STORAGE;
			goto done;
		}
		anchor->group = 0;
		anchor->cookie = 0;
		h->root_cookie = 0;
		h->root_match = 0;
		h->ready_generation = 0;
		h->a_complete = 0;
		h->retired = 1;
		phase->state = EO_STOPPED;
		phase->candidate_generation = 0;
		phase->new_uid_mask = 0;
		result = eo_control_version(h) ? EO_OK : EO_BAD_ROLES;
		goto done;
	}
	if (!command.generation || command.generation == ER_UNKNOWN)
		goto done;
	if (command.operation == EO_REATTEST) {
		// Same-generation, read-only physical re-attestation after membership motion.
		// No candidate roots, no UID publication, and no inferred historical lineage.
		if (phase->state != EO_IDLE ||
		    phase->committed_generation != command.generation ||
		    h->active_generation != command.generation ||
		    command.new_uid_mask ||
		    eo_control_generation(0) != command.generation)
			goto done;
		h->ready_generation = 0;
		if (h->faults || h->movement_fault) {
			result = EO_BAD_ROLES;
			goto done;
		}
		work = eo_get_work();
		if (!work) {
			result = EO_BAD_STORAGE;
			goto done;
		}
		if (eo_load_candidate(work, 0, 0) ||
		    work->a_epoch != command.generation) {
			result = EO_BAD_ROLES;
			goto done;
		}
		result = eo_control_inventory(c, work, 0, 2);
		if (result == EO_OK) {
			if (h->pending_births)
				result = EO_RETRY;
			else
				h->ready_generation = command.generation;
		}
		goto done;
	}

	if (command.operation == EO_BOOTSTRAP_A) {
		if (phase->state == EO_IDLE) {
			if (command.generation <= phase->attempted_generation)
				goto done;
			phase->attempted_generation = command.generation;
			phase->candidate_generation = command.generation;
			phase->new_uid_mask = command.new_uid_mask;
			phase->state = EO_STAGING;
			h->a_complete = 0;
			h->ready_generation = 0;
			if (!eo_control_version(h)) {
				result = EO_BAD_ROLES;
				goto done;
			}
		} else if (phase->state != EO_STAGING ||
			   phase->candidate_generation != command.generation ||
			   phase->new_uid_mask != command.new_uid_mask)
			goto done;
		// Any failed retry invalidates the earlier A-complete barrier.
		__sync_lock_test_and_set(&h->a_complete, 0);
	} else if (phase->candidate_generation != command.generation ||
		   (phase->new_uid_mask != command.new_uid_mask &&
		    !(command.operation == EO_VALIDATE &&
		      phase->state == EO_COMMITTED &&
		      command.new_uid_mask == 0)))
		goto done;
	switch (command.operation) {
	case EO_BOOTSTRAP_A:
	case EO_BOOTSTRAP_B:
	case EO_VALIDATE:
		if (command.operation == EO_BOOTSTRAP_B &&
		    (phase->state != EO_STAGING ||
		     __sync_val_compare_and_swap(&h->a_complete, 0, 0) !=
			     command.generation))
			goto done;
		if (command.operation == EO_VALIDATE &&
		    phase->state != EO_VALIDATED &&
		    phase->state != EO_COMMITTED)
			goto done;
		if (command.operation == EO_VALIDATE &&
		    phase->state == EO_COMMITTED && command.new_uid_mask)
			goto done;
		// A failed re-attestation must not leave an earlier readiness receipt live.
		if (command.operation != EO_BOOTSTRAP_A)
			h->ready_generation = 0;
		// Postcommit recovery only re-attests the active accepted roles. It must
		// never revisit staging roots or change the irreversible committed phase.
		__u32 slot = phase->state == EO_COMMITTED ? 0 : 1;
		__u32 mask =
			phase->state == EO_COMMITTED ? 0 : command.new_uid_mask;
		if (eo_control_generation(slot) != command.generation) {
			result = EO_BAD_ROLES;
			goto done;
		}
		if (h->faults || h->movement_fault) {
			result = EO_BAD_ROLES;
			goto done;
		}
		work = eo_get_work();
		if (!work) {
			result = EO_BAD_STORAGE;
			goto done;
		}
		if (eo_load_candidate(work, slot, mask) ||
		    work->a_epoch != command.generation) {
			result = EO_BAD_ROLES;
			goto done;
		}
		result = eo_control_inventory(
			c, work, mask,
			command.operation == EO_VALIDATE ? 2 : 1);
		if (result != EO_OK)
			goto done;
		if (command.operation == EO_BOOTSTRAP_A)
			__sync_lock_test_and_set(&h->a_complete,
						 command.generation);
		else {
			if (phase->state != EO_COMMITTED)
				phase->state = EO_VALIDATED;
			h->ready_generation = command.generation;
		}
		break;
	case EO_PUBLICATION_BEGIN:
		if (phase->state != EO_VALIDATED ||
		    h->ready_generation != command.generation || h->faults)
			goto done;
		if (!eo_control_receipt(h, phase)) {
			h->ready_generation = 0;
			result = EO_MOVEMENT;
			goto done;
		}
		if (!eo_control_version(h)) {
			result = EO_BAD_ROLES;
			goto done;
		}
		phase->state = EO_PUBLISHING;
		result = EO_OK;
		break;
	case EO_PUBLICATION_COMMITTED:
		if (phase->state != EO_PUBLISHING ||
		    !eo_control_accepted(command.generation))
			goto done;
		// Active-slot replacement, not this bookkeeping command, is the irreversible
		// commit. Native appends successful-only kernel history AFTER the swap and
		// holds PUBLISHING until that flush succeeds. Never offer Abort if the active
		// slot already names this generation, including a partial history flush.
		phase->committed_generation = command.generation;
		h->active_generation = command.generation;
		phase->state = EO_COMMITTED;
		result = eo_control_version(h) ? EO_OK : EO_BAD_ROLES;
		if (!eo_control_receipt(h, phase)) {
			h->ready_generation = 0;
			result = EO_MOVEMENT;
		}
		break;
	case EO_BOOTSTRAP_ABORT:
		if ((phase->state != EO_STAGING &&
		     phase->state != EO_VALIDATED &&
		     phase->state != EO_PUBLISHING) ||
		    eo_control_generation(0) == command.generation)
			goto done;
		if (!eo_control_version(h)) {
			result = EO_BAD_ROLES;
			goto done;
		}
		phase->state = EO_IDLE;
		phase->candidate_generation = 0;
		phase->new_uid_mask = 0;
		__sync_lock_test_and_set(&h->a_complete, 0);
		h->ready_generation = h->faults ? 0 : h->active_generation;
		result = EO_OK;
		break;
	case EO_PHASE_CLEAR:
		if (phase->state != EO_COMMITTED ||
		    phase->committed_generation != command.generation ||
		    eo_control_generation(0) != command.generation)
			goto done;
		if (!eo_control_receipt(h, phase)) {
			h->ready_generation = 0;
			result = EO_MOVEMENT;
			goto done;
		}
		if (h->faults || h->pending_births) {
			h->ready_generation = 0;
			result = EO_RETRY;
			goto done;
		}
		if (!eo_control_version(h)) {
			result = EO_BAD_ROLES;
			goto done;
		}
		phase->state = EO_IDLE;
		phase->candidate_generation = 0;
		phase->new_uid_mask = 0;
		__sync_lock_test_and_set(&h->a_complete, 0);
		h->ready_generation = h->faults ? 0 : command.generation;
		result = h->faults ? EO_BAD_ROLES : EO_OK;
		break;
	default:
		break;
	}
done:
	if (work)
		eo_put_work(work);
	h->result = result;
	__sync_lock_test_and_set(&phase->busy, 0);
	return result;
}
#endif
