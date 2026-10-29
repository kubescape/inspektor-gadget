/* SPDX-License-Identifier: GPL-2.0 */
#ifndef FULL_OWNER_ROLES_H
#define FULL_OWNER_ROLES_H
/* Persistent-owner role lifecycle. Include evaluator.h then owner_types.h.
 * No native activation/Ready claim: authoritative catalogue, gate ownership,
 * immutable map publication and physical inventory remain owner contracts. */
static __always_inline __u64 *eo_gate(__u32 slot)
{
	if (slot >= 65536)
		return 0;
	return bpf_map_lookup_elem(&eo_gates, &slot);
}
static __always_inline int eo_load_candidate(struct eo_work *w, __u32 slot,
					     __u32 newmask)
{
	struct eo_health *h = eo_status();
	struct eo_phase *phase = eo_phase_state();
	if (!phase || phase->state == EO_PUBLISHING ||
	    phase->state == EO_STOPPED)
		return -1;
	const struct fe_header *head = (const void *)eo_blob(slot, 0);
	if (!h || !h->authority_version || h->retired || !head ||
	    !head->generation || head->generation == ER_UNKNOWN ||
	    !head->policies || head->policies > ER_ACTIVE ||
	    head->rule_base != 9 || head->rules > 256 ||
	    newmask >> head->policies)
		return -1;
	w->authority = h->authority_version;
	w->a_epoch = head->generation;
	w->candidate.count = head->policies;
	w->candidate.reserved = 0;
	for (int i = 0; i < ER_ACTIVE; i++) {
		w->candidate.active[i] = (struct er_authority){};
		if ((__u32)i >= head->policies)
			continue;
		const struct fe_policy *p = (const void *)eo_blob(slot, 1 + i);
		if (!p || !p->uid || !p->root_role || !p->root_epoch ||
		    p->root_epoch == ER_UNKNOWN ||
		    p->root_epoch > head->generation)
			return -1;
		__u64 accepted = eo_accepted_epoch(p->uid);
		if (accepted == ER_UNKNOWN)
			return -1;
		__u32 fresh = 0;
		if (accepted) {
			if (accepted != p->root_epoch)
				return -1;
		} else {
			if (!(newmask & (1U << i)))
				return -1;
			fresh = 1;
		}
		w->candidate.active[i] =
			(struct er_authority){ p->uid, p->root_epoch,
					       p->root_role, fresh, 0 };
	}
	return er_candidate_valid(&w->candidate) ||
			       h->authority_version != w->authority ?
		       -1 :
		       0;
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* A separately verified pure predicate keeps physical-inventory iterations
 * from multiplying the eight-by-sixteen role-state branch space. */
__noinline int eo_rows_present(struct eo_work *w)
{
	if (!w || w->candidate.count > ER_ACTIVE)
		return -1;
	for (int i = 0; i < ER_ACTIVE; i++) {
		if ((__u32)i >= w->candidate.count)
			break;
		struct er_authority *a = &w->candidate.active[i];
		int found = 0;
		// Fixed offsets avoid LLVM's split-search induction escaping its bound in
		// the pinned verifier. Duplicate matches still refuse, never truncate.
#ifdef __BPF__
#pragma clang loop unroll(full)
#endif
		for (int j = 0; j < ER_SLOTS; j++) {
			struct er_row *r = &w->merge.rows[j];
			if (r->uid == a->uid && r->epoch == a->epoch &&
			    r->role) {
				if (found)
					return -1;
				found = 1;
			}
		}
		if (!found)
			return -1;
	}
	return 0;
}
#endif
/* A separately verified pure predicate keeps physical-inventory iterations
 * from multiplying the eight-by-sixteen role-state branch space. */
__noinline int eo_rows_complete(struct eo_work *w)
{
	if (!w || w->candidate.count > ER_ACTIVE)
		return -1;
	for (int i = 0; i < ER_ACTIVE; i++) {
		if ((__u32)i >= w->candidate.count)
			break;
		struct er_authority *a = &w->candidate.active[i];
		int found = 0;
		// Fixed offsets avoid LLVM's split-search induction escaping its bound in
		// the pinned verifier. Duplicate matches still refuse, never truncate.
#ifdef __BPF__
#pragma clang loop unroll(full)
#endif
		for (int j = 0; j < ER_SLOTS; j++) {
			struct er_row *r = &w->merge.rows[j];
			if (r->uid == a->uid && r->epoch == a->epoch &&
			    r->role && er_role_known(r)) {
				if (found)
					return -1;
				found = 1;
			}
		}
		if (!found)
			return -1;
	}
	return 0;
}
static __noinline int
eo_validate_task_impl(struct eo_task *s, struct eo_work *w, int require_known)
{
	struct eo_health *h = eo_status();
	if (!h || h->authority_version != w->authority)
		return -1;
	__u32 flags;
	bpf_spin_lock(&s->lock);
	flags = s->flags;
	er_snapshot(&w->merge, &s->committed, w->authority);
	bpf_spin_unlock(&s->lock);
	if (!(flags & EO_VERIFIED) || (flags & EO_QUARANTINED) ||
	    er_prepare(&w->merge, &w->candidate))
		return -1;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	if (require_known ? eo_rows_complete(w) : eo_rows_present(w))
		return -1;
#else
	(void)require_known;
	if (eo_rows_complete(w))
		return -1;
#endif
	return h->authority_version == w->authority ? 0 : -1;
}
static __noinline int eo_stage_task_impl(struct task_struct *task,
					 struct eo_task *s, struct eo_work *w,
					 __u32 newmask)
{
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || h->authority_version != w->authority)
		return -1;
	__u64 *gate = eo_gate(c->gate_slot);
	if (!gate || fg_read(gate) != FG_CLOSED)
		return -1;
	for (int i = 0; i < ER_ACTIVE; i++)
		if ((__u32)i < w->candidate.count &&
		    w->candidate.active[i].new_uid && !(newmask & (1U << i)))
			return -1;
	if (!eo_lineage(task, s))
		return -1;
	bpf_spin_lock(&s->lock);
	er_snapshot(&w->merge, &s->committed, w->authority);
	bpf_spin_unlock(&s->lock);
	if (er_stage_roots(&w->merge, &w->candidate, 1) || eo_rows_complete(w))
		return -1;
	int result = -1;
	bpf_spin_lock(&s->lock);
	if (!(s->flags & EO_QUARANTINED) &&
	    h->authority_version == w->authority)
		result = er_publish(&s->committed, &w->merge, w->authority);
	bpf_spin_unlock(&s->lock);
	return result ? -1 : 0;
}
static __always_inline int eo_validate_task(struct eo_task *s,
					    struct eo_work *w)
{
	return eo_validate_task_impl(s, w, 1);
}
/* Exec may observe retained UNKNOWN; readiness still requires eo_validate_task. */
static __always_inline int eo_validate_exec_task(struct eo_task *s,
						 struct eo_work *w)
{
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	return eo_validate_task_impl(s, w, 0);
#else
	return eo_validate_task(s, w);
#endif
}
static __always_inline int eo_stage_task(struct task_struct *task,
					 struct eo_task *s, struct eo_work *w,
					 __u32 newmask)
{
	return eo_stage_task_impl(task, s, w, newmask);
}
static __always_inline void eo_clear_pending(struct eo_exec_tx *tx)
{
	for (int i = 0; i < ER_ACTIVE; i++)
		tx->pending[i] = (struct er_row){};
}
static __always_inline void eo_exec_suppress(void)
{
	struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
	if (!s)
		return;
	bpf_spin_lock(&s->lock);
	if (s->exec.owned) {
		s->exec.suppress = 1;
		eo_clear_pending(&s->exec);
	}
	bpf_spin_unlock(&s->lock);
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
static __always_inline __u32 eo_exec_class(void)
{
	struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
	if (!s)
		return 2;
	__u32 execution_class;
	bpf_spin_lock(&s->lock);
	execution_class = s->exec.owned ? s->exec.execution_class : 2;
	bpf_spin_unlock(&s->lock);
	return execution_class == 1 ? 1 : 2;
}
/* Shared observation failure cannot certify a missed role transition. Only
 * possible authored role writers are affected; unchanged UID histories survive. */
static __always_inline void eo_exec_observation_fault(__u64 generation,
						      __u64 bit)
{
	eo_data_fault(generation, bit);
	__u32 policies = 0, writes = 0;
	int valid = fe_execution_class(0, generation, &policies, &writes);
	struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
	if (!s)
		return;
	bpf_spin_lock(&s->lock);
	if (s->exec.owned && s->exec.generation == generation) {
		if (valid < 1 || policies != s->exec.policy_count)
			writes = 0xffU >> (8 - (s->exec.policy_count <= 8 ?
							s->exec.policy_count :
							8));
		s->exec.role_write_mask |= writes;
		s->exec.role_uncertain_mask |= writes;
		s->exec.suppress = 1;
		eo_clear_pending(&s->exec);
	}
	bpf_spin_unlock(&s->lock);
}
#endif
static __always_inline int eo_exec_begin(struct linux_binprm *bprm,
					 __u64 *generation)
{
	*generation = 0;
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || !c->cookie || c->abi != EO_ABI || h->retired)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct eo_task *s = eo_lookup_task(task);
	__u32 owned = 0;
	if (s) {
		bpf_spin_lock(&s->lock);
		owned = s->exec.owned;
		*generation = s->exec.generation;
		bpf_spin_unlock(&s->lock);
	}
	if (!owned && bpf_get_current_cgroup_id() != c->cgroup)
		return 0;
	if (h->faults) {
		eo_exec_suppress();
		return -1;
	}
	if (!owned) {
		__u64 *gate = eo_gate(c->gate_slot);
		if (!gate)
			return -1;
		if (fg_enter(gate)) {
			__sync_fetch_and_add(&h->gate_denials, 1);
			return -1;
		}
		s = eo_get_task(task);
		if (!s) {
			eo_fault(EO_FAULT_STORAGE);
			fg_leave_owned(gate, 1, &h->faults);
			return -1;
		}
		const struct fe_header *head = (const void *)eo_blob(0, 0);
		__u64 gen = head ? head->generation : 0;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
		__u32 policies = 0, role_writers = 0;
		int execution_class =
			fe_execution_class(0, gen, &policies, &role_writers);
		if (execution_class < 1) {
			fg_leave_owned(gate, 1, &h->faults);
			eo_fault(EO_FAULT_STATE);
			return -1;
		}
#endif
		int collision = 0;
		bpf_spin_lock(&s->lock);
		if (s->exec.owned)
			collision = 1;
		else {
			s->exec.bprm = (__u64)bprm;
			s->exec.cgroup = c->cgroup;
			s->exec.generation = gen;
			s->exec.owner_cookie = c->cookie;
			s->exec.slot = c->gate_slot;
			s->exec.owned = 1;
			s->exec.checks = 0;
			s->exec.suppress = 0;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
			s->exec.execution_class = execution_class;
			s->exec.policy_count = policies;
			s->exec.role_uncertain_mask = s->exec.role_write_mask =
				0;
			s->exec.global_deny_unknown = s->exec.known_deny_seen =
				0;
#endif
			eo_clear_pending(&s->exec);
		}
		bpf_spin_unlock(&s->lock);
		if (collision) {
			eo_fault(EO_FAULT_STATE);
			fg_leave_owned(gate, 1, &h->faults);
			return -1;
		}
		*generation = gen;
	}
	int invalid = 0;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	__u32 policies = 0, role_writers = 0;
	int execution_class =
		fe_execution_class(0, *generation, &policies, &role_writers);
#endif
	bpf_spin_lock(&s->lock);
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	if (execution_class < 1 ||
	    s->exec.execution_class != (__u32)execution_class ||
	    s->exec.policy_count != policies)
		invalid = 1;
#endif
	if (s->exec.bprm != (__u64)bprm || s->exec.owner_cookie != c->cookie ||
	    s->exec.cgroup != c->cgroup || s->exec.slot != c->gate_slot ||
	    !s->exec.generation || s->exec.generation == ER_UNKNOWN ||
	    s->exec.checks >= 64)
		invalid = 1;
	else
		s->exec.checks++;
	bpf_spin_unlock(&s->lock);
	struct eo_work *w = eo_get_work();
	if (!w)
		invalid = 1;
	else {
		if (eo_load_candidate(w, 0, 0) || w->a_epoch != *generation ||
		    eo_validate_exec_task(s, w))
			invalid = 1;
		eo_put_work(w);
	}
	if (invalid) {
		eo_exec_suppress();
		eo_quarantine(s);
		return -1;
	}
	return 1;
}
static __always_inline int eo_fill_roles(struct fe_facts *f)
{
	f->role_count = 0;
	for (int i = 0; i < ER_ACTIVE; i++)
		f->roles[i] = (struct fe_role){};
	struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
	if (!s)
		return -1;
	struct eo_work *w = eo_get_work();
	if (!w)
		return -1;
	__u64 generation;
	__u32 owned;
	bpf_spin_lock(&s->lock);
	generation = s->exec.generation;
	owned = s->exec.owned;
	bpf_spin_unlock(&s->lock);
	int result = -1;
	if (!owned || eo_load_candidate(w, 0, 0) || w->a_epoch != generation ||
	    eo_validate_exec_task(s, w))
		goto out;
	for (int i = 0; i < ER_ACTIVE; i++) {
		if ((__u32)i >= w->candidate.count)
			break;
		struct er_authority *a = &w->candidate.active[i];
		for (int j = 0; j < ER_SLOTS; j++)
			if (w->merge.rows[j].uid == a->uid &&
			    w->merge.rows[j].epoch == a->epoch &&
			    er_role_known(&w->merge.rows[j])) {
				__u32 index = f->role_count;
				if (index >= ER_ACTIVE)
					goto out;
				f->roles[index].policy_uid = a->uid;
				f->roles[index].role = w->merge.rows[j].role;
				f->role_count++;
			}
	}
	result = 0;
out:
	eo_put_work(w);
	return result;
}
static __always_inline int eo_exec_propose(struct linux_binprm *bprm,
					   const struct fe_decision *d)
{
	struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
	if (!s)
		return -1;
	struct eo_config *c = eo_config();
	const struct fe_header *head = (const void *)eo_blob(0, 0);
	__u64 generation;
	int invalid;
	bpf_spin_lock(&s->lock);
	generation = s->exec.generation;
	invalid = !c || !head || !s->exec.owned ||
		  s->exec.bprm != (__u64)bprm ||
		  s->exec.owner_cookie != c->cookie ||
		  s->exec.cgroup != c->cgroup || s->exec.slot != c->gate_slot ||
		  !generation || generation == ER_UNKNOWN ||
		  generation != head->generation;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	invalid = invalid || !head || !head->policies ||
		  head->policies > ER_ACTIVE ||
		  s->exec.policy_count != head->policies ||
		  (d->audit_unknown & ~FE_UNCERTAINTY_VALID_MASK);
#endif
	bpf_spin_unlock(&s->lock);
	if (invalid) {
		eo_exec_suppress();
		eo_quarantine(s);
		eo_fault(EO_FAULT_STATE);
		return -1;
	}
	/* Observation failures and authored transition conflicts poison this attempt,
  * not previously trusted lineage/committed roles. A repaired generation can
  * therefore recover without re-rooting or clearing accepted task state. */
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	if (d->deny) {
		bpf_spin_lock(&s->lock);
		s->exec.known_deny_seen = 1;
		bpf_spin_unlock(&s->lock);
	}
	if (d->deny || (d->error && d->error != FE_AUDIT_UNKNOWN)) {
#else
	if (d->deny || d->error) {
#endif
		eo_exec_suppress();
		if (d->error
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
		    && d->error != FE_AUDIT_UNKNOWN
#endif
		) {
			eo_data_fault(generation,
				      1ULL << (d->error <= FE_ROLE_CONFLICT ?
						       d->error :
						       FE_INVALID));
			return -1;
		}
		return 0;
	}
	struct eo_work *w = eo_get_work();
	if (!w) {
		eo_exec_suppress();
		return -1;
	}
	invalid = eo_load_candidate(w, 0, 0);
	int conflict = 0;
	if (!invalid)
		invalid = eo_validate_exec_task(s, w);
	if (!invalid) {
		bpf_spin_lock(&s->lock);
		if (!s->exec.owned || s->exec.bprm != (__u64)bprm ||
		    s->exec.generation != w->a_epoch ||
		    s->committed.version != w->merge.base_version)
			invalid = 1;
		else {
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
			__u32 writes = FE_ROLE_WRITES(d->audit_unknown);
			for (int i = 0; i < ER_ACTIVE; i++)
				if (d->proposed_roles[i])
					writes |= 1U << i;
			__u32 uncertain = FE_ROLE_UNCERTAIN(d->audit_unknown);
			if ((writes | uncertain | (d->audit_unknown & 0xffU)) >>
			    s->exec.policy_count)
				invalid = 1;
			s->exec.role_write_mask |= writes;
			s->exec.enforced_write_mask |= d->enforced_writes;
			s->exec.role_conflict_mask |= d->role_conflicts;
			if ((d->enforced_writes | d->role_conflicts) >>
			    s->exec.policy_count)
				invalid = 1;
			if (s->exec.enforced_write_mask &
			    s->exec.role_conflict_mask)
				conflict = 1;
			s->exec.role_uncertain_mask |= uncertain;
			if (d->audit_unknown & FE_AUDIT_GLOBAL_SUPPRESS) {
				s->exec.global_deny_unknown = 1;
				s->exec.suppress = 1;
			}
			if (s->exec.global_deny_unknown)
				s->exec.role_uncertain_mask |=
					s->exec.role_write_mask;
			for (int i = 0; i < ER_ACTIVE; i++) {
				if (s->exec.role_uncertain_mask & (1U << i)) {
					if (s->exec.pending[i].uid)
						s->exec.pending[i].knowledge =
							ER_ROLE_UNKNOWN;
				} else if (s->exec.suppress) {
					s->exec.pending[i] = (struct er_row){};
				}
			}
#endif
			for (int i = 0; i < ER_ACTIVE; i++) {
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
				if (s->exec.known_deny_seen)
					continue;
				__u64 role =
					d->known_role_witnesses[i] ?
						d->known_role_witnesses[i] :
						d->proposed_roles[i];
#else
				if (s->exec.suppress)
					continue;
				__u64 role = d->proposed_roles[i];
#endif
				if (!role)
					continue;
				if ((__u32)i >= w->candidate.count) {
					invalid = 1;
					continue;
				}
				struct er_authority *a =
					&w->candidate.active[i];
				struct er_row *p = &s->exec.pending[i];
				if (p->uid && (p->uid != a->uid ||
					       p->epoch != a->epoch)) {
					invalid = 1;
					continue;
				}
				if (p->uid && p->role != role) {
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
					s->exec.role_conflict_mask |= 1U << i;
					s->exec.role_uncertain_mask |= 1U << i;
					p->knowledge = ER_ROLE_UNKNOWN;
					if (s->exec.enforced_write_mask &
					    (1U << i))
						conflict = 1;
#else
					conflict = 1;
#endif
					continue;
				}
				if (!p->uid)
					*p = er_known_row(a->uid, a->epoch,
							  role);
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
				if (s->exec.suppress ||
				    (s->exec.role_uncertain_mask & (1U << i)))
					p->knowledge = ER_ROLE_UNKNOWN;
#endif
			}
		}
		if (invalid || conflict) {
			s->exec.suppress = 1;
			eo_clear_pending(&s->exec);
		}
		bpf_spin_unlock(&s->lock);
	}
	eo_put_work(w);
	if (invalid) {
		eo_exec_suppress();
		eo_quarantine(s);
		eo_fault(EO_FAULT_STATE);
		return -1;
	}
	if (conflict) {
		eo_data_fault(generation, 1ULL << FE_ROLE_CONFLICT);
		return -1;
	}
	return 0;
}
/* Completion always clears owned state before the final shared count release.
 * Fexit is mandatory: kernel_execve failure does not guarantee sys_exit. */
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
static __always_inline int
eo_finish_exec(struct task_struct *task, struct linux_binprm *bprm, int success)
{
	struct eo_task *s = eo_lookup_task(task);
	struct eo_health *h = eo_status();
	struct eo_config *c = eo_config();
	if (!s || !h || !c)
		return 0;
	/* Snapshot the explicit scalar prefix; pending rows use owned work storage,
     * rather than placing a complete 336-byte transaction on the BPF stack. */
	struct {
		__u64 bprm, cgroup, generation, owner_cookie;
		__u32 owned, slot, suppress, checks;
		__u32 execution_class, role_uncertain_mask, role_write_mask;
		__u32 global_deny_unknown, known_deny_seen, policy_count;
		__u32 enforced_write_mask, role_conflict_mask;
	} tx = {};
	_Static_assert(sizeof(tx) ==
			       __builtin_offsetof(struct eo_exec_tx, pending),
		       "exec snapshot prefix");
	bpf_spin_lock(&s->lock);
	__builtin_memcpy(&tx, &s->exec, sizeof(tx));
	bpf_spin_unlock(&s->lock);
	if (!tx.owned)
		return 0;
	if ((bprm && tx.bprm != (__u64)bprm) || tx.owner_cookie != c->cookie ||
	    tx.cgroup != c->cgroup || tx.slot != c->gate_slot) {
		eo_quarantine(s);
		return 0;
	}
	__u64 *gate = eo_gate(tx.slot);
	if (!gate) {
		eo_fault(EO_FAULT_GATE);
		return 0;
	}
	int invalid = 0, changed = 0;
	struct eo_work *w = 0;
	/* A known semantic deny cancels changes deterministically, even when audit
     * let exec succeed. Failure also preserves the entire committed vector. */
	if (success && !tx.known_deny_seen) {
		w = eo_get_work();
		if (!w)
			invalid = 1;
		else {
			if (eo_load_candidate(w, 0, 0) ||
			    w->a_epoch != tx.generation ||
			    w->candidate.count != tx.policy_count ||
			    eo_validate_exec_task(s, w))
				invalid = 1;
			if (!invalid) {
				bpf_spin_lock(&s->lock);
				if (__builtin_memcmp(&tx, &s->exec, sizeof(tx)))
					invalid = 1;
				for (int i = 0; i < ER_ACTIVE; i++)
					w->source.rows[i] = s->exec.pending[i];
				bpf_spin_unlock(&s->lock);
				__u32 uncertain = tx.role_uncertain_mask |
						  (tx.global_deny_unknown ?
							   tx.role_write_mask :
							   0);
				if ((uncertain | tx.role_write_mask) >>
				    tx.policy_count)
					invalid = 1;
				for (int i = 0; i < ER_ACTIVE; i++) {
					if ((__u32)i >= tx.policy_count)
						break;
					const struct er_authority *a =
						&w->candidate.active[i];
					const struct er_row *pending =
						&w->source.rows[i];
					int unknown = !!(uncertain & (1U << i));
					if (!unknown &&
					    (tx.suppress || !pending->uid))
						continue;
					if (!unknown &&
					    (pending->uid != a->uid ||
					     pending->epoch != a->epoch ||
					     !pending->role ||
					     !er_role_known(pending))) {
						invalid = 1;
						continue;
					}
					int found = 0;
					for (int j = 0; j < ER_SLOTS; j++) {
						struct er_row *row =
							&w->merge.rows[j];
						if (row->uid != a->uid ||
						    row->epoch != a->epoch)
							continue;
						found++;
						if (unknown)
							row->knowledge =
								ER_ROLE_UNKNOWN;
						else {
							row->role =
								pending->role;
							row->knowledge =
								ER_ROLE_KNOWN;
						}
						changed = 1;
					}
					if (found != 1)
						invalid = 1;
				}
			}
		}
	}
	__u32 claimed = 0;
	bpf_spin_lock(&s->lock);
	if (s->exec.owned && s->exec.bprm == tx.bprm &&
	    s->exec.owner_cookie == tx.owner_cookie &&
	    s->exec.generation == tx.generation) {
		if (__builtin_memcmp(&tx, &s->exec, sizeof(tx)))
			invalid = 1;
		if (w && !invalid) {
			for (int i = 0; i < ER_ACTIVE; i++)
				if (__builtin_memcmp(&s->exec.pending[i],
						     &w->source.rows[i],
						     sizeof(struct er_row)))
					invalid = 1;
		}
		if (success && !tx.known_deny_seen && changed && !invalid &&
		    w) {
			if ((s->flags & EO_QUARANTINED) ||
			    h->authority_version != w->authority ||
			    er_publish(&s->committed, &w->merge, w->authority))
				invalid = 1;
		}
		eo_clear_pending(&s->exec);
		s->exec.owned = s->exec.suppress = s->exec.checks = 0;
		s->exec.bprm = 0;
		s->exec.execution_class = s->exec.policy_count = 0;
		s->exec.role_uncertain_mask = s->exec.role_write_mask = 0;
		s->exec.global_deny_unknown = s->exec.known_deny_seen = 0;
		s->exec.enforced_write_mask = s->exec.role_conflict_mask = 0;
		claimed = 1;
	}
	bpf_spin_unlock(&s->lock);
	if (w)
		eo_put_work(w);
	if (invalid) {
		eo_quarantine(s);
		eo_fault(EO_FAULT_STATE);
	}
	fg_leave_owned(gate, claimed, &h->faults);
	return 0;
}
#else
static __always_inline int
eo_finish_exec(struct task_struct *task, struct linux_binprm *bprm, int success)
{
	struct eo_task *s = eo_lookup_task(task);
	struct eo_health *h = eo_status();
	struct eo_config *c = eo_config();
	if (!s || !h || !c)
		return 0;
	__u32 owned, slot, suppress;
	__u64 identity, owner, generation, original;
	bpf_spin_lock(&s->lock);
	owned = s->exec.owned;
	slot = s->exec.slot;
	identity = s->exec.bprm;
	owner = s->exec.owner_cookie;
	generation = s->exec.generation;
	suppress = s->exec.suppress;
	original = s->exec.cgroup;
	bpf_spin_unlock(&s->lock);
	if (!owned)
		return 0;
	if ((bprm && identity != (__u64)bprm) || owner != c->cookie ||
	    original != c->cgroup || slot != c->gate_slot) {
		eo_quarantine(s);
		return 0;
	}
	__u64 *gate = eo_gate(slot);
	if (!gate) {
		eo_fault(EO_FAULT_GATE);
		return 0;
	}
	int invalid = 0;
	struct eo_work *w = 0;
	if (success && !suppress) {
		w = eo_get_work();
		if (!w)
			invalid = 1;
		else {
			if (eo_load_candidate(w, 0, 0) ||
			    w->a_epoch != generation ||
			    eo_validate_exec_task(s, w))
				invalid = 1;
			if (!invalid) {
				bpf_spin_lock(&s->lock);
				for (int i = 0; i < ER_ACTIVE; i++)
					w->source.rows[i] = s->exec.pending[i];
				bpf_spin_unlock(&s->lock);
				for (int i = 0; i < ER_ACTIVE; i++) {
					struct er_row *p = &w->source.rows[i];
					if (!p->uid)
						continue;
					int found = 0;
					for (int j = 0; j < ER_SLOTS; j++)
						if (w->merge.rows[j].uid ==
							    p->uid &&
						    w->merge.rows[j].epoch ==
							    p->epoch) {
							w->merge.rows[j].role =
								p->role;
							found++;
						}
					if (found != 1 || !p->role)
						invalid = 1;
				}
			}
		}
	}
	__u32 claimed = 0;
	bpf_spin_lock(&s->lock);
	if (s->exec.owned && s->exec.bprm == identity &&
	    s->exec.owner_cookie == owner) {
		if (success && !s->exec.suppress && !invalid && w) {
			if ((s->flags & EO_QUARANTINED) ||
			    h->authority_version != w->authority ||
			    er_publish(&s->committed, &w->merge, w->authority))
				invalid = 1;
		}
		eo_clear_pending(&s->exec);
		s->exec.bprm = 0;
		s->exec.owned = 0;
		s->exec.suppress = 0;
		s->exec.checks = 0;
		claimed = 1;
	}
	bpf_spin_unlock(&s->lock);
	if (w)
		eo_put_work(w);
	if (invalid) {
		eo_quarantine(s);
		eo_fault(EO_FAULT_STATE);
	}
	fg_leave_owned(gate, claimed, &h->faults);
	return 0;
}
#endif
static __always_inline __u64 eo_task_cgroup(struct task_struct *task)
{
	__u64 id = 0;
	if (BPF_CORE_READ_INTO(&id, task, cgroups, dfl_cgrp, kn, id))
		return 0;
	return id;
}
/* No lookup/write follows a counted fork's final release. The owner identity
 * and gate slot are the original admission's, never the completion's cgroup. */
static __always_inline int
eo_release_fork(struct eo_task *p, struct task_struct *child, int failed)
{
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || !p)
		return 0;
	__u32 slot, owned;
	__u64 owner, identity, original;
	bpf_spin_lock(&p->lock);
	slot = p->fork.slot;
	owned = p->fork.owned;
	owner = p->fork.owner_cookie;
	identity = p->fork.child;
	original = p->fork.cgroup;
	bpf_spin_unlock(&p->lock);
	if (!owned)
		return 0;
	if (owner != c->cookie || original != c->cgroup ||
	    slot != c->gate_slot || (!failed && identity != (__u64)child)) {
		eo_quarantine(p);
		return 0;
	}
	__u64 *gate = eo_gate(slot);
	if (!gate) {
		eo_fault(EO_FAULT_GATE);
		return 0;
	}
	__u32 claimed = 0;
	bpf_spin_lock(&p->lock);
	if (p->fork.owned && p->fork.owner_cookie == owner &&
	    p->fork.child == identity) {
		p->fork.owned = 0;
		p->fork.child = 0;
		claimed = 1;
	}
	bpf_spin_unlock(&p->lock);
	fg_leave_owned(gate, claimed, &h->faults);
	return 0;
}
SEC("lsm.s/task_alloc")
int BPF_PROG(eo_task_alloc, struct task_struct *child, __u64 clone_flags,
	     int ret)
{
	if (ret)
		return ret;
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || !c->cookie || c->abi != EO_ABI || h->retired ||
	    bpf_get_current_cgroup_id() != c->cgroup)
		return 0;
	if (h->faults)
		return -1;
	__u64 *gate = eo_gate(c->gate_slot);
	if (!gate)
		return -1;
	if (fg_enter(gate)) {
		__sync_fetch_and_add(&h->gate_denials, 1);
		return -11;
	}
	struct task_struct *parent = bpf_get_current_task_btf();
	struct eo_task *p = eo_get_task(parent);
	if (!p) {
		eo_fault(EO_FAULT_STORAGE);
		fg_leave_owned(gate, 1, &h->faults);
		return -1;
	}
	int collision = 0;
	bpf_spin_lock(&p->lock);
	if (p->fork.owned)
		collision = 1;
	else
		p->fork = (struct eo_fork_tx){ (__u64)child, c->cgroup,
					       c->cookie, 1, c->gate_slot };
	bpf_spin_unlock(&p->lock);
	if (collision) {
		eo_fault(EO_FAULT_STATE);
		fg_leave_owned(gate, 1, &h->faults);
		return -1;
	}
	/* Accepted state is required after activation; lack of a role never roots it.
  * Initial observation before root authorization records births only. */
	if (clone_flags & (1ULL << 33)) {
		__sync_fetch_and_add(&h->gate_denials, 1);
		return -1;
	}
	if (h->active_generation) {
		struct eo_work *w = eo_get_work();
		int invalid = !w;
		if (w) {
			invalid = eo_load_candidate(w, 0, 0) ||
				  eo_validate_task(p, w);
			eo_put_work(w);
		}
		if (invalid) {
			eo_quarantine(p);
			return -1;
		}
	}
	return 0;
}
SEC("tp_btf/task_newtask")
int BPF_PROG(eo_task_newtask, struct task_struct *child, __u64 clone_flags)
{
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || !c->cookie || c->abi != EO_ABI || h->retired)
		return 0;
	struct task_struct *parent = bpf_get_current_task_btf();
	struct eo_task *p = eo_lookup_task(parent);
	__u32 owned = 0;
	__u64 original = 0, owner = 0, identity = 0;
	if (p) {
		bpf_spin_lock(&p->lock);
		owned = p->fork.owned;
		original = p->fork.cgroup;
		owner = p->fork.owner_cookie;
		identity = p->fork.child;
		bpf_spin_unlock(&p->lock);
	}
	__u64 target = eo_task_cgroup(child),
	      current = bpf_get_current_cgroup_id();
	if (!owned && target != c->cgroup && current != c->cgroup)
		return 0;
	if (owned && (owner != c->cookie || original != c->cgroup ||
		      identity != (__u64)child)) {
		eo_quarantine(p);
		return 0;
	}
	__u32 observing = eo_credit(&h->pending_births, EO_TASKS) != 0;
	if (!observing) {
		eo_fault(EO_FAULT_CAPACITY);
		return eo_release_fork(p, child, 0);
	}
	struct eo_task *s = eo_get_task(child);
	if (!s) {
		eo_fault(EO_FAULT_STORAGE);
		goto release;
	}
	if (!p)
		p = eo_get_task(parent);
	if (!p) {
		eo_quarantine(s);
		goto release;
	}
	if (target != c->cgroup || current != c->cgroup ||
	    (clone_flags & (1ULL << 33))) {
		eo_quarantine(s);
		goto release;
	}
	/* A post-activation uncounted success is unknown ingress, never a late root. */
	if (!owned && h->active_generation) {
		eo_quarantine(s);
		goto release;
	}
	struct eo_phase *phase = eo_phase_state();
	if (!phase || phase->state == EO_PUBLISHING ||
	    phase->state == EO_STOPPED) {
		eo_quarantine(s);
		goto release;
	}
	__u64 creator = eo_group(parent);
	struct eo_anchor *anchor = eo_root();
	if (!anchor || !anchor->group) {
		if (!creator ||
		    bpf_map_update_elem(&eo_birth_groups, &s->cookie, &creator,
					BPF_NOEXIST)) {
			eo_quarantine(s);
			goto release;
		}
		int overflow = 0;
		bpf_spin_lock(&s->lock);
		if (!(s->flags & EO_PENDING_BIRTH)) {
			if (s->committed.version >= ER_UNKNOWN - 1)
				overflow = 1;
			else {
				s->flags |= EO_PENDING_BIRTH;
				s->committed.version++;
			}
		}
		bpf_spin_unlock(&s->lock);
		if (overflow) {
			eo_fault(EO_FAULT_VERSION);
			eo_quarantine(s);
		}
		goto release;
	}
	if (!eo_lineage(parent, p)) {
		eo_quarantine(s);
		goto release;
	}
	struct eo_work *w = eo_get_work();
	if (!w) {
		eo_quarantine(s);
		goto release;
	}
	__u32 slot = 0, mask = 0;
	if (!h->active_generation) {
		if ((phase->state != EO_STAGING &&
		     phase->state != EO_VALIDATED) ||
		    !phase->candidate_generation || !phase->new_uid_mask) {
			eo_put_work(w);
			eo_quarantine(s);
			goto release;
		}
		slot = 1;
		mask = phase->new_uid_mask;
	}
	int invalid = eo_load_candidate(w, slot, mask);
	if (!invalid && slot == 1 && w->a_epoch != phase->candidate_generation)
		invalid = 1;
	if (!invalid) {
		bpf_spin_lock(&p->lock);
		w->source = p->committed;
		w->source_flags = p->flags;
		bpf_spin_unlock(&p->lock);
		if (!(w->source_flags & EO_VERIFIED) ||
		    (w->source_flags & EO_QUARANTINED))
			invalid = 1;
	}
	if (!invalid) {
		bpf_spin_lock(&s->lock);
		er_snapshot(&w->merge, &s->committed, w->authority);
		bpf_spin_unlock(&s->lock);
		invalid = er_inherit(&w->merge, &w->candidate, w->source.rows);
		if (!invalid &&
		    (h->active_generation || h->a_complete == w->a_epoch)) {
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
			invalid = h->active_generation ? eo_rows_present(w) :
							 eo_rows_complete(w);
#else
			invalid = eo_rows_complete(w);
#endif
		}
	}
	if (!invalid) {
		bpf_spin_lock(&s->lock);
		if ((s->flags & EO_QUARANTINED) ||
		    h->authority_version != w->authority ||
		    er_publish(&s->committed, &w->merge, w->authority))
			invalid = 1;
		else {
			s->flags |= EO_VERIFIED;
			s->flags &= ~EO_PENDING_BIRTH;
		}
		bpf_spin_unlock(&s->lock);
	}
	eo_put_work(w);
	if (invalid)
		eo_quarantine(s);
release:
	if (observing)
		__sync_fetch_and_sub(&h->pending_births, 1);
	return eo_release_fork(p, child, 0);
}
SEC("fexit/copy_process")
int BPF_PROG(eo_copy_process_exit, struct pid *pid, int trace, int node,
	     struct kernel_clone_args *args, struct task_struct *result)
{
	if ((__u64)result < ~4094ULL)
		return 0;
	struct eo_task *p = eo_lookup_task(bpf_get_current_task_btf());
	return eo_release_fork(p, 0, 1);
}
SEC("tp_btf/sched_process_exec")
int BPF_PROG(eo_sched_exec, struct task_struct *task, int old_pid,
	     struct linux_binprm *bprm)
{
	return eo_finish_exec(task, bprm, 1);
}
SEC("fexit/bprm_execve")
int BPF_PROG(eo_bprm_exit, struct linux_binprm *bprm, int ret)
{
	return eo_finish_exec(bpf_get_current_task_btf(), bprm, 0);
}
SEC("tp_btf/sched_process_exit")
int BPF_PROG(eo_task_exit, struct task_struct *task)
{
	/* Fork cleanup precedes exec cleanup. A task cannot be running exec while
  * copy_process is still active; both fallbacks nevertheless remain bounded. */
	struct eo_task *s = eo_lookup_task(task);
	eo_release_fork(s, 0, 1);
	return eo_finish_exec(task, 0, 0);
}
#endif
