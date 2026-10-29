/* SPDX-License-Identifier: GPL-2.0 */
#ifndef FULL_EPOCH_ROLES_H
#define FULL_EPOCH_ROLES_H

/* Work-copy scalar-role merge only: no task storage, pending grants, lineage
 * discovery or activation owner. ER_ACCEPTED_EPOCH(uid) must read a COMPLETE,
 * immutable successful-activation catalogue, including removed policies.
 * Zero means proven never activated, NOT missing/unknown evidence. The owner
 * must supply ER_UNKNOWN for an unavailable catalogue/failed lookup. Epochs
 * cannot equal ER_UNKNOWN. Candidate and catalogue snapshots must remain fixed
 * throughout a merge and their version must be checked at publication. */
#ifndef ER_ACCEPTED_EPOCH
#error "define ER_ACCEPTED_EPOCH(uid) using trusted successful history"
#endif
#define ER_SLOTS 16
#define ER_ACTIVE 8
#define ER_UNKNOWN (~(__u64)0)
#define ER_INVALID (-1)
#define ER_CAPACITY (-2)
#define ER_LINEAGE (-3)
#define ER_STALE (-4)
#ifndef ER_INLINE
#define ER_INLINE static __inline __attribute__((always_inline))
#endif

struct er_row {
	__u64 uid, epoch, role;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	__u32 knowledge, reserved;
#endif
};
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
enum { ER_ROLE_EMPTY = 0, ER_ROLE_KNOWN = 1, ER_ROLE_UNKNOWN = 2 };
_Static_assert(sizeof(struct er_row) == 32, "development role ABI");
#else
_Static_assert(sizeof(struct er_row) == 24, "ABI2 role ABI");
#endif
ER_INLINE struct er_row er_known_row(__u64 uid, __u64 epoch, __u64 role)
{
	struct er_row row = { .uid = uid, .epoch = epoch, .role = role };
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	row.knowledge = ER_ROLE_KNOWN;
#endif
	return row;
}
ER_INLINE int er_role_known(const struct er_row *row)
{
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	return row->knowledge == ER_ROLE_KNOWN && row->reserved == 0;
#else
	return row->role != 0;
#endif
}
struct er_authority {
	__u64 uid, epoch, root;
	__u32 new_uid, reserved;
};
struct er_candidate {
	__u32 count, reserved;
	struct er_authority active[ER_ACTIVE];
};
struct er_state {
	__u64 version;
	struct er_row rows[ER_SLOTS];
};
struct er_work {
	__u64 base_version, authority_version;
	int error;
	__u32 prepared;
	struct er_row rows[ER_SLOTS];
};

/* Snapshot under the state lock. authority_version is a nonzero, never-reused
 * owner version covering BOTH candidate and successful history. Do not call
 * any merge/lookup function under the state lock. */
ER_INLINE void er_snapshot(struct er_work *w, const struct er_state *state,
			   __u64 authority_version)
{
	w->base_version = state->version;
	w->authority_version = authority_version;
	w->error = authority_version ? 0 : ER_INVALID;
	w->prepared = 0;
	for (int i = 0; i < ER_SLOTS; i++)
		w->rows[i] = state->rows[i];
}
ER_INLINE int er_fail(struct er_work *w, int error)
{
	if (!w->error)
		w->error = error;
	return w->error;
}
ER_INLINE int er_candidate_valid(const struct er_candidate *c)
{
	if (c->count > ER_ACTIVE || c->reserved)
		return ER_INVALID;
		/* Keep this fixed eight-row validator out of the surrounding loop SCC.
     * The pinned verifier otherwise carries its scalar induction register into
     * the following rows loop after LLVM reuses it for a map-value pointer. */
#ifdef __BPF__
#pragma clang loop unroll(full)
#endif
	for (int i = 0; i < ER_ACTIVE; i++) {
		const struct er_authority *a = &c->active[i];
		if ((__u32)i >= c->count) {
			if (a->uid || a->epoch || a->root || a->new_uid ||
			    a->reserved)
				return ER_INVALID;
			continue;
		}
		if (!a->uid || !a->epoch || a->epoch == ER_UNKNOWN ||
		    !a->root || a->new_uid > 1 || a->reserved)
			return ER_INVALID;
		for (int j = 0; j < ER_ACTIVE; j++)
			if (j < i && c->active[j].uid == a->uid)
				return ER_INVALID;
		__u64 er_accepted = ER_ACCEPTED_EPOCH(a->uid);
		if (er_accepted == ER_UNKNOWN ||
		    (a->new_uid ? er_accepted != 0 : er_accepted != a->epoch))
			return ER_INVALID;
	}
	return 0;
}
/* 1 accepted, 2 current staged root, 0 proven stale never-activated row.
 * A mismatched accepted epoch is corruption, never a reason to re-root. */
ER_INLINE int er_row_kind(const struct er_row *r, const struct er_candidate *c)
{
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	if (!r->uid)
		return (r->epoch || r->role || r->knowledge || r->reserved) ?
			       ER_INVALID :
			       0;
	if (r->reserved ||
	    (r->knowledge != ER_ROLE_KNOWN && r->knowledge != ER_ROLE_UNKNOWN))
		return ER_INVALID;
#else
	if (!r->uid)
		return (r->epoch || r->role) ? ER_INVALID : 0;
#endif
	if (!r->epoch || r->epoch == ER_UNKNOWN || !r->role)
		return ER_INVALID;
	__u64 er_accepted = ER_ACCEPTED_EPOCH(r->uid);
	if (er_accepted == ER_UNKNOWN)
		return ER_INVALID;
	if (er_accepted)
		return er_accepted == r->epoch ? 1 : ER_INVALID;
	for (int i = 0; i < ER_ACTIVE; i++) {
		if ((__u32)i >= c->count)
			break;
		const struct er_authority *a = &c->active[i];
		if (a->uid == r->uid && a->epoch == r->epoch)
			return a->new_uid && a->root == r->role &&
					       er_role_known(r) ?
				       2 :
				       ER_INVALID;
	}
	return 0;
}
ER_INLINE int er_rows_valid(const struct er_row *rows,
			    const struct er_candidate *c)
{
	for (int i = 0; i < ER_SLOTS; i++) {
		if (er_row_kind(&rows[i], c) < 0)
			return ER_INVALID;
		if (!rows[i].uid)
			continue;
		for (int j = 0; j < ER_SLOTS; j++)
			if (j < i && rows[j].uid == rows[i].uid)
				return ER_INVALID;
	}
	return 0;
}
ER_INLINE int er_prepare(struct er_work *w, const struct er_candidate *c)
{
	if (w->error)
		return w->error;
	if (er_candidate_valid(c) || er_rows_valid(w->rows, c))
		return er_fail(w, ER_INVALID);
	for (int i = 0; i < ER_SLOTS; i++) {
		if (er_row_kind(&w->rows[i], c) == 0)
			w->rows[i] = (struct er_row){};
	}
	w->prepared = 1;
	return 0;
}
ER_INLINE int er_insert(struct er_work *w, struct er_row row)
{
	int vacant = -1;
	for (int i = 0; i < ER_SLOTS; i++) {
		if (w->rows[i].uid == row.uid) {
			/* Existing accepted role wins; incoming state never overwrites it. */
			return w->rows[i].epoch == row.epoch ?
				       0 :
				       er_fail(w, ER_INVALID);
		}
		if (!w->rows[i].uid && vacant < 0)
			vacant = i;
	}
	if (vacant < 0 || vacant >= ER_SLOTS)
		return er_fail(w, ER_CAPACITY);
	w->rows[vacant] = row;
	return 0;
}
/* lineage_verified must be the caller's explicit kernel-verified decision,
 * never cgroup membership, absent state or a userspace seed assertion.
 * Only new UIDs receive roots. Accepted UIDs missing a row remain missing. */
ER_INLINE int er_stage_roots(struct er_work *w, const struct er_candidate *c,
			     int lineage_verified)
{
	if (w->error)
		return w->error;
	if (lineage_verified != 1)
		return er_fail(w, ER_LINEAGE);
	if (er_prepare(w, c))
		return w->error;
	for (int i = 0; i < ER_ACTIVE; i++) {
		if ((__u32)i >= c->count)
			break;
		const struct er_authority *a = &c->active[i];
		if (a->new_uid &&
		    er_insert(w, er_known_row(a->uid, a->epoch, a->root)))
			return w->error;
	}
	return 0;
}
/* source must be a coherent committed/staged-root snapshot, never pending exec
 * grants. Current-new staged roots are inherited only while exactly authorized
 * by the same immutable candidate. Caller must validate creator lineage. */
ER_INLINE int er_inherit(struct er_work *w, const struct er_candidate *c,
			 const struct er_row source[ER_SLOTS])
{
	if (w->error)
		return w->error;
	if (er_prepare(w, c) || er_rows_valid(source, c))
		return er_fail(w, ER_INVALID);
	for (int i = 0; i < ER_SLOTS; i++) {
		int kind = er_row_kind(&source[i], c);
		if (kind > 0 && er_insert(w, source[i]))
			return w->error;
	}
	return 0;
}
/* Publish ONLY under the destination state lock, after owner authority/version
 * synchronization. No map lookups, helper calls, allocation or nested locks.
 * Every other writer MUST increment state.version; no wrap or version reuse.
 * A failed/partial work copy is never published. Snapshot/merge/publish callers
 * must not mutate work.rows except through this API; this is not a hostile-input
 * validator. It cannot by itself establish source lineage or catalogue trust. */
ER_INLINE int er_publish(struct er_state *state, const struct er_work *w,
			 __u64 authority_version)
{
	if (w->error)
		return w->error;
	if (!w->prepared || !authority_version ||
	    w->authority_version != authority_version ||
	    w->base_version != state->version || state->version == ER_UNKNOWN)
		return ER_STALE;
	for (int i = 0; i < ER_SLOTS; i++)
		state->rows[i] = w->rows[i];
	state->version++;
	return 0;
}
#endif
