/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_ROUTE_H
#define ENFORCE_EXEC_SHARED_ROUTE_H
#include "shared_snapshot.h"
/* Accepted-epoch catalogue key shared by route publication and the legacy
 * kernel adapter. Keep it independent of either storage implementation. */
struct se_epoch_key {
	__u64 scope, uid;
};
#define SE_ROUTE_FREE 0
#define SE_ROUTE_PREPARING 1
#define SE_ROUTE_ACTIVE 2
#define SE_ROUTE_WITHDRAWN 3
#define SE_ROUTE_UNSELECTED 0
#define SE_ROUTE_OWNED 1
#define SE_ROUTE_AUDIT_FAULT 2
#define SE_ROUTE_STRICT_FAULT 3
#define SE_ROUTE_INVARIANT_FAULT 4

/* Fixed ARRAY storage, never a borrowed/recyclable HASH value. This lock is
 * the SOLE authority for the associated snapshot payload, including commands.
 * The legacy se_shared_binding.lock must not also govern this payload.
 * cgroup_identity is a lifetime-pinned physical identity, not a recycled ID.
 */
struct se_route_anchor {
	struct bpf_spin_lock lock;
	__u32 incarnation;
	__u64 cgroup_identity, scope, payload_generation, active_serial,
		admission_serial;
	__u32 payload_slot, active_record, execution_class, phase, early_claims,
		reserved;
	__u32 tasks_used, scratch_used, inode_refs, inode_reserved;
#ifdef ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE
	/* Physical-source lifetime, independent of evaluation/reader lifetime.
	 * The fixed anchor and these fields remain under the original route lock.
	 * No timeout or controller assertion may clear unresolved_sources. */
	__u64 next_source_pin;
	__u32 source_pins, unresolved_sources;
#endif
};
#ifdef ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE
/* This is a publication barrier, not evaluation, role or cleanup authority.
 * The adapter selects owner from protected, source-owned physical-exec state;
 * neither a copied owner nor caller-supplied token establishes that identity.
 * All owner accesses, including consumption, use the SAME original route lock.
 * source_sequence distinguishes physical execs even if task/bprm addresses
 * recur. The source must retain that identity until its actual terminal. */
struct se_source_mode_token {
	__u64 scope, generation, physical, source_sequence, pin_sequence;
	__u32 slot, incarnation, execution_class, reserved;
};
struct se_source_mode_owner {
	struct se_source_mode_token token;
	__u32 owned, reserved;
};
#endif
/* Only this aligned scalar is published in the cgroup locator HASH. Adapter
 * publication/copy uses a single atomic u64 access; no class lives in it.
 * Incarnation is bounded u32 and never wraps, including after recycle.
 */
static inline __u64 se_route_locator(__u32 slot, __u32 incarnation)
{
	return ((__u64)incarnation << 32) | slot;
}
/* Stack-local, nonexported ownership of ONE synchronous kernel invocation.
 * Never accept this from a command, retained scratch, or another invocation.
 * Transfer consumes it before returning; persistent replay protection belongs
 * to the designated task/invocation se_reader_owner, not a copied stack token.
 */
struct se_route_claim {
	__u64 scope, serial, generation, admission_serial;
	__u32 incarnation, record, execution_class, owned, slot, reserved;
};
/* This transition runs under the route spinlock. Keep its call boundary
 * lexical: stock Rocky 4.18 rejects BPF-to-BPF calls while locked. */
static __attribute__((always_inline)) inline int
se_route_open_locked(struct se_route_anchor *a, __u64 cgroup,
		     __u64 scope, __u32 slot)
{
	if (a->phase != SE_ROUTE_FREE || a->early_claims || a->reserved ||
#ifdef ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE
	    a->source_pins || a->unresolved_sources ||
#endif
	    a->inode_refs || a->inode_reserved || !cgroup || !scope ||
	    scope == ~0ULL || a->incarnation == (__u32)~0U)
		return -1;
	a->incarnation++;
	a->cgroup_identity = cgroup;
	a->scope = scope;
	a->payload_slot = slot;
	a->phase = SE_ROUTE_PREPARING;
	return 0;
}
/* Complete route/snapshot preflight BEFORE any accepted-epoch stores. The
 * adapter must additionally validate factual targets and qualification under
 * this same lock. No lookup/task lock/fallible operation may follow first store.
 */
static __attribute__((always_inline)) inline int
se_route_commit_preflight_locked(struct se_route_anchor *a,
				 struct se_binding_snapshots *b, __u32 record,
				 __u64 serial, __u64 qualification)
{
	if ((a->phase != SE_ROUTE_PREPARING && a->phase != SE_ROUTE_ACTIVE) ||
#ifdef ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE
	    a->source_pins || a->unresolved_sources ||
#endif
	    a->early_claims || a->reserved || b->scope != a->scope ||
	    a->payload_generation != b->generation ||
	    a->active_serial != b->active_serial ||
	    (a->active_serial && a->active_record != b->active_record) ||
	    a->admission_serial != qualification ||
	    a->admission_serial >= ~0ULL - 1)
		return -1;
	return se_binding_commit_preflight_locked(
		b, record, serial, b->generation, b->admission_serial);
}
/* Infallible SAME-lock continuation of the above preflight, after all
 * prevalidated accepted-epoch stores. No reference-count transfer. */
static __attribute__((always_inline)) inline void
se_route_commit_publish_locked(struct se_route_anchor *a,
			       struct se_binding_snapshots *b, __u32 record)
{
	se_binding_commit_publish_locked(b, record);
	const struct se_snapshot *s = &b->records[record];
	a->payload_generation = b->generation;
	a->active_serial = s->serial;
	a->active_record = record;
	a->execution_class = s->execution_class;
	a->phase = SE_ROUTE_ACTIVE;
	a->admission_serial++;
}
/* Anchor lock held BEFORE any fallible payload/task/scratch lookup. A stale
 * locator is unselected at withdrawal; its class is never used. The fixed
 * ARRAY lookup is nonfallible only under admitted index/map-lifetime premises.
 * Overflow returns a terminal scalar from the CURRENT locked class, no tuple.
 * The exec adapter may first recover an already-owned ORIGINAL exec reader;
 * that identity-only recovery never observes under this unowned current tuple.
 */
/* This is called with the route spinlock held. Older supported kernels do
 * not permit a BPF-to-BPF call from that lock region. */
static __attribute__((always_inline)) inline int se_route_claim_locked(
					struct se_route_anchor *a,
					__u64 locator, __u64 cgroup,
					struct se_route_claim *c)
{
	if ((__u32)locator != a->payload_slot ||
	    (__u32)(locator >> 32) != a->incarnation || !a->incarnation ||
	    a->cgroup_identity != cgroup || a->phase != SE_ROUTE_ACTIVE)
		return SE_ROUTE_UNSELECTED;
	if (a->execution_class < 1 || a->execution_class > 2)
		return SE_ROUTE_INVARIANT_FAULT; /* inadmissible class invariant violation */
	if (c->owned || a->reserved || a->early_claims == (__u32)~0U ||
	    a->admission_serial >= ~0ULL - 1)
		return a->execution_class == 1 ? SE_ROUTE_AUDIT_FAULT :
						 SE_ROUTE_STRICT_FAULT;
	a->early_claims++;
	a->admission_serial++;
	*c = (struct se_route_claim){ .scope = a->scope,
				      .serial = a->active_serial,
				      .generation = a->payload_generation,
				      .admission_serial = a->admission_serial,
				      .incarnation = a->incarnation,
				      .record = a->active_record,
				      .execution_class = a->execution_class,
				      .owned = 1,
				      .slot = a->payload_slot };
	return SE_ROUTE_OWNED;
}
static __attribute__((always_inline)) inline int
se_route_claim_valid(const struct se_route_anchor *a,
				       const struct se_route_claim *c)
{
	return c->owned && !c->reserved && c->slot == a->payload_slot &&
	       a->phase == SE_ROUTE_ACTIVE && a->early_claims &&
	       a->incarnation == c->incarnation && a->scope == c->scope &&
	       a->active_serial == c->serial &&
	       a->payload_generation == c->generation &&
	       a->active_record == c->record &&
	       a->execution_class == c->execution_class;
}
#ifdef ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE
/* Establish protection BEFORE consuming the lexical claim or releasing the
 * final reader. The source binds owner to its protected physical-exec header
 * before returning from this same locked region; no unprotected handoff is
 * permitted. This does not consume the ordinary route claim. */
static __attribute__((always_inline)) inline int
se_route_source_pin_acquire_locked(struct se_route_anchor *a,
	const struct se_route_claim *claim, __u64 physical, __u64 source_sequence,
	struct se_source_mode_owner *owner, struct se_source_mode_token *token)
{
	if (!owner || !token || owner->owned || owner->reserved ||
	    !physical || !source_sequence || source_sequence == ~0ULL ||
	    !se_route_claim_valid(a, claim) || a->reserved ||
	    claim->owned != 1 || !claim->incarnation || !claim->scope ||
	    !claim->generation || claim->execution_class < 1 ||
	    claim->execution_class > 2 ||
	    a->source_pins == (__u32)~0U || a->next_source_pin >= ~0ULL - 1)
		return -1;
	struct se_source_mode_token next = {
		.scope = claim->scope, .generation = claim->generation,
		.physical = physical, .source_sequence = source_sequence,
		.pin_sequence = ++a->next_source_pin, .slot = claim->slot,
		.incarnation = claim->incarnation,
		.execution_class = claim->execution_class,
	};
	a->source_pins++;
	owner->token = next;
	owner->owned = 1;
	*token = next;
	return 0;
}
/* Only an actual source terminal holding the original protected owner may
 * consume this barrier. A copied token is merely an equality check. The caller
 * authenticates physical/source_sequence from that physical-exec lifetime,
 * never from current routing or userspace. Duplicate release cannot consume a
 * newer pin stored in the reused owner. Admission/record serials deliberately
 * do not participate: ordinary admission changes them while a source is live. */
static __attribute__((always_inline)) inline int
se_route_source_pin_release_locked(struct se_route_anchor *a,
	struct se_source_mode_owner *owner, const struct se_source_mode_token *token,
	__u64 physical, __u64 source_sequence)
{
	if (!owner || !token || owner->owned != 1 || owner->reserved ||
	    token->reserved || !physical || !source_sequence ||
	    token->physical != physical || token->source_sequence != source_sequence ||
	    !token->pin_sequence || token->pin_sequence > a->next_source_pin ||
	    !a->source_pins || a->phase != SE_ROUTE_ACTIVE || a->reserved ||
	    token->slot != a->payload_slot || token->incarnation != a->incarnation ||
	    token->scope != a->scope || token->generation != a->payload_generation ||
	    token->execution_class < 1 || token->execution_class > 2 ||
	    token->execution_class != a->execution_class ||
	    owner->token.scope != token->scope ||
	    owner->token.generation != token->generation ||
	    owner->token.physical != token->physical ||
	    owner->token.source_sequence != token->source_sequence ||
	    owner->token.pin_sequence != token->pin_sequence ||
	    owner->token.slot != token->slot ||
	    owner->token.incarnation != token->incarnation ||
	    owner->token.execution_class != token->execution_class ||
	    owner->token.reserved)
		return -1;
	owner->owned = 0;
	a->source_pins--;
	return 0;
}
/* If the source cannot publish exact physical-exec bookkeeping, latch its
 * original route while the lexical claim still protects it. Repeated failures
 * use constant storage. Ordinary exec admission remains unchanged; only
 * publication/withdrawal/reuse is stopped. There is intentionally no clear API:
 * missing receipts, elapsed time and zero WORK counts do not prove a drain. */
static __attribute__((always_inline)) inline int
se_route_source_latch_locked(struct se_route_anchor *a,
	const struct se_route_claim *claim)
{
	if (!se_route_claim_valid(a, claim))
		return -1;
	a->unresolved_sources = 1;
	return 0;
}
/* Later admission of the SAME physical exec after its original class was
 * frozen. The caller has authenticated physical/source_sequence from its
 * protected source capsule; the protected owner under this same original route
 * lock is the only key. The current cgroup and locator never participate, so a
 * migrated exec keeps its original route. While the pin is held, publication
 * and withdrawal are refused, so payload generation and active record cannot
 * change. Any mismatch is a fault of the ORIGINAL frozen class, never the
 * class of whichever route the task currently occupies. */
static __attribute__((always_inline)) inline int
se_route_claim_source_locked(struct se_route_anchor *a,
	const struct se_source_mode_owner *owner, __u64 physical,
	__u64 source_sequence, __u32 frozen_class, struct se_route_claim *c)
{
	if (frozen_class < 1 || frozen_class > 2)
		return SE_ROUTE_INVARIANT_FAULT;
	const struct se_source_mode_token *t = &owner->token;
	if (c->owned || owner->owned != 1 || owner->reserved || t->reserved ||
	    !physical || !source_sequence || t->physical != physical ||
	    t->source_sequence != source_sequence ||
	    t->execution_class != frozen_class || !t->pin_sequence ||
	    t->pin_sequence > a->next_source_pin || !a->source_pins ||
	    a->phase != SE_ROUTE_ACTIVE || a->reserved || !a->incarnation ||
	    t->slot != a->payload_slot || t->incarnation != a->incarnation ||
	    t->scope != a->scope || t->generation != a->payload_generation ||
	    a->execution_class != frozen_class ||
	    a->early_claims == (__u32)~0U || a->admission_serial >= ~0ULL - 1)
		return frozen_class == 1 ? SE_ROUTE_AUDIT_FAULT :
					   SE_ROUTE_STRICT_FAULT;
	a->early_claims++;
	a->admission_serial++;
	*c = (struct se_route_claim){ .scope = a->scope,
				      .serial = a->active_serial,
				      .generation = a->payload_generation,
				      .admission_serial = a->admission_serial,
				      .incarnation = a->incarnation,
				      .record = a->active_record,
				      .execution_class = a->execution_class,
				      .owned = 1,
				      .slot = a->payload_slot };
	return SE_ROUTE_OWNED;
}
#endif
/* Final payload read precedes release. Failed lookup uses the owned class and
 * releases this lexical claim, never another persistent interpreter claim. */
static __attribute__((always_inline)) inline int se_route_release_locked(
					  struct se_route_anchor *a,
					  struct se_route_claim *c)
{
	if (!se_route_claim_valid(a, c))
		return -1;
	c->owned = 0;
	a->early_claims--;
	return 0;
}
/* No zero-count gap: persistent snapshot ownership is established BEFORE the
 * early count is consumed, under the SAME anchor lock. No task lock nesting.
 * owner must be selected by physical invocation identity, never command input.
 */
static __attribute__((always_inline)) inline int se_route_transfer_locked(
	struct se_route_anchor *a, struct se_binding_snapshots *b,
	struct se_route_claim *c, __u64 task_cookie,
	struct se_reader_owner *owner, struct se_reader_token *token)
{
	if (!se_route_claim_valid(a, c) || b->generation != c->generation ||
	    b->scope != c->scope || b->active_record != c->record ||
	    b->active_serial != c->serial)
		return -1;
	if (se_reader_acquire_record_locked(b, c->record, c->serial, c->scope,
					    task_cookie, owner, token))
		return -1;
	c->owned = 0;
	a->early_claims--;
	return 0;
}
static __attribute__((always_inline)) inline int se_route_withdraw_locked(struct se_route_anchor *a,
					   struct se_binding_snapshots *b)
{
	if (a->phase != SE_ROUTE_ACTIVE || a->early_claims ||
#ifdef ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE
	    a->source_pins || a->unresolved_sources ||
#endif
	    a->scope != b->scope || a->payload_generation != b->generation ||
	    a->active_serial != b->active_serial ||
	    a->admission_serial >= ~0ULL - 1 ||
	    se_binding_withdraw_preflight_locked(b, b->generation,
						 b->admission_serial))
		return -1;
	se_binding_withdraw_publish_locked(b);
	a->phase = SE_ROUTE_WITHDRAWN;
	a->admission_serial++;
	return 0;
}
/* Only AFTER actual locator unlink and all outside-lock command/cleanup access
 * has joined. Adapter owns that proof; a user-provided boolean is not evidence.
 * No helper, map delete, task lock or fallible call occurs in this block. */
static __attribute__((always_inline)) inline int
se_route_recycle_locked(struct se_route_anchor *a,
					  const struct se_binding_snapshots *b)
{
	if (a->phase != SE_ROUTE_WITHDRAWN || a->early_claims || a->reserved ||
#ifdef ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE
	    a->source_pins || a->unresolved_sources ||
#endif
	    a->tasks_used || a->scratch_used || a->inode_refs ||
	    a->inode_reserved || b->scope != a->scope || b->active_serial ||
	    b->inflight)
		return -1;
	for (__u32 i = 0; i < 2; i++)
		if (b->records[i].phase != SE_SNAPSHOT_FREE ||
		    b->records[i].claims || b->records[i].commands)
			return -1;
	a->cgroup_identity = 0;
	a->scope = 0;
	a->payload_generation = 0;
	a->active_serial = 0;
	a->payload_slot = 0;
	a->active_record = 0;
	a->execution_class = 0;
	a->phase = SE_ROUTE_FREE;
	return 0;
}
/* Actual adapter entry. The HASH borrow ends after ONE aligned atomic scalar
 * copy. Stable ARRAY storage and the pinned current-cgroup identity must outlive
 * this call. Valid locator indices cannot fail the admitted ARRAY lookup.
 * This lexical claim must be consumed in the same invocation on EVERY path.
 */
#ifdef SE_ROUTE_INDEX_LOOKUP
#ifndef SE_ROUTE_AFTER_LOCATOR_COPY
#define SE_ROUTE_AFTER_LOCATOR_COPY() \
	do {                          \
	} while (0)
#endif
static inline int se_route_admit(__u64 cgroup, struct se_route_claim *claim)
{
	const __u64 *entry = SE_ROUTE_INDEX_LOOKUP(&cgroup);
	if (!entry)
		return SE_ROUTE_UNSELECTED;
#ifdef __bpf__
	/* Clang21 BPF does not lower C11 AtomicLoad; cmpxchg(0,0) is the
  * supported single-word atomic observation, with no value change. */
	__u64 locator = __sync_val_compare_and_swap((__u64 *)entry, 0, 0);
#else
	__u64 locator = __atomic_load_n(entry, __ATOMIC_RELAXED);
#endif
	SE_ROUTE_AFTER_LOCATOR_COPY();
	if (!locator)
		return SE_ROUTE_UNSELECTED;
	__u32 slot = (__u32)locator;
	if (slot >= SE_ROUTE_CAPACITY)
		return SE_ROUTE_INVARIANT_FAULT;
	struct se_route_anchor *anchor = SE_ROUTE_ANCHOR_LOOKUP(&slot);
	if (!anchor)
		return SE_ROUTE_INVARIANT_FAULT; /* inadmissible ARRAY invariant */
	bpf_spin_lock(&anchor->lock);
	int result = se_route_claim_locked(anchor, locator, cgroup, claim);
	bpf_spin_unlock(&anchor->lock);
	return result;
}
#endif
#endif
