/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#ifndef UK_RESTART_FENCE_H
#define UK_RESTART_FENCE_H

#define FENCE_PRCTL 0x4b554246
#define FENCE_STRICT 1
#define FENCE_AUDIT 2
#define FENCE_SECTION_EXEC (1U << 0)
#define FENCE_MAX_PODS 4096
#define FENCE_MAX_CHILDREN 128
#define FENCE_INACTIVE 1

struct fence_identity {
	__u64 incarnation;
	__u64 start_boottime;
	__u32 tgid;
	__u32 reserved;
};

struct fence_challenge {
	__u64 incarnation;
	__u64 lo;
	__u64 hi;
};

/* One immutable HASH replacement publishes the entire pod and its children. */
struct fence_child {
	__u64 cgroup_id;
	__u64 binding_identity;
	__u64 exec_owner;
	__u64 exec_generation;
	__u32 strict_sections;
	__u32 audit_sections;
	__u32 off_sections;
	__u32 bound_sections;
	/* Accounting only; never substitutes for an exact native handover. */
	__u64 accounted_incarnation;
	__u64 reserved64[1];
};

struct fence_binding {
	__u64 pod_uid_hash;
	__u64 revision;
	/* Fallback for an unknown child, not readiness shared by siblings. */
	__u32 strict_sections;
	__u32 audit_sections;
	__u32 child_count;
	__u32 flags;
	__u64 fallback_accounted_incarnation;
	__u64 reserved64[3];
	struct fence_child children[FENCE_MAX_CHILDREN];
};

_Static_assert(sizeof(struct fence_child) == 64, "fence child ABI");
_Static_assert(sizeof(struct fence_binding) == 8256, "fence pod ABI");
_Static_assert(__builtin_offsetof(struct fence_child, accounted_incarnation) ==
		       48,
	       "fence child accounting ABI");
_Static_assert(__builtin_offsetof(struct fence_binding,
				  fallback_accounted_incarnation) == 32,
	       "fence pod accounting ABI");
_Static_assert(__builtin_offsetof(struct fence_binding, children) == 64,
	       "fence children ABI");

struct fence_totals {
	__u64 denied;
	__u64 audit;
	__u64 lost;
	__u64 outage_denied;
	__u64 outage_audit;
	__u64 outage_lost;
};

struct fence_event {
	__u64 ktime;
	__u64 cgroup_id;
	__u64 pod_uid_hash;
	__u32 tgid;
	__u32 mode;
};

#endif
