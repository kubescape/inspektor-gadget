/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 The Inspektor Gadget authors */
#ifndef ENFORCE_EXEC_FULLPOLICY_EVALUATOR_H
#define ENFORCE_EXEC_FULLPOLICY_EVALUATOR_H
#include "matcher.h"
#if defined(FM_GLOBAL_BLOB_LOOKUP)
#define FE_GLOBAL_MATCHER 1
#endif
#define FE_INLINE static __attribute__((always_inline)) inline
#ifdef __bpf__
#define FE_LOOP(count, callback, context) fm_bpf_loop(count, callback, context, 0)
#else
#define FE_LOOP(count, callback, context) fm_c_loop(count, callback, context)
#endif

/* This evaluator consumes authoritative facts only. It neither observes tasks
 * nor bootstraps roles. The caller owns private scratch for the entire call;
 * per-CPU storage is unsafe across sleepable operations. Blobs must be immutable.
 * argv is a canonical NUL-separated vector, with offsets into argv_bytes.
 */
struct fe_path { fm_u32 length; fm_u8 bytes[256]; };
struct fe_role { fm_u64 policy_uid, role; };
struct fe_facts {
    struct fe_path actor_path, target_path;
    int actor_image, target_image;
    fm_u32 effective_uid, uid_known;
    struct fe_path ancestors[16];
    fm_u32 ancestor_count, ancestors_complete;
    struct fe_role roles[8];
    fm_u32 role_count, fs_mask, fs_known; /* fs_known: per-class FE_* mask */
    fm_u8 argv[4096];
    fm_u32 argc, argv_offsets[64], argv_bytes, argv_complete;
    int stdin_pipe;
};
enum { FE_TMPFS = 1, FE_MEMFD = 2, FE_DELETED = 4, FE_OVERLAY = 8 };
enum { FE_OK = 0, FE_INVALID = 1, FE_UNKNOWN = 2, FE_ROLE_CONFLICT = 3 };
struct fe_decision {
    fm_u32 deny, mode;
    fm_u64 matched_rules[4], proposed_roles[8];
    fm_u32 error;
};
struct fe_scratch {
    struct fm_scratch matcher;
    struct fe_decision decision;
    fm_u32 arg_lengths[64];
};
_Static_assert(sizeof(struct fe_facts) == 9216, "facts ABI");
_Static_assert(sizeof(struct fe_decision) == 112, "decision ABI");
struct fe_header { fm_u64 generation; fm_u32 policies, rule_base, rules, container; };
/* root_epoch is owner metadata used by trusted role-fact acquisition; the
 * evaluator never bootstraps a missing role from it. */
struct fe_policy { fm_u64 uid, root_role; fm_u32 fallback, mode; fm_u64 root_epoch; };
_Static_assert(sizeof(struct fe_policy) == 32, "policy prefix ABI");
struct fe_list { fm_u32 base, count; };
struct fe_rule {
    fm_u32 policy, mode, deny;
    int actor_image, target_image, stdin_pipe;
    fm_u32 ancestor_depth, reserved;
    fm_u64 set_role;
    struct fe_list actor_path, target_path, ancestor_path, actor_role, uid,
                   container, fs_type, arg_contains, arg_prefix;
};
struct fe_string { fm_u32 length; fm_u8 bytes[256]; };
_Static_assert(sizeof(struct fe_rule) == 112, "rule prefix ABI");
_Static_assert(sizeof(struct fe_header) == 24, "header prefix ABI");

FE_INLINE const struct fm_blob *fe_blob(void *ctx, fm_u32 key)
{
    if (key >= FM_MAX_ENTRIES) return 0;
#ifdef FE_GLOBAL_MATCHER
    (void)ctx;
    return FM_GLOBAL_BLOB_LOOKUP(key);
#else
    return FM_BLOB_LOOKUP(ctx, key);
#endif
}
FE_INLINE int fe_list_valid(struct fe_list list)
{
    return list.count <= 256 && list.base < FM_MAX_ENTRIES &&
           list.count <= FM_MAX_ENTRIES - list.base;
}
struct fe_bytes_context {
    const fm_u8 *left, *right;
    fm_u32 length;
    int equal;
};
static long fe_bytes_step(fm_u32 i, void *opaque)
{
    struct fe_bytes_context *c = opaque;
    if (i >= 255 || i >= c->length) return 1;
    if (c->left[i] != c->right[i]) { c->equal = 0; return 1; }
    return 0;
}
FE_INLINE int fe_bytes_equal(const fm_u8 *a, const fm_u8 *b, fm_u32 length)
{
    if (length > 255) return -1;
    struct fe_bytes_context c = {a, b, length, 1};
    if (FE_LOOP(length, fe_bytes_step, &c) < 0) return -1;
    return c.equal;
}
struct fe_path_check { const struct fe_path *path; fm_u32 offset; int error; };
static long fe_path_byte(fm_u32 i, void *opaque)
{
    (void)i;
    struct fe_path_check *c = opaque;
    if (c->offset >= c->path->length) return 1;
    fm_u32 rune = 0, width = 0;
    if (fm_decode(c->path->bytes, c->path->length, c->offset, &rune, &width)) {
        c->error = 1; return 1;
    }
    c->offset += width;
    return 0;
}
FE_INLINE int fe_path_valid(const struct fe_path *path)
{
    if (path->length > 255) return 0;
    struct fe_path_check c = {path, 0, 0};
    if (FE_LOOP(255, fe_path_byte, &c) < 0) return 0;
    return !c.error && c.offset == path->length;
}
struct fe_paths_check { const struct fe_facts *facts; int error; };
static long fe_ancestor_valid(fm_u32 i, void *opaque)
{
    struct fe_paths_check *c = opaque;
    if (i >= 16 || i >= c->facts->ancestor_count) return 1;
    if (!fe_path_valid(&c->facts->ancestors[i])) { c->error = 1; return 1; }
    return 0;
}
/* Validate the full vector before matching, including arguments not consulted
 * by a successful alternative. Zero lengths are valid empty arguments. */
struct fe_argv_check {
    const struct fe_facts *facts;
    struct fe_scratch *scratch;
    fm_u32 block, argument, start;
    int error;
};
static long fe_argv_byte(fm_u32 i, void *opaque)
{
    struct fe_argv_check *c = opaque;
    fm_u64 offset = (fm_u64)c->block * 256 + i;
    if (i >= 256 || offset >= 4096 || offset >= c->facts->argv_bytes) return 1;
    if (c->facts->argv[offset]) return 0;
    fm_u32 arg = c->argument;
    if (arg >= 64 || arg >= c->facts->argc || c->facts->argv_offsets[arg] != c->start) {
        c->error = 1; return 1;
    }
    c->scratch->arg_lengths[arg] = offset - c->start;
    c->argument++;
    c->start = offset + 1;
    return 0;
}
static long fe_argv_block(fm_u32 i, void *opaque)
{
    struct fe_argv_check *c = opaque;
    if (i >= 16 || c->error) return 1;
    c->block = i;
    if (FE_LOOP(256, fe_argv_byte, c) < 0) c->error = 1;
    return c->error ? 1 : 0;
}
/* Independently verify the4096-byte scan; do not expand its nested callbacks
 * under every rule/predicate state. Both arguments are bounded typed memory. */
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_argv_valid(const struct fe_facts *f, struct fe_scratch *s)
{
    if (!f || !s || !f->argv_complete || f->argc > 64 || f->argv_bytes > 4096) return 0;
    struct fe_argv_check c = {.facts = f, .scratch = s};
    if (FE_LOOP(16, fe_argv_block, &c) < 0) return 0;
    return !c.error && c.argument == f->argc && c.start == f->argv_bytes;
}
enum { FE_PATH, FE_VALUE, FE_STRING, FE_FS, FE_ARG_EXACT, FE_ARG_PREFIX };
struct fe_match_context {
    void *blob_context;
    const struct fe_facts *facts;
    struct fe_scratch *scratch;
    struct fe_list list;
    const struct fe_path *path;
    const struct fe_string *string;
    fm_u64 value;
    fm_u32 kind;
    int result;
};
struct fe_argument_bytes {
    const struct fe_facts *facts;
    const struct fe_string *value;
    fm_u32 offset, length;
    int equal;
};
static long fe_argument_byte(fm_u32 i, void *opaque)
{
    struct fe_argument_bytes *c = opaque;
    if (i >= 255 || i >= c->length) return 1;
    fm_u64 offset = (fm_u64)c->offset + i;
    __asm__ __volatile__("" : "+r"(offset));
    if (offset >= 4096) { c->equal = -1; return 1; }
    if (c->facts->argv[offset] != c->value->bytes[i]) {
        c->equal = 0; return 1;
    }
    return 0;
}
struct fe_arg_context {
    const struct fe_facts *facts;
    struct fe_scratch *scratch;
    const struct fe_string *value;
    fm_u32 kind;
    int result;
};
static long fe_arg_step(fm_u32 i, void *opaque)
{
    struct fe_arg_context *c = opaque;
    const struct fe_facts *f = c->facts;
    if (i >= 64 || i >= f->argc) return 1;
    fm_u32 len = c->value->length, offset = f->argv_offsets[i];
    fm_u32 actual = c->scratch->arg_lengths[i];
    if (len > actual || (c->kind == FE_ARG_EXACT && len != actual)) return 0;
    if (offset >= 4096 || len > 4096 - offset || len > 255) { c->result = -1; return 1; }
    struct fe_argument_bytes bytes = {f, c->value, offset, len, 1};
    if (FE_LOOP(255, fe_argument_byte, &bytes) < 0) bytes.equal = -1;
    if (bytes.equal) { c->result = bytes.equal; return 1; }
    return 0;
}
/* Keep the64-argument scan independent of rule/list verifier state. The byte
 * callback indexes the full argv array with an explicit absolute bound: an
 * interior argv pointer is not falsely advertised as256 readable bytes. */
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_match_arguments(const struct fe_facts *facts, struct fe_scratch *scratch,
#ifdef FE_GLOBAL_MATCHER
                       fm_u32 string_key, fm_u32 kind)
#else
                       const struct fe_string *value, fm_u32 kind)
#endif
{
#ifdef FE_GLOBAL_MATCHER
    const struct fe_string *value = (const struct fe_string *)fe_blob(0, string_key);
#endif
    if (!facts || !scratch || !value || facts->argc > 64 ||
        value->length > 255 || (kind != FE_ARG_EXACT && kind != FE_ARG_PREFIX)) return -1;
    struct fe_arg_context c = {facts, scratch, value, kind, 0};
    if (FE_LOOP(64, fe_arg_step, &c) < 0) return -1;
    return c.result;
}
FE_INLINE fm_u32 fe_fs_bit(const struct fe_string *s)
{
    if (s->length == 5 && s->bytes[0]=='t' && s->bytes[1]=='m' && s->bytes[2]=='p' && s->bytes[3]=='f' && s->bytes[4]=='s') return FE_TMPFS;
    if (s->length == 5 && s->bytes[0]=='m' && s->bytes[1]=='e' && s->bytes[2]=='m' && s->bytes[3]=='f' && s->bytes[4]=='d') return FE_MEMFD;
    if (s->length == 7 && s->bytes[0]=='d' && s->bytes[1]=='e' && s->bytes[2]=='l' && s->bytes[3]=='e' && s->bytes[4]=='t' && s->bytes[5]=='e' && s->bytes[6]=='d') return FE_DELETED;
    if (s->length == 7 && s->bytes[0]=='o' && s->bytes[1]=='v' && s->bytes[2]=='e' && s->bytes[3]=='r' && s->bytes[4]=='l' && s->bytes[5]=='a' && s->bytes[6]=='y') return FE_OVERLAY;
    return 0;
}
static long fe_match_step(fm_u32 i, void *opaque)
{
    struct fe_match_context *c = opaque;
    if (i >= 256 || i >= c->list.count) return 1;
    const struct fm_blob *blob = fe_blob(c->blob_context, c->list.base + i);
    if (!blob) { c->result = -1; return 1; }
    int result = 0;
    if (c->kind == FE_PATH) {
        if (!c->path) { c->result = -1; return 1; }
        result = fm_match_key(c->blob_context, c->list.base + i,
                              c->path->bytes, c->path->length, &c->scratch->matcher);
    } else if (c->kind == FE_VALUE) {
        result = blob->words[0] == c->value;
    } else {
        const struct fe_string *s = (const struct fe_string *)blob;
        if (s->length > 255) { c->result = -1; return 1; }
        if (c->kind == FE_STRING) {
            if (!c->string) { c->result = -1; return 1; }
            if (s->length == c->string->length)
                result = fe_bytes_equal(s->bytes, c->string->bytes, s->length);
        } else if (c->kind == FE_FS) {
            fm_u32 bit = fe_fs_bit(s);
            result = bit && (c->facts->fs_known & bit) ? !!(c->facts->fs_mask & bit) : -1;
        } else {
#ifdef FE_GLOBAL_MATCHER
            result = fe_match_arguments(c->facts, c->scratch, c->list.base + i, c->kind);
#else
            result = fe_match_arguments(c->facts, c->scratch, s, c->kind);
#endif
        }
    }
    if (c->kind == FE_FS && result < 0) {
        c->result = -1; /* keep looking for a known-positive OR alternative */
        return 0;
    }
    if (result) { c->result = result; return 1; }
    return 0;
}
FE_INLINE int fe_match(struct fe_match_context *c, struct fe_list list, fm_u32 kind)
{
    if (!fe_list_valid(list)) return -1;
    if (!list.count) return 1;
    c->list = list; c->kind = kind; c->result = 0;
    if (FE_LOOP(list.count, fe_match_step, c) < 0) return -1;
    return c->result;
}
struct fe_ancestor_context { struct fe_match_context *match; struct fe_list list; fm_u32 depth; int result; };
static long fe_ancestor_step(fm_u32 i, void *opaque)
{
    struct fe_ancestor_context *c = opaque;
    if (i >= 16 || i >= c->depth || i >= c->match->facts->ancestor_count) return 1;
    c->match->path = &c->match->facts->ancestors[i];
    if (!c->match->path->length) { c->result = -1; return 1; }
    int result = fe_match(c->match, c->list, FE_PATH);
    if (result) { c->result = result; return 1; }
    return 0;
}
struct fe_eval_context {
    void *blob_context;
    const struct fe_facts *facts;
    struct fe_scratch *scratch;
    const struct fe_header *header;
    fm_u32 matched, allow_mode, deny_mode;
};
/* Resolve all eight policy-local role records in an independent verifier
 * compartment. Absence is unknown, never an implicit root-role bootstrap. */
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_resolve_role(const struct fe_facts *facts, fm_u64 policy_uid, fm_u64 *role)
{
    if (!facts || !role || facts->role_count > 8) return -1;
    fm_u64 found = 0;
    for (fm_u32 i = 0; i < 8; i++) {
        if (i >= facts->role_count) break;
        if (facts->roles[i].policy_uid != policy_uid) continue;
        fm_u64 candidate = facts->roles[i].role;
        if (found && found != candidate) return -1;
        found = candidate;
    }
    if (!found) return -1;
    *role = found;
    return 0;
}

#ifndef FE_GLOBAL_MATCHER
struct fe_predicate_context {
    struct fe_eval_context *evaluation;
    const struct fe_rule *rule;
    const struct fe_policy *policy;
    struct fe_match_context match;
    int result;
};
/* One predicate per helper callback prevents the verifier from multiplying
 * matcher states across nine sequential list callsites. Field order remains the
 * oracle's order: an unknown fact is an error only when actually consulted. */
static long fe_predicate_step(fm_u32 index, void *opaque)
{
    struct fe_predicate_context *pc = opaque;
    struct fe_eval_context *e = pc->evaluation;
    const struct fe_rule *r = pc->rule;
    const struct fe_facts *f = e->facts;
    struct fe_match_context *c = &pc->match;
    struct fe_list list = {};
    fm_u32 kind = FE_VALUE;
    int result = 1;
    switch (index) {
    case 0:
    case 1:
        if (index == 0) { list = r->actor_path; c->path = &f->actor_path; }
        else { list = r->target_path; c->path = &f->target_path; }
        if (list.count && !c->path->length) goto unknown;
        kind = FE_PATH;
        break;
    case 2:
        list = r->actor_role;
        if (list.count && fe_resolve_role(f, pc->policy->uid, &c->value) < 0) goto unknown;
        break;
    case 3:
        list = r->container; kind = FE_STRING;
        if (list.count) {
            c->string = (const struct fe_string *)fe_blob(e->blob_context, e->header->container);
            if (!c->string || !c->string->length || c->string->length > 255) goto unknown;
        }
        break;
    case 4:
        list = r->uid;
        if (list.count && !f->uid_known) goto unknown;
        c->value = f->effective_uid;
        break;
    case 5:
        if (r->actor_image == -1) return 0;
        if (f->actor_image < 0 || f->actor_image > 1) goto unknown;
        result = r->actor_image == f->actor_image;
        goto done;
    case 6:
        if (r->target_image == -1) return 0;
        if (f->target_image < 0 || f->target_image > 1) goto unknown;
        result = r->target_image == f->target_image;
        goto done;
    case 7:
        list = r->fs_type; kind = FE_FS;
        break;
    case 8: {
        if (!r->ancestor_path.count) return 0;
        if (!r->ancestor_depth || r->ancestor_depth > 16) goto unknown;
        struct fe_ancestor_context a = {c, r->ancestor_path, r->ancestor_depth, 0};
        if (FE_LOOP(16, fe_ancestor_step, &a) < 0) goto unknown;
        result = a.result;
        if (!result && f->ancestor_count < r->ancestor_depth && !f->ancestors_complete) goto unknown;
        goto done;
    }
    case 9:
        if ((r->arg_contains.count || r->arg_prefix.count) && !fe_argv_valid(f, e->scratch)) goto unknown;
        list = r->arg_contains; kind = FE_ARG_EXACT;
        break;
    case 10:
        list = r->arg_prefix; kind = FE_ARG_PREFIX;
        break;
    case 11:
        if (r->stdin_pipe == -1) return 0;
        if (f->stdin_pipe < 0 || f->stdin_pipe > 1) goto unknown;
        result = r->stdin_pipe == f->stdin_pipe;
        goto done;
    default:
        goto unknown;
    }
    result = fe_match(c, list, kind);
done:
    if (result != 1) { pc->result = result; return 1; }
    return 0;
unknown:
    pc->result = -1;
    return 1;
}
#endif
#ifdef FE_GLOBAL_MATCHER
/* Verify the complete ordered conjunction once with typed arguments. Direct
 * field sequencing removes the predicate callback frame, so ancestry plus the
 * separately verified matcher remains within eight BPF frames. */
__attribute__((noinline))
int fe_rule_match_global(const struct fe_facts *f, struct fe_scratch *scratch,
                         fm_u32 rule_key, fm_u64 policy_uid)
{
    /* Fetch immutable data inside this compartment. Global memory arguments
     * are treated as writable by the verifier even when declared const. */
    const struct fe_rule *r = (const struct fe_rule *)fe_blob(0, rule_key);
    if (!f || !scratch || !r || f->ancestor_count > 16 || f->role_count > 8 ||
        r->actor_image < -1 || r->actor_image > 1 || r->target_image < -1 || r->target_image > 1 ||
        r->stdin_pipe < -1 || r->stdin_pipe > 1) return -1;
    const struct fe_header *header = (const struct fe_header *)fe_blob(0, 0);
    if (!header) return -1;
    struct fe_match_context c = {.facts=f, .scratch=scratch};
    int result;
#define FE_TEST(list, kind) do { result = fe_match(&c, (list), (kind)); if (result != 1) return result; } while (0)
    c.path = &f->actor_path;
    if (r->actor_path.count && !c.path->length) return -1;
    FE_TEST(r->actor_path, FE_PATH);
    c.path = &f->target_path;
    if (r->target_path.count && !c.path->length) return -1;
    FE_TEST(r->target_path, FE_PATH);
    if (r->actor_role.count && fe_resolve_role(f, policy_uid, &c.value) < 0) return -1;
    FE_TEST(r->actor_role, FE_VALUE);
    if (r->container.count) {
        c.string = (const struct fe_string *)fe_blob(0, header->container);
        if (!c.string || !c.string->length || c.string->length > 255) return -1;
    }
    FE_TEST(r->container, FE_STRING);
    if (r->uid.count && !f->uid_known) return -1;
    c.value = f->effective_uid;
    FE_TEST(r->uid, FE_VALUE);
    if (r->actor_image != -1) {
        if (f->actor_image < 0 || f->actor_image > 1) return -1;
        if (r->actor_image != f->actor_image) return 0;
    }
    if (r->target_image != -1) {
        if (f->target_image < 0 || f->target_image > 1) return -1;
        if (r->target_image != f->target_image) return 0;
    }
    FE_TEST(r->fs_type, FE_FS);
    if (r->ancestor_path.count) {
        if (!r->ancestor_depth || r->ancestor_depth > 16) return -1;
        struct fe_ancestor_context a = {&c, r->ancestor_path, r->ancestor_depth, 0};
        if (FE_LOOP(16, fe_ancestor_step, &a) < 0) return -1;
        if (a.result != 1) {
            if (a.result < 0 || (f->ancestor_count < r->ancestor_depth && !f->ancestors_complete)) return -1;
            return 0;
        }
    }
    if ((r->arg_contains.count || r->arg_prefix.count) && !fe_argv_valid(f, scratch)) return -1;
    FE_TEST(r->arg_contains, FE_ARG_EXACT);
    FE_TEST(r->arg_prefix, FE_ARG_PREFIX);
    if (r->stdin_pipe != -1) {
        if (f->stdin_pipe < 0 || f->stdin_pipe > 1) return -1;
        if (r->stdin_pipe != f->stdin_pipe) return 0;
    }
#undef FE_TEST
    return 1;
}
#endif
FE_INLINE int fe_rule_match(struct fe_eval_context *e, const struct fe_rule *r,
                           const struct fe_policy *p, fm_u32 rule_key)
{
#ifdef FE_GLOBAL_MATCHER
    (void)r;
    return fe_rule_match_global(e->facts, e->scratch, rule_key, p->uid);
#else
    (void)rule_key;
    struct fe_predicate_context c = {
        .evaluation = e, .rule = r, .policy = p, .result = 1,
        .match = {.blob_context=e->blob_context, .facts=e->facts, .scratch=e->scratch},
    };
    if (FE_LOOP(12, fe_predicate_step, &c) < 0) return -1;
    return c.result;
#endif
}
static long fe_rule_step(fm_u32 i, void *opaque)
{
    struct fe_eval_context *e = opaque;
    struct fe_decision *d = &e->scratch->decision;
    if (i >= 256 || i >= e->header->rules) return 1;
    const struct fe_rule *r = (const struct fe_rule *)fe_blob(e->blob_context, e->header->rule_base + i);
    if (!r || r->policy >= 8 || r->policy >= e->header->policies || r->mode < 1 || r->mode > 2 || r->deny > 1 ||
        r->actor_image < -1 || r->actor_image > 1 || r->target_image < -1 || r->target_image > 1 || r->stdin_pipe < -1 || r->stdin_pipe > 1) {
        d->error = FE_INVALID; return 1;
    }
    const struct fe_policy *p = (const struct fe_policy *)fe_blob(e->blob_context, 1 + r->policy);
    if (!p) { d->error = FE_INVALID; return 1; }
    int match = fe_rule_match(e, r, p, e->header->rule_base + i);
    if (match < 0) { d->error = FE_UNKNOWN; return 1; }
    if (!match) return 0;
    e->matched = 1;
    d->matched_rules[(i >> 6) & 3] |= (fm_u64)1 << (i & 63);
    if (r->deny) {
        d->deny = 1;
        if (r->mode > e->deny_mode) e->deny_mode = r->mode;
    } else {
        if (r->mode > e->allow_mode) e->allow_mode = r->mode;
        fm_u32 index = r->policy;
        if (index >= 8) { d->error = FE_INVALID; return 1; }
        if (r->set_role) {
            if (d->proposed_roles[index] && d->proposed_roles[index] != r->set_role) {
                d->error = FE_ROLE_CONFLICT; return 1;
            }
            d->proposed_roles[index] = r->set_role;
        }
    }
    return 0;
}
FE_INLINE int fe_evaluate(void *blob_context, const struct fe_facts *f, struct fe_scratch *s)
{
    /* Clear outputs even on malformed input and poisoned/reused scratch. The
     * matcher and argument lengths initialize their own consumed scratch. */
    s->decision.deny = 0; s->decision.mode = 1; s->decision.error = 0;
    for (fm_u32 i=0; i<4; i++) s->decision.matched_rules[i] = 0;
    for (fm_u32 i=0; i<8; i++) s->decision.proposed_roles[i] = 0;
    const struct fe_header *h = (const struct fe_header *)fe_blob(blob_context, 0);
    if (!h || !h->policies || h->policies > 8 || h->rules > 256 || h->rule_base != 9 ||
        h->container >= FM_MAX_ENTRIES || f->ancestor_count > 16 || f->role_count > 8 ||
        !fe_path_valid(&f->actor_path) || !fe_path_valid(&f->target_path)) {
        s->decision.error = FE_INVALID; return -1;
    }
    struct fe_paths_check paths = {f, 0};
    if (FE_LOOP(16, fe_ancestor_valid, &paths) < 0 || paths.error) {
        s->decision.error = FE_INVALID; return -1;
    }
    struct fe_eval_context e = {blob_context, f, s, h, 0, 1, 1};
    if (FE_LOOP(h->rules, fe_rule_step, &e) < 0) s->decision.error = FE_INVALID;
    if (s->decision.error) {
        for (fm_u32 i=0; i<8; i++) s->decision.proposed_roles[i] = 0;
        return -1;
    }
    if (!e.matched) {
        for (fm_u32 i=0; i<8; i++) {
            if (i >= h->policies) break;
            const struct fe_policy *p = (const struct fe_policy *)fe_blob(blob_context, 1+i);
            if (!p || p->fallback > 2 || p->mode < 1 || p->mode > 2) {
                s->decision.error = FE_INVALID; return -1;
            }
            if (p->fallback == 2) {
                s->decision.deny = 1;
                if (p->mode > e.deny_mode) e.deny_mode = p->mode;
            } else if (p->fallback == 1 && p->mode > e.allow_mode) e.allow_mode = p->mode;
        }
    }
    s->decision.mode = s->decision.deny ? e.deny_mode : e.allow_mode;
    if (s->decision.deny)
        for (fm_u32 i=0; i<8; i++) s->decision.proposed_roles[i] = 0;
    return 0;
}
#endif
