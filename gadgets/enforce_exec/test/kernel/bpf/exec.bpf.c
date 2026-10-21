// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
// Feasibility probe only: not part of the shipped gadget image.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_RULES 8
#define PATH_SIZE 256

extern int bpf_path_d_path(struct path *path, char *buf, size_t buf__sz) __ksym;

// Slot 0 contains the generation header; remaining slots contain path rules.
struct exec_policy_entry {
    __u64 generation;
    __u32 mode; // 0 off, 1 audit, 2 enforce
    __u32 default_deny;
    __u32 count;
    __u32 deny;
    __u32 prefix;
    __u32 length;
    char path[PATH_SIZE];
};
struct policy_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES + 1);
    __type(key, __u32);
    __uint(value_size, sizeof(struct exec_policy_entry));
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 8);
    __type(key, __u64);
    __array(values, struct policy_map);
} bindings SEC(".maps");
// Materialize the inner-map type for clang BTF emission.
struct policy_map policy_template SEC(".maps");

struct scratch { char path[PATH_SIZE]; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scratch);
} scratch_space SEC(".maps");

struct event {
    __u64 generation;
    __u64 cgroup;
    __u32 deny;
    __u32 mode;
    __s32 path_result;
    __u32 reserved;
    char path[PATH_SIZE];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");
// denied decisions, submitted events, dropped events, allowed decisions, path errors
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void count(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&counters, &key);
    if (value)
        (*value)++;
}

struct compare_ctx {
    struct scratch *scratch;
    struct exec_policy_entry *rule;
    __u32 length;
    bool match;
};

static long compare_char(__u32 index, void *data)
{
    struct compare_ctx *ctx = data;
    __u64 offset = index;
    // Keep the bounds check and pointer arithmetic on the same 64-bit scalar.
    asm volatile("" : "+r"(offset));
    if (offset >= PATH_SIZE || offset >= ctx->length)
        return 1;
    if (ctx->scratch->path[offset] != ctx->rule->path[offset]) {
        ctx->match = false;
        return 1;
    }
    return 0;
}

SEC("lsm/bprm_check_security")
long BPF_PROG(enforce_exec, struct linux_binprm *bprm, long ret)
{
    if (ret)
        return ret;
    __u64 cgroup = bpf_get_current_cgroup_id();
    // Read the inner map ONCE. Header and rules belong to the same generation.
    void *policy = bpf_map_lookup_elem(&bindings, &cgroup);
    if (!policy)
        return 0;
    __u32 zero = 0;
    struct exec_policy_entry *header = bpf_map_lookup_elem(policy, &zero);
    if (!header)
        return -1;
    __u32 mode = header->mode;
    if (!mode)
        return 0;
    __u64 generation = header->generation;
    __u32 rule_count = header->count;
    bool deny = header->default_deny;
    struct scratch *scratch = bpf_map_lookup_elem(&scratch_space, &zero);
    if (!scratch) {
        volatile long result = 0;
        if (mode == 2)
            result = -1;
        return result;
    }
    __builtin_memset(scratch->path, 0, PATH_SIZE);
    // Preserve verifier trust: do not copy the file pointer through probe reads.
    int length = bpf_path_d_path(&bprm->file->f_path, scratch->path, PATH_SIZE);
    if (length <= 0) {
        deny = true; // Explicit runtime resolution-error policy for this probe.
        count(4);
    } else {
        bool allow_match = false, deny_match = false;
        for (__u32 i = 1; i <= MAX_RULES; i++) {
            if (i > rule_count)
                break;
            __u32 key = i;
            struct exec_policy_entry *rule = bpf_map_lookup_elem(policy, &key);
            if (!rule)
                continue;
            __u32 rule_len = rule->length;
            if (rule_len == 0 || rule_len >= PATH_SIZE)
                continue;
            struct compare_ctx comparison = {
                .scratch = scratch, .rule = rule, .length = rule_len, .match = true,
            };
            if (bpf_loop(PATH_SIZE, compare_char, &comparison, 0) < 0)
                comparison.match = false;
            if (!rule->prefix && length != rule_len + 1)
                comparison.match = false;
            if (comparison.match) {
                if (rule->deny)
                    deny_match = true;
                else
                    allow_match = true;
            }
        }
        if (deny_match)
            deny = true;
        else if (allow_match)
            deny = false;
    }
    count(deny ? 0 : 3);
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->generation = generation;
        event->cgroup = cgroup;
        event->deny = deny;
        event->mode = mode;
        event->path_result = length;
        event->reserved = 0;
        // No stale path bytes on resolution failure.
        if (length > 0)
            __builtin_memcpy(event->path, scratch->path, PATH_SIZE);
        else
            __builtin_memset(event->path, 0, PATH_SIZE);
        bpf_ringbuf_submit(event, 0);
        count(1);
    } else {
        count(2);
    }
    // Keep explicit signed errno branches visible to the 6.12 verifier.
    volatile long result = 0;
    if (deny && mode == 2)
        result = -1;
    return result; // -EPERM or allow
}

// Test-only companion: demonstrate correct BPF-LSM return-value chaining.
SEC("lsm/bprm_check_security")
long BPF_PROG(preserve_previous, struct linux_binprm *bprm, long ret)
{
    return ret;
}
char LICENSE[] SEC("license") = "GPL";
