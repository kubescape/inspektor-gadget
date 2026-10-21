// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
// Execution enforcement; maps remain empty until a validated target is bound.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <gadget/macros.h>

#define MAX_RULES 8
#define PATH_SIZE 256

// Tests override only marker creation; production always calls the real helper.
#ifndef EXEC_PROCESS_MARKER_CREATE
#define EXEC_PROCESS_MARKER_CREATE(task, value) \
    bpf_task_storage_get(&process_targets, task, value, BPF_LOCAL_STORAGE_GET_F_CREATE)
#endif

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
    __uint(max_entries, 1);
    __type(key, __u64);
    __array(values, struct policy_map);
} bindings SEC(".maps");

// The host seeds an actual task object via pidfd, never a reusable numeric PID.
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, __u64);
} process_targets SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct policy_map);
} process_bindings SEC(".maps");


// Persistent health is independent of event delivery and policy generations.
struct process_health_value { __u64 failures; __u64 degraded; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_health_value);
} process_health SEC(".maps");

struct exec_path_scratch { char path[PATH_SIZE]; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exec_path_scratch);
} scratch_space SEC(".maps");

struct event {
    __u64 generation;
    __u64 cgroup;
    __u32 deny;
    __u32 mode;
    __s32 path_result;
    __u32 host_pid;
    char path[PATH_SIZE];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");
GADGET_TRACER(verdict, events, event);

// denied decisions, submitted events, dropped events, allowed decisions, path errors, rate limited
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void count(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&counters, &key);
    if (value)
        (*value)++;
}

// At most 100 report attempts per CPU per second; enforcement is never throttled.
struct report_window { __u64 second; __u32 attempts; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct report_window);
} report_windows SEC(".maps");

static __always_inline bool report_allowed(void)
{
    __u32 zero = 0;
    struct report_window *window = bpf_map_lookup_elem(&report_windows, &zero);
    if (!window)
        return false;
    __u64 second = bpf_ktime_get_ns() / 1000000000;
    if (window->second != second) {
        window->second = second;
        window->attempts = 0;
    }
    if (window->attempts >= 100)
        return false;
    window->attempts++;
    return true;
}

struct compare_ctx {
    struct exec_path_scratch *scratch;
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
    __u32 zero = 0;
    struct task_struct *task = bpf_get_current_task_btf();
    struct task_struct *leader = task->group_leader;
    __u64 *marked = bpf_task_storage_get(&process_targets, leader, 0, 0);
    // Read one inner map; the header and all rules share one generation.
    void *policy;
    if (marked)
        policy = bpf_map_lookup_elem(&process_bindings, &zero);
    else
        policy = bpf_map_lookup_elem(&bindings, &cgroup);
    if (!policy)
        return 0;
    struct exec_policy_entry *header = bpf_map_lookup_elem(policy, &zero);
    if (!header)
        return -1;
    __u32 mode = header->mode;
    // A nonleader exec replaces the leader (de_thread). Preserve the marker
    // even while off, so a later policy update can still address this process.
    if (marked && task != leader) {
        __u64 one = 1;
        if (!EXEC_PROCESS_MARKER_CREATE(task, &one)) {
            struct process_health_value *health = bpf_map_lookup_elem(&process_health, &zero);
            if (health) {
                __sync_fetch_and_add(&health->failures, 1);
                if (mode != 2)
                    __sync_fetch_and_or(&health->degraded, 1);
            }
            // NULL does not identify a precise errno. Choose ENOMEM when
            // enforcing to avoid silently losing the selected process.
            // Audit and off must never block solely to preserve tracking.
            volatile long result = 0;
            if (mode == 2)
                result = -12;
            return result;
        }
    }
    if (!mode)
        return 0;
    __u64 generation = header->generation;
    __u32 rule_count = header->count;
    bool deny = header->default_deny;
    struct exec_path_scratch *scratch = bpf_map_lookup_elem(&scratch_space, &zero);
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
    bool reporting = report_allowed();
    struct event *event = reporting ? bpf_ringbuf_reserve(&events, sizeof(*event), 0) : 0;
    if (event) {
        event->generation = generation;
        event->cgroup = cgroup;
        event->deny = deny;
        event->mode = mode;
        event->path_result = length;
        event->host_pid = bpf_get_current_pid_tgid() >> 32;
        // No stale path bytes on resolution failure.
        if (length > 0)
            __builtin_memcpy(event->path, scratch->path, PATH_SIZE);
        else
            __builtin_memset(event->path, 0, PATH_SIZE);
        bpf_ringbuf_submit(event, 0);
        count(1);
    } else {
        count(reporting ? 2 : 5);
    }
    // Keep explicit signed errno branches visible to the 6.12 verifier.
    volatile long result = 0;
    if (deny && mode == 2)
        result = -1;
    return result; // -EPERM or allow
}

char LICENSE[] SEC("license") = "GPL";
