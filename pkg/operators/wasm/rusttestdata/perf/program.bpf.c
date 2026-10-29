#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct event {
	__u32 a;
	__u32 b;
	__u8 c;
	__u8 unused[247];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Test-only diagnostics: scope 1 is this test process, scope 0 other TGIDs.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} diag_tgid SEC(".maps");

struct diag_counts {
	__u64 entered;
	__u64 unrecorded;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct diag_counts);
} diag_entries SEC(".maps");

struct diag_result {
	__s64 result; // Preserve the complete signed helper return, including zero.
	__u32 scope;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct diag_result);
	__type(value, __u64);
} diag_results SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int test_write_e(struct syscall_trace_enter *ctx)
{
	struct event event = { .a = 42, .b = 42, .c = 43 };

	__u32 zero = 0;
	__u32 *tgid = bpf_map_lookup_elem(&diag_tgid, &zero);
	__u32 scope = tgid && *tgid == (bpf_get_current_pid_tgid() >> 32);
	struct diag_counts *counts = bpf_map_lookup_elem(&diag_entries, &scope);
	if (counts)
		__sync_fetch_and_add(&counts->entered, 1);

	long result = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
					    &event, sizeof(event));
	struct diag_result key = { .result = result, .scope = scope };
	__u64 *count = bpf_map_lookup_elem(&diag_results, &key);
	if (!count) {
		__u64 initial = 0;
		bpf_map_update_elem(&diag_results, &key, &initial, BPF_NOEXIST);
		count = bpf_map_lookup_elem(&diag_results, &key);
	}
	if (count)
		__sync_fetch_and_add(count, 1);
	else if (counts)
		__sync_fetch_and_add(&counts->unrecorded, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
