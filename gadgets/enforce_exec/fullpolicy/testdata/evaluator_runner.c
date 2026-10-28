/* SPDX-License-Identifier: Apache-2.0 */
/* Native harness for the same header used by BPF; allocation is harness-only. */
#ifdef __bpf__
struct fm_blob;
static inline const struct fm_blob *lookup_global(unsigned int);
#define FM_GLOBAL_BLOB_LOOKUP(key) lookup_global(key)
#define FM_BLOB_LOOKUP(context, key) lookup_global(key)
#include "../bpf/evaluator.h"
#define SEC(name) __attribute__((section(name), used))
#define MAP_UINT(name, value) int(*name)[value]
#define MAP_TYPE(name, value) value *name
struct {
	MAP_UINT(type, 1);
	MAP_UINT(max_entries, FM_MAX_ENTRIES);
	MAP_UINT(map_flags,
		 1U << 7); /* BPF_F_RDONLY_PROG, matching production */
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fm_blob);
} blobs SEC(".maps");
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fe_facts);
} input_map SEC(".maps");
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fe_scratch);
} scratch_map SEC(".maps");
static void *(*map_lookup)(void *, const void *) = (void *)1;
static inline const struct fm_blob *lookup_global(unsigned int key)
{
	return map_lookup(&blobs, &key);
}
/* Program.Test only. Shared test maps are not a concurrent runtime scratch
 * design. This filter is never attached to a socket or exec hook. */
SEC("socket") int evaluator(void *unused)
{
	(void)unused;
	fm_u32 zero = 0;
	const struct fe_facts *facts = map_lookup(&input_map, &zero);
	struct fe_scratch *scratch = map_lookup(&scratch_map, &zero);
	if (!facts || !scratch)
		return 0;
	return fe_evaluate(&blobs, facts, scratch) + 1;
}
char LICENSE[] SEC("license") = "GPL";
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct fm_blob;
struct fixture {
	struct fm_blob *entries;
	unsigned int count;
};
#ifdef FE_FIXED_MAP_TEST
static struct fixture *active_fixture;
static const struct fm_blob *lookup_global(unsigned int);
#define FM_GLOBAL_BLOB_LOOKUP(key) lookup_global(key)
#endif
static const struct fm_blob *lookup(void *, unsigned int);
#define FM_BLOB_LOOKUP(context, key) lookup(context, key)
#include "../bpf/evaluator.h"
static const struct fm_blob *lookup(void *ctx, unsigned int key)
{
	struct fixture *f = ctx;
	return key < f->count ? &f->entries[key] : NULL;
}
#ifdef FE_FIXED_MAP_TEST
static const struct fm_blob *lookup_global(unsigned int key)
{
	return lookup(active_fixture, key);
}
#endif
int main(int argc, char **argv)
{
	if (argc != 3)
		return 2;
	FILE *program = fopen(argv[1], "rb"), *facts = fopen(argv[2], "rb");
	if (!program || !facts || fseek(program, 0, SEEK_END))
		return 2;
	long size = ftell(program);
	if (size <= 0 || size % 288 || size / 288 > FM_MAX_ENTRIES ||
	    fseek(program, 0, SEEK_SET))
		return 2;
	struct fixture fixture = { .count = size / 288 };
	fixture.entries = calloc(fixture.count, 288);
	struct fe_facts *f = calloc(1, sizeof(*f));
	struct fe_scratch *s = calloc(1, sizeof(*s));
	if (!fixture.entries || !f || !s ||
	    fread(fixture.entries, 288, fixture.count, program) !=
		    fixture.count ||
	    fread(f, sizeof(*f), 1, facts) != 1)
		return 2;
#ifdef FE_FIXED_MAP_TEST
	active_fixture = &fixture;
#endif
	memset(s, 0xa5, sizeof(*s));
	int result = fe_evaluate(&fixture, f, s);
	struct fe_decision first = s->decision;
	int again = fe_evaluate(&fixture, f, s);
	if (result != again || memcmp(&first, &s->decision, sizeof(first)))
		return 3;
	printf("%d %u %u %u", result, first.deny, first.mode, first.error);
	for (unsigned int i = 0; i < 4; i++)
		printf(" %llu", first.matched_rules[i]);
	for (unsigned int i = 0; i < 8; i++)
		printf(" %llu", first.proposed_roles[i]);
	puts("");
	fclose(program);
	fclose(facts);
	free(fixture.entries);
	free(f);
	free(s);
	return 0;
}

#endif
