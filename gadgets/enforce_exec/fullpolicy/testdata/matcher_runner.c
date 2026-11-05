/* SPDX-License-Identifier: Apache-2.0 */
/* Plain userspace oracle harness; libc/allocation are outside matcher.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fm_blob;
struct fixture {
	struct fm_blob *entries;
	unsigned int count;
};
static const struct fm_blob *lookup(void *, unsigned int);
#define FM_BLOB_LOOKUP(context, key) lookup(context, key)
#include "../bpf/matcher.h"

static const struct fm_blob *lookup(void *context, unsigned int key)
{
	struct fixture *fixture = context;
	return key < fixture->count ? &fixture->entries[key] : NULL;
}
int main(int argc, char **argv)
{
	if (argc != 4)
		return 2;
	FILE *file = fopen(argv[1], "rb");
	if (!file || fseek(file, 0, SEEK_END))
		return 2;
	long bytes = ftell(file);
	if (bytes <= 0 || bytes % sizeof(struct fm_blob) ||
	    bytes / sizeof(struct fm_blob) > FM_MAX_ENTRIES ||
	    fseek(file, 0, SEEK_SET))
		return 2;
	struct fixture fixture = { .count = bytes / sizeof(struct fm_blob) };
	fixture.entries = calloc(fixture.count, sizeof(struct fm_blob));
	struct fm_scratch *scratch = calloc(1, sizeof(*scratch));
	if (!fixture.entries || !scratch ||
	    fread(fixture.entries, sizeof(struct fm_blob), fixture.count,
		  file) != fixture.count)
		return 2;
	fclose(file);
	unsigned int pattern_key = strtoul(argv[2], NULL, 10);
	if (pattern_key >= fixture.count)
		return 2;
	unsigned char input[1024];
	size_t hex_length = strlen(argv[3]);
	if (hex_length % 2 || hex_length / 2 > sizeof(input))
		return 2;
	for (size_t i = 0; i < hex_length / 2; i++) {
		unsigned int byte;
		if (sscanf(argv[3] + 2 * i, "%2x", &byte) != 1)
			return 2;
		input[i] = byte;
	}
	/* Poison scratch to catch dependence on calloc/previous invocation state. */
	memset(scratch, 0xa5, sizeof(*scratch));
	int result = fm_match(
		&fixture,
		(const struct fm_pattern *)&fixture.entries[pattern_key], input,
		hex_length / 2, scratch);
	/* Reusing scratch after an error or match must produce the same answer. */
	int again = fm_match(
		&fixture,
		(const struct fm_pattern *)&fixture.entries[pattern_key], input,
		hex_length / 2, scratch);
	if (result != again)
		return 3;
	printf("%d\n", result);
	free(scratch);
	free(fixture.entries);
	return 0;
}
