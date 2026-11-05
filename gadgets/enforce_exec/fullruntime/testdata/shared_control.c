// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
struct bpf_spin_lock {
	int held;
};
static int locks;
static void bpf_spin_lock(struct bpf_spin_lock *l)
{
	assert(!locks && !l->held);
	locks++;
	l->held = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *l)
{
	assert(locks == 1 && l->held);
	locks--;
	l->held = 0;
}
#define SEC(x)
#define SE_CONTROL_TEST 1
#define SE_PROFILE_BINDINGS 2
#define SE_PROFILE_SLOTS_256 2
#define SE_PROFILE_SLOTS_1024 0
#define SE_PROFILE_SLOTS_4096 0
#define SE_PROFILE_SLOTS_16384 0
struct se_node_config;
struct se_control_command;
struct se_control_receipt;
struct se_shared_object;
struct se_shared_binding;
struct se_arena_cell;
static struct se_node_config *config_lookup(const __u32 *);
static struct se_control_command *command_lookup(const __u32 *);
static struct se_control_receipt *receipt_lookup(const __u32 *);
static __u64 *admin_lookup(void);
static struct se_shared_object *object_lookup(const __u32 *);
static struct se_shared_binding *binding_lookup(const __u32 *);
static struct se_arena_cell *cell_lookup(const __u32 *);
static void after_store(struct se_shared_object *);
#define SE_CONFIG_LOOKUP config_lookup
#define SE_COMMAND_LOOKUP command_lookup
#define SE_RECEIPT_LOOKUP receipt_lookup
#define SE_ADMIN_LOOKUP admin_lookup
#define SE_OBJECT_LOOKUP object_lookup
#define SE_BINDING_LOOKUP binding_lookup
#define SE_CELL_LOOKUP cell_lookup
#define SE_AFTER_CELL_STORE after_store
#include "shared_control.h"
static struct se_node_config config = { .node_cookie = 11,
					.nonce = 22,
					.abi = 3,
					.profile_version = 1,
					.bindings = 2,
					.objects = 2,
					.cells = 512,
					.slots = { 2, 0, 0, 0 } };
static struct se_control_command command;
static struct se_control_receipt receipt;
static struct se_shared_object objects[2];
static struct se_shared_binding bindings[2];
static struct se_arena_cell cells[512];
static __u64 admin = 22;
static int have_admin = 1, object_lookups, paused;
static struct se_node_config *config_lookup(const __u32 *k)
{
	assert(!locks && !*k);
	return &config;
}
static struct se_control_command *command_lookup(const __u32 *k)
{
	assert(!locks && !*k);
	return &command;
}
static struct se_control_receipt *receipt_lookup(const __u32 *k)
{
	assert(!locks && !*k);
	return &receipt;
}
static __u64 *admin_lookup(void)
{
	assert(!locks);
	return have_admin ? &admin : 0;
}
static struct se_shared_object *object_lookup(const __u32 *k)
{
	assert(!locks);
	object_lookups++;
	return *k < 2 ? &objects[*k] : 0;
}
static struct se_shared_binding *binding_lookup(const __u32 *k)
{
	assert(!locks);
	return *k < 2 ? &bindings[*k] : 0;
}
static struct se_arena_cell *cell_lookup(const __u32 *k)
{
	assert(!locks);
	return *k < 512 ? &cells[*k] : 0;
}
static void after_store(struct se_shared_object *o)
{
	assert(!locks);
	if (!paused)
		return;
	paused--;
	bpf_spin_lock(&o->lock);
	assert(o->state.writer_sequence);
	assert(se_object_abort_locked(&o->state, o->state.generation,
				      o->state.attempt) < 0);
	bpf_spin_unlock(&o->lock);
}
static int call(__u32 op)
{
	command.node_cookie = 11;
	command.nonce = 22;
	command.sequence++;
	command.operation = op;
	return se_command(0);
}
int main(void)
{
	command = (struct se_control_command){ .node_cookie = 11,
					       .nonce = 22,
					       .sequence = 1,
					       .operation = SE_OBJECT_BEGIN,
					       .object = 1,
					       .attempt = 99,
					       .count = 2 };
	have_admin = 0;
	assert(se_command(0) && !object_lookups && !receipt.sequence);
	have_admin = 1;
	admin = 23;
	assert(se_command(0) && !object_lookups);
	admin = 22;
	command.node_cookie = 12;
	assert(se_command(0) && !object_lookups);
	command.node_cookie = 11;
	config.cells = 513;
	assert(se_command(0) && !object_lookups);
	config.cells = 512;
	receipt.node_cookie = 12;
	assert(se_command(0) && !object_lookups && receipt.node_cookie == 12);
	receipt.node_cookie = 0;
	command = (struct se_control_command){ .scope = 1 };
	assert(!call(SE_BINDING_OPEN) && bindings[0].state.scope == 1);
	command.object = 1;
	command.attempt = 99;
	command.count = 2;
	assert(!call(SE_OBJECT_BEGIN) && objects[1].state.generation == 1);
	command.generation = 1;
	command.index = 1;
	command.value.words[0] = 77;
	assert(call(SE_OBJECT_WRITE) && !cells[257].words[0]);
	command.index = 0;
	paused = 1;
	assert(!call(SE_OBJECT_WRITE) && !paused && cells[256].words[0] == 77 &&
	       !cells[0].words[0]);
	command.index = 1;
	assert(!call(SE_OBJECT_WRITE));
	command.count = 300;
	command.execution_class = 1;
	assert(call(SE_OBJECT_FINALIZE));
	command.count = 1;
	assert(!call(SE_OBJECT_FINALIZE));
	command.index = 0;
	command.value.words[0] = 88;
	assert(call(SE_OBJECT_WRITE) && cells[256].words[0] == 77);
	command.generation = 0;
	command.serial = 0;
	command.handles[0] = (struct se_pin_ticket){ .object_slot = 1,
						     .object_generation = 1 };
	assert(!call(SE_SNAPSHOT_PREPARE) &&
	       bindings[0].state.records[0].serial == 1);
	command.serial = 1;
	assert(!call(SE_SNAPSHOT_PIN) && objects[1].state.pins == 1);
	assert(!call(SE_SNAPSHOT_PIN) && objects[1].state.pins == 1);
	assert(!call(SE_SNAPSHOT_SEAL) &&
	       bindings[0].state.records[0].phase == SE_SNAPSHOT_PREPARED &&
	       !bindings[0].state.active_serial);
	assert(!se_binding_commit_preflight_locked(&bindings[0].state, 0, 1, 0,
						   0));
	se_binding_commit_publish_locked(&bindings[0].state, 0);
	struct se_binding_snapshots active = bindings[0].state;
	assert(call(SE_SNAPSHOT_ABORT) &&
	       !memcmp(&active, &bindings[0].state, sizeof(active)));
	assert(!se_binding_withdraw_preflight_locked(
		&bindings[0].state, 1, bindings[0].state.admission_serial));
	se_binding_withdraw_publish_locked(&bindings[0].state);
	assert(!call(SE_SNAPSHOT_RELEASE) && !objects[1].state.pins);
	assert(!call(SE_SNAPSHOT_RELEASE) && !objects[1].state.pins);
	assert(!call(SE_SNAPSHOT_RECLAIM));
	__u64 seq = receipt.sequence;
	assert(se_command(0) && receipt.sequence == seq); /* replay */
	assert(call(999) &&
	       !bindings[0].state.active_serial); /* no Commit/Ready opcode */
	assert(!locks);
	puts("actual authenticated shared syscall body: profile, physical arena write, ticket and replay controls passed");
}
