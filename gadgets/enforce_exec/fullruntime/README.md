# Experimental persistent exec owner

## Legacy ABI2 reference and shared Go boundary

**The legacy per-binding ABI2 lifecycle below is not the shared-node activation
contract.** [Commit `dabee7d08`](https://github.com/kubescape/inspektor-gadget/commit/dabee7d08345752cada90c326e25cd7b6855d62d)
publishes ordinary-Go shared preparation, ownership/accounting, receipt cleanup
and bounded clean retry. Those paths and their selected Go tests do not establish
kernel reclamation, accepted-generation publication/reload or native withdrawal
integration for the shared replacement.

The published [`StartNode`](https://github.com/kubescape/inspektor-gadget/blob/dabee7d08345752cada90c326e25cd7b6855d62d/gadgets/enforce_exec/fullruntime/shared_node.go#L67-L72)
refuses startup; binding inspection cannot report protection.
[Full-image admission and `Ready`](https://github.com/kubescape/inspektor-gadget/blob/dabee7d08345752cada90c326e25cd7b6855d62d/gadgets/enforce_exec/fullruntime/shared_host.go#L64-L74)
also refuse shared activation (`Ready` is defined at
[lines 191–199](https://github.com/kubescape/inspektor-gadget/blob/dabee7d08345752cada90c326e25cd7b6855d62d/gadgets/enforce_exec/fullruntime/shared_host.go#L191-L199)).
The [legacy publisher](https://github.com/kubescape/inspektor-gadget/blob/dabee7d08345752cada90c326e25cd7b6855d62d/gadgets/enforce_exec/fullruntime/publication.go#L70-L74)
rejects development ABI3 activation rather than treating ABI2 publication as a
shared receipt. This boundary defines no new wire ABI. Shared native integration,
physical Ready and kernel qualification remain unavailable or unproved; the
legacy isolated matrix and lifetime-credit rules below do not qualify them.

This package contains the **legacy per-binding `Owner` profile** and the unfinished
shared-node `NodeEnforcer` replacement. The legacy profile provides the native
persistent owner, bounded whole-exec gate, publication coordinator and isolated
tests for frozen policy-map revisions. Its embedding supplies authenticated
runtime leases and public event provenance; readiness requires the explicitly
supported kernel/runtime environment. Its proofs do not qualify the shared-node
replacement.

## Shared-node implementation status and API contracts

`NodeEnforcer.Ready` **never reports Ready**: it returns a startup error when the
host is absent, mismatched, incomplete or closing/closed, and otherwise returns
`ErrSharedNativeUnavailable`. Routing, union evaluator adaptation, qualified
history publication and required attachment receipts are not integrated.
Protocol preparation and Go tests do not establish protected workloads.
`se_publication_arm` is the only shared commit/withdrawal producer, and only from
an authenticated `cgroup_kn_lock_live` barrier. A syscall receipt is not that
producer. `se_arm_frame` is per-CPU scratch, not epoch authority. Shared exec
reads `se_epoch_bank` through the kernel-owned `se_epoch_index`. `SE_ARM_BIND`
reserves that index on an earlier barrier; commit only accepts an index that
already names the cell. The unread `se_accepted_epochs` hash is not that
catalogue. An isolated Clang 19 load of the arm, including index bind and bank lookup,
was accepted by local kernel `7.1.13+parrot7-amd64`. That is not the admitted
BTF/Clang 21.1.8 matrix, not Ready, reload integration, or kernel qualification.

- Private shared-object preparation uploads compiler-owned content only. It
  grants no root, snapshot or image qualification.
- `fullpolicy.CompileSharedPolicyCompact` and
  `fullpolicy.NewSharedSnapshotCompact` provide scalar/compact diagnostics, not
  memory admission or activation guarantees. The Limited compiler and private
  worker have conditional logical accounting, but complete producing-artifact
  qualification remains unavailable; see the scope below.
- The private operation context deliberately has `context.Cause(op) == op.Err()`;
  it does not propagate a custom parent cause. Providers must not retain it beyond
  the synchronous, joined operation. Joining retires logical ownership, not
  allocator/GC or scheduler resources.

### Conditional shared-worker qualification

The private worker covers only a **never-staged, generation-zero binding**. It
uses one joined operation for object compilation, union compilation and staging;
it does not establish accepted history, general reload or activation.

On the exact reviewed Go 1.27.3 Linux/amd64 source/tool/profile pins, the
[conditional composition](../fullpolicy/qualification/worker_composition.go)
derives these logical operation-owned terms:

| Term | Bytes |
|---|---:|
| Bootstrap `B` | 536 |
| Project phase maximum | 1,310,800 |
| Selected dependency maximum | 1,454 |
| Combined tail `T` | 1,312,254 |

The fixed reservation would be `B + T = 1,312,790`; object and union compiler
debits remain cumulative and separate. Package/library startup owners, including
the carrier and warmed type caches, are not charged again per operation. These
terms are not an allocator, stack, RSS or complete node-resource bound.

**Complete worker evidence remains unavailable.** `deriveWorkerTail` still
refuses, so the conditional calculation cannot issue a positive PREBUILD or
carrier. Both producer phases generate fresh lowering and typed-Go sentinel
checks bound to the selected snapshot, exports, profile/tools and runner
identity. The typed check does not certify arbitrary unsafe or assembly writes;
opaque-input disposition and final published-consumer/release provenance remain
separate requirements. Diagnostic checks against older published consumer pins
do not qualify the unpublished shared-runtime changes.

The [qualification tooling](../fullpolicy/qualification/README.md) keeps runner
source linkage `UNPROVEN` and native activation `NOT_QUALIFIED`. Approved
signed-image digest verification remains the external release/deployment trust
requirement; these tools do not establish it, and hashes alone are not
authentication. No positive descriptor or Ready state follows from these local
tools or their tests.

The remaining sections describe the **legacy per-binding `Owner` profile**,
including its lifecycle and historical isolated proofs, not `NodeEnforcer`.

## Legacy per-binding Owner support and security limits

This is the **legacy full persistent-owner profile**, not the
[simple path-only engine](../README.md). It currently admits only the two exact
custom **amd64** kernel artifacts in [KERNEL-MATRIX.md](KERNEL-MATRIX.md). Stock
distribution kernels and arm64 are not supported by this profile. BPF LSM and
ftrace availability alone do not satisfy its admission checks.

### Best-effort operational audit

**Audit is best effort across operational faults and reloads.** Audit policy
evaluation must not intentionally deny audited decisions or evaluator
unknown/error results, must not grant uncertain roles, and must preserve earlier
LSM denials. This does not promise uninterrupted execution: tracking, resource or
structural faults and closed admission during reload or re-attestation may block
even audit-only workloads. Enforcement-capable policies remain fail-closed; do
not fall open to hide an operational fault.

On a precommit candidate refusal, retain the last-good active policy and accepted
history. The embedding must report failure/NotReady rather than advertise the
rejected revision as active. Reopen admission only after safe rollback and phase
cleanup; failed rollback retains pending ownership and the closed gate until
recovery. Do not discard trusted state to force admission. A postcommit error
requires resuming the same committed generation, not rolling back to the old
policy.

The legacy mocked Go regression `TestLegacyOwnerUpdateBestEffortAdmission`
covers precommit refusal, drain cancellation and rollback failure/recovery
through `Owner.Update` with fake maps/control and a heap admission word. This is
protocol coverage, not native bootstrap, ABI3/shared activation, physical Ready,
Kubernetes status propagation or kernel qualification.

### Scope, runtime helpers and operator consent

An owner covers one **exact cgroup**, not its descendants. Creating or moving
into a child cgroup does not extend policy coverage. A trusted embedding must
exclude unsupported cgroup delegation and authenticate its runtime lease; the
node-agent strict admission contract includes cgroup-mount, capability,
namespace and seccomp restrictions. Movement observation detects changes and
invalidates readiness; it is not a general mechanism that prevents migration.

This profile has no `BindRestricted` host-namespace exception and no inferred
runtime-helper exemption. A `kubectl exec`/`docker exec` helper entering from an
unobserved creator can fail lineage checks and leave the owner NotReady. A
closed gate can also reject exec or fork during lifecycle operations. Allowing a
`/runc` path does not establish creator lineage or authenticate that binary.
Treat helper disruption as an explicit cost of opting into strict enforcement,
not as a reason to infer an exemption or reset trusted state.

Enforcement consent belongs to the host operator: global
`operator.oci.allow-enforcement` defaults to false. Image behavior metadata
declares what an image requests; it cannot enable that host setting. Image
verification, runtime admission and policy validation remain separate checks.

### Role-entry authoring and isolation

The current compiler requires a `setRole` rule to be an allow, but does **not**
require an actor constraint. An omitted actor (or an empty actor object) places
no restriction on who may enter the role: any matching successful exec can
propose that transition. For example, a rule targeting `bwrap` and assigning
`sandbox-helper` without an actor restriction can let the agent launch `bwrap`
itself to obtain that role. The executable's name is not an authorization proof.

Review each role-entry rule as a grant of future authority. Constrain the actual
authorized actor using meaningful role/path/image predicates where appropriate,
and check that untrusted code cannot first enter or control that actor. An empty
actor object is not a mitigation. This is authoring guidance, not a claim that
the current validator rejects broad grants. Role changes are policy-local and
commit only after successful exec; role labels received through telemetry do
not grant authority.

A constrained grant in the native `fullpolicy` Go IR can look like this (not CLI
YAML or a complete deployment policy):

```go
fromImage := true
policy := fullpolicy.Policy{
    ID: "sandbox-policy", Revision: "1", Mode: fullpolicy.Enforce,
    RootRole: "agent", Default: fullpolicy.Deny,
    Rules: []fullpolicy.Rule{{
        Name: "enter-sandbox-helper", Action: fullpolicy.Allow,
        Actor: fullpolicy.Actor{
            Role: []string{"trusted-launcher"},
            Path: []string{"/usr/libexec/sandbox-launcher"},
            FromImage: &fromImage,
        },
        Target: fullpolicy.Target{
            Path: []string{"/usr/bin/bwrap"}, FromImage: &fromImage,
            SetRole: "sandbox-helper",
        },
    }},
}
```

All three actor constraints must match. This assumes the launcher already has
authenticated `trusted-launcher` role history in this policy and cannot be
controlled or invoked as a confused deputy by untrusted code. The example does
not grant that initial role: its default root role stays `agent`, and missing
history is not authority. The image-origin predicate describes admitted backing
files; it does not prove that the process or its inputs are trustworthy. Review
how the launcher role is established and what it permits before using the grant.
A wildcard-only actor such as `Path: []string{"/**"}` still admits arbitrary
actor paths; its mere presence is not meaningful authorization.

The compiler currently accepts broad grants without an actor-warning API.
`TestRoleEntryAuthoring` and the ordinary Go/C parity cases document this behavior,
including deny/conflict suppression. They are not proof of kernel fact acquisition
or of the runtime's successful-exec role commit.

Roles are **not hostile-code isolation boundaries**. Processes can delegate work
through shared files, IPC, signals or services; containers in a pod commonly
share networking and may share storage. The combined authority reachable through
those channels is a threat-model upper bound, not a literal union performed by
the rule evaluator. Separate pods are a starting point for stronger separation,
but also require appropriate network, storage and service-access controls.

### Restart and recovery

Policy reload retains the same live owner's hooks and history; restarting the
gadget or its owning process does not. Maps and links are not pinned for crash
persistence. Once those resources close, enforcement and retained role history
are lost; a fresh owner cannot reconstruct them from event labels or current
cgroup membership.

Fresh bootstrap authorizes the exact trusted init threadgroup and descendants
whose creator lineage the owner actually observed. Arbitrary already-running
multiprocess containers are not generally re-adoptable; unknown pre-existing
tasks refuse readiness rather than receive inferred root roles. See the
[conservative lineage contract](OWNER-ABI.md#conservative-lineage-boundary).
Withdrawing a faulted owner removes protection; it is not recovery of protected
state. Pinning alone would not supply the missing recovery protocol.

## Word and ownership

One aligned 64-bit word in a writable `BPF_F_MMAPABLE` ARRAY holds a closed high
bit and a low-bit admission count (maximum 4,096). The map has 65,536 lifetime
slots. `GateMap` allocates monotonically; retired slots stay closed and are never
reused. At most 1,024 allocated, nonretired slots may coexist. Exhaustion is an
explicit refusal, not recycling: this avoids a stale pre-admission reader
admitting against a different binding after slot ABA.

Use one Go allocator/publisher owner per map. No ordinary store or
`bpf_map_update_elem` may replace an activated word. Both BPF and Go use aligned
64-bit atomic operations. The first actual BPF exec transaction calls `fg_enter`,
then latches its original binding, slot and transaction identity before looking
up policy. A successful admission owns exactly one release. Do not copy admission
or pending-transition ownership to forked/cloned children.

`BeginUpdate(ctx)` atomically closes admission while retaining the count, waits
for zero and returns an exclusive publication lease. Publish a fully prepared,
frozen inner map before `Reopen`; on precommit preparation/publication failure,
retain the old map and reopen only after safe candidate cleanup. A timeout reopens
only the closure this owner acquired, preserving outstanding admissions. A stale
lease cannot reopen a later
publisher's closure. `Retire` permanently closes a drained slot. `GateMap.Close`
refuses unmapping until all slots have been retired.

Admission and the generic `Leave` helper use bounded CAS loops (64 attempts).
Contention is explicit: failed admission grants nothing; failed generic release
retains ownership/count and must be retried or reported stuck. The role-lifecycle
fixture instead uses `fg_leave_owned`: it claims and clears transaction ownership
under the task lock, finishes all owned writes, then performs one final atomic
subtraction. Duplicate cleanup without a claim never subtracts. Underflow is a
sticky corruption fault, never a reset or compensating write.

## Whole-exec integration boundary

The caller must commit roles and clear pending transaction state **before** its
final count decrement. It must match completion to the original `bprm` and slot,
not the current PID/cgroup (nonleader exec and migration can change these).

Syscall-exit cleanup alone is insufficient: failed `kernel_execve` can return to
a kernel caller without a syscall-exit event. The proposed full runtime requires
verified `fexit/bprm_execve` completion plus task-exit fallback, attached before
admitting LSM transactions. Successful `sched_process_exec` can commit roles, but
release must follow all transaction-owned writes. A separate isolated role fixture has passed all five required hook attachments
and 14 lifecycle cases on the pinned custom kernel, including scripts, failures,
nonleader exec, fork/vfork and an explicitly injected missing-fexit task-exit
fallback. This does not prove persistent production-owner publication, bootstrap
lineage, cgroup migration during active admission, ptrace drain behavior, or
production shutdown ordering. This package does not supply that owner.

Closed-gate exec attempts need an explicit, observable operational failure policy;
never bypass authored enforcement while publication is underway. This can disrupt
runtime helpers and even explicitly audited workloads during a reload. The gate
library does not silently choose this product behavior or claim that it is wired.

The opaque verdict candidate fails closed when a bounded TASK or WORK quota
(`SE_PROFILE_TASK_QUOTA`, `SE_PROFILE_SCRATCH_QUOTA`), the deferred storage, or
the source/target handoff is exhausted: Strict refuses the birth or exec and
Audit leaves the child unevaluated. Building with
`ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE` adds the
`opaque_real_fail_closed_rates` counters (quota LIMIT, source refusal, missing
target, evaluation WORK refusal, storage quarantine, other constructor
failure), and `FailClosedRate` maps two snapshots to a degraded verdict for a
threshold. Its seventh counter reports WORK start retry-bound exhaustions
(`SE_PROFILE_WORK_RETRIES`, default min(16, WORK quota)),
a subset of those refusals. Nothing wires this to `Ready`, which stays unavailable.

The witness has explicit exclusions; these fail-closed outcomes are not counted
in any class:

- first-exec qualification faults (`terminal_fault` from
  `real_owner_birth_qualify`);
- pending-receipt quarantine (`real_owner_reader_begin_core` result `& 8`,
  `real_owner_reader_quarantine_pending`);
- `real_owner_child_open_parent` failure in `real_owner_child_finish`;
- the deferred G019/G020 refusals: cross-generation, interpreter refusal and
  migration relabel.

A zero rate therefore does not prove that no exec failed closed. A future
`Ready` gate must also cover these outcomes before its NotReady verdict can be
trusted. Counting them changes the qualified objects and is a G019/G020 item.

First-exec qualification (`real_owner_birth_qualify`) exists only under
`ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC`, a test-named macro. It
must be productized before G019/G020 can close; until then it is a blocker.

The final-free physical-reuse fix (`se_of_withdraw_directory` in
`lsm/task_free`) is part of every build of the candidate's final-free program,
not of the rate witness: the object refuses to compile without it.

User-approved G025 capacity thresholds:

- **128/16 is the qualified default profile for the opaque candidate build**
  (TASK/WORK quota per binding, two bindings; WORK start retries
  min(16, WORK quota)). 64/8 and 256/32 are qualified alternatives; 256/32 has
  no stack headroom. The candidate source has no default: the build passes
  every value as `-D` flags, all with `-DSE_PROFILE_BINDINGS=2`:
  - 64/8: `-DSE_PROFILE_TASKS=128 -DSE_PROFILE_TASK_QUOTA=64
    -DSE_PROFILE_SCRATCH=16 -DSE_PROFILE_SCRATCH_QUOTA=8
    -DSE_PROFILE_WORK_RETRIES=8`
  - 128/16 (default): `-DSE_PROFILE_TASKS=256 -DSE_PROFILE_TASK_QUOTA=128
    -DSE_PROFILE_SCRATCH=32 -DSE_PROFILE_SCRATCH_QUOTA=16`
    (`SE_PROFILE_WORK_RETRIES` defaults to 16)
  - 256/32: `-DSE_PROFILE_TASKS=512 -DSE_PROFILE_TASK_QUOTA=256
    -DSE_PROFILE_SCRATCH=64 -DSE_PROFILE_SCRATCH_QUOTA=32
    -DSE_PROFILE_WORK_RETRIES=16`

  The in-repo product shared build profile is separate and unchanged by this
  default.
- **Steady-state gate** (test reaper at 2 ms): 0 Strict fail-closed refusals
  and 0 Audit unevaluated children at a sustained 400 births/s per node,
  3 streams, at least 10,000 paced births per exact kernel and class, at
  128/16. 800/s and 1600/s are exploratory ceiling points only.
- **Burst gate** (G019/G020, product reaper): 0 refusals for 1,000
  back-to-back births at 3 and at 8 streams on both kernels. Sizing rule:
  birth rate × credit-return latency < quota.

Runtime reporting rule for a future `Ready` gate built on the witness
(`FailClosedRateDegradedWindow`, `FailClosedRateNotReadyWindow` and their
thresholds in `fail_closed_rate.go`):

- **Degraded** on any fail-closed refusal (Strict) or unevaluated child
  (Audit) within 60 s.
- **NotReady** when the fail-closed rate is above 0.1% over 5 min.
- An unreadable or missing witness, or a counter that moved backwards, is
  **unknown**, never a zero rate.

## Verification

Ordinary tests exercise concurrency, timeout preservation, publisher ownership,
limits, slot retirement and BPF compilation. Privileged testing is opt-in:

```sh
IG_EXEC_GATE_KERNEL_TEST=1 \
IG_EXEC_GATE_BPF_SOURCE=/absolute/path/bpf/gate_test.bpf.c \
./sandbox-exec-gate-kernel.test -test.run '^TestGateKernel$' -test.v
```

Run only on the explicitly selected disposable x86_64 fixture. The kernel test
loads a socket-filter program and uses `BPF_PROG_TEST_RUN`; it attaches nothing.
It tests actual mmap/BPF atomic interoperability, not LSM facts or full exec roles.

## Historical identities

`IdentityRegistry` reserves compiler-validated policy/role hashes before any
candidate seeding or publication. It retains successful reservations even when
subsequent publication fails. Older task state may still carry those hashes;
policy deletion and reload must never free or rename them. Collision and lifetime
capacity failures leave the registry unchanged. The registry is scoped to one
persistent task-state owner and must not be recreated on every revision. It is
not a substitute for production bootstrap, admission, or publication wiring.

## Prepared program publication

`ProgramSlot` is the native frozen-map publication building block for one future
persistent binding owner. `Begin` drains the shared gate and exposes immutable
staging slot1. Native bootstrap must establish its own proof before `Commit`
atomically replaces active slot0 and permanently records successful UID epochs.
Admission remains closed until native phase cleanup and `Finish`. Precommit
`Abort` preserves the last-good map. Failed staging/epoch cleanup is retained and
blocks new allocation, without restarting the old program. Shared handles cannot
complete another publisher's transaction. Every candidate attempt is monotonic;
removed/re-added UIDs retain their original successful epoch.

The native owner must exclusively control the borrowed maps/gate, enforce
aggregate budgets and retain the binding identity leases. It must clear bootstrap
phase before Finish/Abort, drain before StopGadget, and call CloseAfterDetach only
after actual runtime teardown. This building block neither attaches hooks nor
authorizes lineage or reports a production binding Ready. Its ordinary tests use
failure-injected maps; real map-in-map/freeze proof is separately opt-in.

`epoch_roles.h` is the work-copy merge helper, not a task-storage owner. Its caller
provides complete immutable accepted history and verified lineage, and publishes
only under the task lock after both task and authority versions still match.
Accepted scalar roles are not rerooted, and unactivated failed epochs cannot
become authoritative in another attempt. Kernel socket parity proof is separate
from the native C matrix and from production lifecycle wiring.

## Experimental assembled owner and native publication coordinator

**Legacy ABI2 reference:** this section and the native OCI lifecycle below do not
implement or qualify the shared-node replacement; see the
[shared Go boundary](#legacy-abi2-reference-and-shared-go-boundary).

The shared full source now has an explicit `ENFORCE_EXEC_PERSISTENT_OWNER`
profile. `../full/owner/Makefile` packages it separately; its metadata does **not**
advertise the incompatible immutable full-runtime capability. The profile shares
actual fact acquisition with the immutable evaluator, uses active frozen slot0,
and includes persistent role/control hooks. Compilation/BTF checks are not
verifier acceptance or a production activation claim.

`OwnerControl` borrows loaded maps and the operator's `program/eo_command` handle.
It freezes kernel-owned identity maps before activating the exact configuration,
and runs nonce-qualified commands on one dedicated OS thread. Accepted commands
are joined even when their context is canceled. Closing the worker joins calls
and destroys that physical thread; it never detaches hooks or releases pins.
The rejected negative-PID cgroup.procs write must produce both EINVAL and an
authenticated movement-arm receipt. A path parsing error alone proves nothing.

`Publisher` composes the shared gate, A/B inventory, root-group continuity checks,
immutable slot replacement, successful-only epoch flush, committed revalidation,
and phase clear. First startup must call ProgramSlot.Begin **before** activating
configuration, retain that prepared handle, authorize the exact root, then pass
it to NewPublisher and Resume. It must not briefly reopen an empty active slot.
Precommit refusals attempt bounded rollback; failed rollback retains the closed
handle. A map swap is irreversible even if history flush or a command's result
fails. Resume inspects kernel phase receipts and completes the same generation;
it never reroots accepted state or starts a replacement owner.

PublicationResult.Committed refers to the attempted revision, while Generation
identifies the currently active revision (which can still be last-good on a
refused attempt). Admitting means the gate is open, **not** production Ready.
Runtime leases, hook coverage, image evidence, aggregate budgets, OCI startup and
shutdown integration, and public decoder provenance remain native-owner duties.
Retire must succeed before StopGadget; identity pins remain held until confirmed
teardown. The opt-in assembled-kernel fixture is separate from OCI integration.

The assembled fixture has now passed with real hooks and the qualified worker,
including retained-role capacity refusal/last-good and postcommit recovery. It
also verifies native UAPI write/delete refusal on physical IDs and state. The
kernel does not support Freeze on a TASK_STORAGE value containing a spin lock;
see OWNER-ABI.md for the frozen-cookie + read-only-native-hash layout and its
lifetime/privileged-handle assumptions. Native OCI integration and the embedding's persistent backend are now connected
and have isolated pinned-kernel proof; production/general-environment readiness
is not implied.

## Native OCI lifecycle (isolated pinned-environment proof)

`NewOwner` reserves a **shared** aggregate Budget and exclusive cgroup scope
before the OCI collection can load. All owners in one embedding must share that
budget. Native owner images must contain exactly one eBPF layer and no WASM or other
layers. OCI admission enforces this before initializing any image operators,
including when a supplied native owner encounters missing/rewritten ABI metadata.
Additional collections (including duplicate names) also invalidate native resource
admission.
Resource manifests are checked both at admission and again immediately before
allocation, after parameter, context-variable and enricher rewrites:
map payload capacities,
physical local-storage credits, encoded instruction ceilings and two frozen
program slots are accounted. This is bounded capacity accounting, **not** a
measurement or guarantee of kernel/Go RSS, allocator overhead or JIT expansion.
Reservations remain held until confirmed teardown, including failed startup.

### Attach capacity, readiness and the owner cap (G009)

There is no source-derived owner ceiling. The capacity is the measured
per-trampoline link limit, probed with no-op fillers on both exact AL2023
kernels (`test/al2023-trampoline-cap`):

| hook (trampoline) | kind | 6.12.113-138.209 | 6.18.56-125.164 | preexisting |
|---|---|---|---|---|
| bprm_check_security, task_alloc, task_free, socket_connect, inode_init_security_anon | LSM | 38 | 38 | 0 |
| file_open | LSM | 37 | 37 | 1 (stock VM) |
| bprm_execve, cgroup_migrate, copy_process | fentry, fexit | 38 | 38 | 0 |
| bprm_execve, bprm_check_security | mixed fentry/fexit(/LSM) | 38 | 38 | 0 |

That is **38 links per hook on both kernels** (`BPF_MAX_TRAMP_LINKS`; the
limit hit is `E2BIG` from the link count, not the trampoline image size),
shared by fentry, fexit, fmod_ret and LSM programs on the same trampoline (an
LSM hook `X` uses the trampoline of `bpf_lsm_X`). The 38 is shared with every
other BPF consumer on the node, as the preexisting `file_open` link shows.

* **K/R policy.** Each enforcement family may use at most `K` links per hook
  and must leave `R` free for third parties. `R` defaults to **8**
  (`nativeattach.DefaultReservePerHook`; `operators.NativeAttachReserveKey`
  overrides it), so at most 30 per hook are usable by enforcement families
  together. `K` is the family's own need per hook, derived from its packaged
  attach set, and must be **at most 8** (`nativeattach.MaxFamilyLinksPerHook`).
  The exec candidate needs at most **3** on any hook: bprm_execve 3, and 1
  each on task_free, task_alloc, security_bprm_creds_for_exec and
  bprm_check_security.
* **Packaged attach set.** The candidate's ELF has 13 programs on
  bprm_check_security; 11 are tail-call targets and must never be attached.
  `bpf/opaque_real_owner_child_candidate.programs.yaml` is the gadget.yaml
  `programs:` block that marks every trampoline program outside the steady
  state `attach_to: gadget_program_disabled` (tail-call targets, the two
  bootstrap programs, two diagnostics). The eBPF operator skips those programs
  and leaves them out of `K`. `TestCandidateAttachSetDeclaration` and
  `TestCandidateAttachSetObjects` (with `IG_ENFORCE_EXEC_CANDIDATE_OBJECTS`)
  derive the attach set from that block plus the object and pin it.
* **Legacy Owner cap.** `NewBudget` refuses more than `LegacyOwnerHardCap`
  (**2**) owners and `NewOwner` refuses a third owner, both with
  `ErrLegacyOwnerCap`, before anything of it is loaded or attached. Each
  owner attaches 10 trampoline links of its own. One Budget must be shared
  per node.
* **No support claim for owner concurrency.** Neither the legacy Owner cap nor
  the 38-link measurement is a supported concurrency figure. Running more
  than one owner per node, or any number of owners next to other BPF
  consumers, is not claimed to be supported; per-owner concurrency is G019.
* **Transactional attach.** Every collection admitted by a native resource
  validator (and only those; ordinary gadgets are unchanged) is attached by
  `pkg/operators/ebpf/nativeattach`: in a fixed order (task_free, task_alloc,
  movement/cgroup/other hooks, then decision hooks: bprm_execve fexit, fentry,
  creds_for_exec, bprm_check_security), all-or-nothing. Any attach error
  closes this collection's links in reverse order before Start returns, and
  `E2BIG` is a typed `*nativeattach.ErrAttachCapacity{Target, Attached, Err}`
  naming the trampoline. Receipts are published only after every link is
  attached, and a missing receipt fails the transaction.
* **Reserve (hint).** Before attaching, the live links per trampoline are
  counted (`BPF_LINK_GET_NEXT_ID` plus link info). The family refuses with
  `ErrAttachCapacity` unless `K + R` links are free. The hint is not the
  authority; the attach and rollback are.
* **Automatic retry (default).** Every native family retries by default
  (`nativeattach.DefaultRetry`: 500ms doubling to a 30s cap, no attempt
  bound). A capacity refusal does not fail Start: Start blocks, retrying,
  until the family attaches or the gadget context is canceled. While it
  waits the family is NotReady, and each refusal is logged as a typed
  `ErrAttachCapacity` that names the target trampoline. Each attempt re-runs
  the hint and the whole transaction, and a refused attempt leaves no link or
  receipt, so there is never a partial hook set. Errors other than capacity
  (for example a failed link count) are returned at once. A family may
  install its own `nativeattach.Retry` under `operators.NativeAttachRetryKey`
  (`State` then receives every NotReady, Ready and a final non-capacity
  error), or `false` to opt out.
* **Legacy Owner refuses at once.** `WithOwner` sets
  `operators.NativeAttachRetryKey` to `false`: the legacy per-cgroup Owner
  does not retry and its Start returns the capacity refusal immediately.
* **Link-based programs only.** Rollback closes bpf links only. A native
  family is therefore refused, before anything is attached and without
  retry, if an enabled program would attach without a bpf link or with side
  effects rollback cannot undo (kprobes/uprobes, tracepoints, perf events,
  socket filters, TC, sockmap programs, iterators). Admitted are LSM and
  fentry/fexit/tp_btf links, syscall commands and admitted recovery TEST_RUN
  programs, which covers the exec candidate and owner families.
* **Readiness component.** In the native path each receipt's `Check` also
  verifies, by link ID, that the link still exists and references the same
  program. A missing or replaced link returns `*nativeattach.ErrNotReady`
  naming the target; a stale Ready is never reported. This is a component
  check for a future Ready gate: `NodeEnforcer.Ready` stays unavailable.

The native data operator verifies live, operator-owned attachment receipts for
all required hooks, not just image annotations/program FDs. It validates the
trusted transferred lease's proc/cgroup/namespace pins, independently refuses a
root cgroup or the host mount namespace, initializes immutable origins and probes
its own filesystem marker before activating scope. The lease must authenticate
runtime ownership, genuine host identity, stable root/mount constraints and any
complete image-origin evidence. It must not reenter Owner methods.

The exact x86_64 kernel matrix retains the original archived BTF digest
`12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b`.
The additional individually proved artifact has BTF digest
`759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51`:
same Linux source `6b4b543fa18757297ac756a6fe6e64f506b7844a`, with fanotify,
redirect/NAT and CPU bandwidth configuration needed by Kubernetes, plus a
separate local version. Its complete isolated upstream proof and artifact hashes
are recorded in [KERNEL-MATRIX.md](KERNEL-MATRIX.md); private Kubernetes/OTLP
integration remains separate and pending. Both exact gates require
active BPF LSM and enabled ftrace. Unknown digests refuse; neither a matching
release string nor the same source commit establishes support. No general
released-kernel or arm64 support is claimed.

Lifecycle ordering is deliberate:
1. Construct Owner; pass WithOwner and the native data operator to the manager.
2. StartGadget prepares only: scope remains gated and no policy is committed.
3. **After StartGadget succeeds**, explicitly Activate and verify Owner.Check.
4. Update/Resume use the same hooks/maps/task histories, never ReplaceGadget.
5. **Before StopGadget**, successfully drain/retire with BeforeStop. A timeout
   retains old admission/enforcement; do not cancel the runtime in that case.
6. Wait for manager teardown, then ReleaseAfterDetach. Operator Close joins the
   qualified command thread but intentionally does not release identity pins or
   the reservation before eBPF FDs/links are confirmed closed.

Internal owner ABI **2** adds active-only, same-generation physical re-attestation.
ABI1 development artifacts are rejected; the chart version is unchanged.
Movement invalidates the inventory receipt. Owner.Check renews it only behind a
closed/drained gate, with no new roots or epoch writes. Unknown ingress refuses
readiness; after it leaves, accepted state can be re-attested without rerooting.
These pauses can disrupt exec/runtime helpers; there are no inferred exemptions.
The native OCI fixture and ABI2 re-attestation have passed isolated runs with
controlled synthetic leases, real datasource bitmaps and confirmed teardown.
This is not proof of containerd/CRI authenticity, all persistent-profile predicate
combinations, real runtime-helper churn, or the connected node-agent backend.
Those integration prerequisites remain before default activation.

## Reproducible supported owner artifact

The default upstream builder is not proof for this experimental profile. Build an
explicit amd64 archive with the tested compiler and exact supported kernel BTF:

```sh
make -C gadgets/enforce_exec/full/owner archive \
  VMLINUX_BTF=/trusted/vmlinux.btf CLANG=clang-21 BPFTOOL=bpftool \
  IMAGE=localhost/enforce-exec-owner:abi2 ARCHIVE=/tmp/owner.tar
```

This requires Clang 21.1.8 and an exact admitted BTF digest; it never loads BPF.
The archive contains the unchanged owner metadata and a single amd64 platform.
Its compiler/BTF/input bytes are trusted build inputs, not policy-provided code.
Compilation alone is not verifier proof: Clang 19 produced a refused object on
the tested kernel. The embedding's combined fixture accepts the resulting archive
through the same native ORAS tar path as its service configuration.
