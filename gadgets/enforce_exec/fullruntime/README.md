# Experimental persistent exec owner

This package provides the native persistent owner, bounded whole-exec gate,
publication coordinator and isolated tests for frozen policy-map revisions. The
embedding supplies authenticated runtime leases and public event provenance;
readiness requires the explicitly supported kernel/runtime environment.

## Current support and security limits

This is the **full persistent-owner profile**, not the
[simple path-only engine](../README.md). It currently admits only the two exact
custom **amd64** kernel artifacts in [KERNEL-MATRIX.md](KERNEL-MATRIX.md). Stock
distribution kernels and arm64 are not supported by this profile. BPF LSM and
ftrace availability alone do not satisfy its admission checks.

**Audit is not yet safe as a nonblocking trial mode in this implementation.**
Evaluator/observation errors, owner faults and closed admission during reload or
re-attestation can deny exec even for an audit-only policy. Strictly nonblocking
audit, including these failure paths, is required follow-up work, not a property
established by the existing isolated proofs. Enforced policies must not fall open
to hide such failures. Do not interpret an audit verdict or a successful reload
test as proof that all audit failure paths permit execution.

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
frozen inner map before `Reopen`; on preparation/publication failure, retain the
old map and reopen. A timeout reopens only the closure this owner acquired,
preserving outstanding admissions. A stale lease cannot reopen a later
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
