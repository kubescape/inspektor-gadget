# Exec restart fence

This independent IG object is not part of the exact-pinned product ELF.
It guards host cgroup-v2 **pod** subtrees when the agent has not attested
takeover. A fenced Strict exec returns EPERM. Audit execs are not blocked
by this guard and are counted. No timeout releases the fence.

## Integration order

1. Open and attest the fence before attaching the product engine. Use the
   embedded ELF from `Object` on a supported target. An unavailable object,
   missing/unsupported hook, pin mismatch, or failed registration is a
   readiness refusal, not a signal to continue without the fence.
2. Register with a one-use kernel challenge. A new incarnation does not
   un-fence existing workloads. Resolve trusted host pod and container
   cgroup-v2 descriptors; PublishCensus publishes the pod mark and known
   sibling classes in one immutable row. Independently managed container
   roots must be verified non-overlapping, including while the owner is
   down. Census validation can reject known overlaps; it cannot prove
   where the runtime will create an undiscovered root. Ordinary
   descendants within a verified root keep its classification.
3. MoveChild releases only an exact Strict or Audit child after its
   committed product generation has been attested. Unknown descendants
   cannot inherit another child's handover. Mixed scopes use a Strict
   fallback; Audit fallback requires evidence that Strict is impossible.
4. RefenceChild before potentially destructive live product operations.
   CommitPolicyWithdrawal may set a child Off only after authoritative
   policy removal and native route withdrawal. Discovery loss does not
   authorize Off. Serialize attestation with native mutation.
5. Arm and verify before withdrawing any product route on shutdown. The
   product hook attaches after this guard so it evaluates first on the
   supported kernels. Close is not an uninstall.
6. Report cumulative outage separately from same-owner reconciliation.
   Remove a child or pod only after proving the physical cgroup is gone.

The pinned exit hook arms on the authenticated process's last thread
(`signal->live == 0`), ahead of descriptor release. The LSM hook also
pre-arms on authenticated self-exec before CLOEXEC, and the exec tracepoint
arms idempotently. Once pre-armed, even an unsuccessful attempt can leave
Strict pods fenced; the same thread group cannot register itself again to
resume. The engine's link FDs must be close-on-exec, must not be passed
to other processes (including by pidfd or independent pins), and agent
threads must not unshare their FD table.

## Pins and uninstall

The standard path is `/sys/fs/bpf/kubescape/fence-v3/` (owner-only 0700
directories; use the host bpffs mount). The frozen manifest is published
last, and load verifies current boot, expected object, attached
links/programs and map identities. Pending or incompatible pins remain
in place; do not infer that an unknown set protects anything, or detach
it on an adoption refusal. V1 and v2 are refused and retained, not
replaced or run alongside v3. Hot version migration is not implemented.
The loader checks the named v3 BTF accounting layout before any attach,
not only the same-sized map geometry, and scans pinned rows against the
last issued incarnation before adoption.

`Lift` is reserved for an explicitly authorized Helm pre-delete hook.
It latches retirement in the pinned state even if the running agent still
has open link FDs; the normal start/restart path cannot undo that decision.
The retired graph stays pinned as a tombstone. A subsequent installation
needs an explicit, separate retired-graph recovery procedure; normal
`Open` never treats retirement as permission to replace a pin set.

## V3 accounting provenance

V3 keeps the 8,256-byte pod snapshot and 64-byte child slots, but assigns
one formerly reserved header word to the fallback accounting incarnation
(offset 32) and one child word to its accounting incarnation (offset 48).
All remaining reserved words stay zero. The new pin format, path, BTF
field schema, and exact object digest are incompatible with v2. There is
no automatic migration, pin replacement, or change to the native product ELF.

Registration and ordinary census publication preserve inherited provenance;
refencing clears native readiness but keeps its accounting epoch. A fresh
exact Move updates only that child. Thus same-owner reconciliation is
distinguished from successor recovery even while the child is unbound.
Authorized Off and inactive-scope publication clear the corresponding epoch.
Cumulative counters are not reset.

After a complete authoritative census and policy snapshot, with no
ambiguous identities and all retained managed children freshly handed over
or authoritatively removed, the caller may invoke
`AcknowledgePodAccounting`. Serialize the proof with native mutations and
use its returned PodRef. The API verifies the current exact revision and
all retained managed child handovers before acknowledging fallback
accounting. Neither registration, a partial census, nor one child's Move
acknowledges other children or the fallback. An empty child list alone is
not caller authority. This API changes telemetry only: unknown descendants
still have no native readiness and retain the same fallback verdict.

Accounting fields never authorize an exec or establish protection.
Missing/incoherent attribution is reported as lost/unattributed observation,
not an invented normal/outage count; malformed classification still fails
closed. Loss counters count observation/attribution failures and need not
equal distinct execs. Userspace refuses malformed or future provenance
without rewriting it.

## Build and qualification

The AMD64 object is in `bpf/fence_amd64.elf`. Regenerate with
`go generate .` in this directory using the repository-pinned gadget-builder
image from `Makefile` (`clang`, libbpf headers and `llvm-strip`; see
`bpf/build.sh`). Build qualification payloads with that same toolchain and
verify the baseline fence object matches the embedded object byte for byte
before running the oracle. `CLANG` and `LLVM_STRIP` overrides remain available,
but changing the toolchain requires regenerating and qualifying the resulting
exact object; a previous object's qualification does not transfer.
The build is separate from, and does not rotate, the product object's pins.
Non-AMD64 embedded use is currently refused.

The VM oracle under `qualification/` uses an independently selective
fixture backend, not the actual node-agent. It does not qualify product
integration, Helm publication, NRI start-gate hooks, or cloud behavior.
