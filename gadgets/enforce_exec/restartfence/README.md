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
   sibling classes in one immutable row.
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

The standard path is `/sys/fs/bpf/kubescape/fence-v2/` (owner-only 0700
directories; use the host bpffs mount). The frozen manifest is published
last, and load verifies current boot, expected object, attached
links/programs and map identities. Pending or incompatible pins remain
in place; do not infer that an unknown set protects anything, or detach
it on an adoption refusal. V1 is therefore refused and retained, not
replaced or run alongside v2. Hot v1-to-v2 migration is not implemented.

`Lift` is reserved for an explicitly authorized Helm pre-delete hook.
It latches retirement in the pinned state even if the running agent still
has open link FDs; the normal start/restart path cannot undo that decision.
The retired graph stays pinned as a tombstone. A subsequent installation
needs an explicit, separate retired-graph recovery procedure; normal
`Open` never treats retirement as permission to replace a pin set.

## Build and qualification

The AMD64 object is in `bpf/fence_amd64.elf`. Regenerate with
`go generate .` in this directory (clang-19, libbpf headers and
`llvm-strip`; see `bpf/build.sh`). The build is separate from, and
does not rotate, the product object's pins. Non-AMD64 embedded use
is currently refused.

The VM oracle under `qualification/` uses an independently selective
fixture backend, not the actual node-agent. It does not qualify product
integration, Helm publication, NRI start-gate hooks, or cloud behavior.
