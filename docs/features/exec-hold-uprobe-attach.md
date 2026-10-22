# Exec-hold until uprobe attach

## Motivation

A uprobe attached to a Go binary's `crypto/tls` functions only observes calls
that happen *after* the attach completes. If a process execs and immediately
uses a TLS connection — as short-lived CLI tools commonly do — the uprobe
attach pipeline (resolving the binary's Go module data, walking its pclntab,
locating the attach offsets, then registering the kernel uprobe) can lose the
race against the process's own first write. The result is a connection that
is never captured at all, even though the binary and the mechanism that would
capture it both exist; the attach simply lost a timing race it structurally
cannot always win once the process has already exec'd.

The existing exec-driven reattach path
(`uprobetracer.Tracer.ReattachContainerExecPid`, see ADR 0001 in the
downstream consumer's docs) already narrows this race as far as a purely
*post*-exec mechanism can: it fires as soon as the fork's own exec-event
BPF program observes the exec, which is faster than waiting for a later,
unrelated poll. But it is still fundamentally after the exec has already
happened, and cannot close the race to zero.

This feature closes it to zero for a bounded, explicit set of binaries by
holding the *exec itself* open — via a fanotify `FAN_OPEN_EXEC_PERM`
permission gate — until the uprobe attach has actually completed, or a
bounded timeout elapses. Nothing is held that isn't explicitly opted into an
allowlist; every unmatched exec on the node pays zero added cost.

## Architecture

### Marking (deciding what to hold)

`pkg/container-hook/exechold.go` owns an operator-configurable allowlist of
binary basenames (`SetExecHoldBinaries`). A candidate is only ever considered
after it has been resolved with the same hardening in every code path:

- `execHoldOpenCandidate` resolves the candidate under a container's rootfs
  via `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`, confirms it's a
  regular file, and confirms its `st_dev` matches the container root's
  device — rejecting a symlink escape to a host path, and a bind mount from
  a *different* filesystem. On a kernel that reports `STATX_MNT_ID`/
  `STATX_MNT_ID_UNIQUE` (Linux >= 5.8, preferring the reuse-proof
  `_UNIQUE` variant from >= 6.8), it additionally compares the candidate's
  unique mount identity against the rootfs's own, which also rejects a
  **same-device** bind mount (e.g. bind-mounting another directory from the
  node's own root filesystem into the container) — `st_dev` alone cannot
  tell that case apart from a legitimate file inside the rootfs's own
  mount, since both share the same device. **On a kernel that supports the
  mount-identity check, a container cannot get a host binary marked this
  way at all; on an older kernel (< 5.8), a same-device bind mount of a
  host binary is the one residual gap `st_dev` alone cannot close.**
- The candidate is validated via an `O_PATH` open (cheap, doesn't block on
  special files), then re-opened via `/proc/self/fd/<pathfd>` as `O_RDONLY`
  before being marked — `fanotify_mark`'s NULL-pathname mark-by-fd form
  resolves its `dirfd` argument through the kernel's `fdget()`, which
  excludes `O_PATH` descriptors. The re-open is of the *already-validated
  object*, not a second resolution of the original path, so there is no new
  TOCTOU window.

Candidates are marked from two independent triggers, both using the exact
same resolution/marking code:

1. **Container-create enumeration** — inside the existing bounded
   create→start gate (`watchPidFileIterate`/`callbackAddContainerBounded`),
   for binaries already present in the container's image.
2. **First-exec observation** — for binaries installed into a container
   *after* it started (the dominant real-world case for interactively-run,
   freshly-downloaded CLI tools). This reuses the fork's existing
   mntns-scoped exec-event ringbuf (`exec_events`/`EventTypeExecContainer`,
   the same emission `ReattachContainerExecPid` already consumes). The exec
   that triggers this observation is *never* held — by the time it's
   observed, it has already happened — but every subsequent exec of that
   binary in that container is now marked and will be held.
3. **External write-time pre-marking** — `ContainerCollection.MarkExecHoldCandidateByMntns`
   exposes the same marking logic to a caller outside this package entirely
   (e.g. a consumer's own file-write tracer), so a binary can be marked the
   moment it's written to disk, before its first exec — closing the
   remaining gap trigger (2) leaves open for a binary's very first
   invocation. A direct single-file write is caught; an installer that
   writes to a temp path and atomically renames into place is not (no
   `rename(2)` event is watched), and falls back to trigger (2)'s
   first-exec coverage for that one invocation.

### Holding (the dispatcher)

Marks are read on a **dedicated** `FAN_CLASS_CONTENT` fanotify group,
deliberately separate from the fork's existing `runtimeBinaryNotify` group:
it omits `FAN_REPORT_TID` (this feature needs process, not thread,
granularity) and `FAN_UNLIMITED_QUEUE` (this feature's queue is meant to be
bounded, unlike the always-on host-runtime-binary watch).

`exechold_dispatch.go` implements the hold:

- **Guard first, no lock:** an incoming event is checked against this
  dispatcher's own hold-state (an in-memory set of overlay `(dev, ino)`
  pairs) via a cheap local `fstat`. An event with no matching hold-state is
  allowed immediately — no worker, no credit check. Hold-state is recorded
  *before* the corresponding mark is installed, with rollback if the mark
  call fails, so there is never a window where a real hold exists with no
  matching state.
- **Credit before parse:** a bounded pool of workers calls
  `uprobetracer.Tracer.CreditIfAttached` — an atomic check-and-credit
  accessor that resolves the candidate's *real* (post-overlay) inode,
  checks whether this tracer already has a live uprobe on it, and if so
  credits the reference to the holding container in the same step, with no
  ELF parse. Only a genuinely first-ever hold on a given real inode reaches
  a full resolve+attach.
- **Timeout via a separate goroutine:** because a blocked synchronous call
  cannot be preempted, the per-hold timeout is enforced by a goroutine
  distinct from the one doing the work, racing "worker finished" against
  the bound. A per-event token (`sync.Once`) makes whichever side loses the
  race a safe no-op — a worker the timeout already gave up on can complete
  later without touching hold-state belonging to a different, later hold
  on the same object.
- **Watchdog:** if the dispatcher's own read loop — not one slow worker,
  the loop itself — stops making progress, a watchdog closes the group's
  file. Per `fanotify(7)`, closing a group's fd resolves every outstanding
  permission event as allowed; this is the same fail-open guarantee that
  covers a crashed or restarted process, deliberately triggered here for a
  live-but-wedged one too.

### Crediting correctness

`CreditIfAttached` performs *both* halves of what the normal attach path
splits across two call sites — the `inodeRefCount` bump (`attachOneOpenFile`)
and the `containerPid2Inodes[pid]` append (`commitOpenedTargets`) — in one
`t.mu` critical section. Doing only the first half would leave
`DetachContainer` unable to ever release that reference, since it walks
`containerPid2Inodes[pid]` to know what to decrement; the inode's uprobe
and pinned file handle would then outlive every container that legitimately
still holds them.

## Resource accounting

Every execve on the node — not just held ones — inserts a record into a
shared, node-wide eBPF map (`exec_args`) this fork already uses for a
different purpose (correlating container-create fanotify events with their
eBPF-observed exec). A held exec occupies that map's slot for the duration
of the hold. `exec_args`'s capacity was raised from 128 to 512 entries
(`installEbpf`, a Go-level `ebpf.MapSpec.MaxEntries` edit, not a BPF source
change) to give this feature's added, bounded hold pressure headroom
without starving the map's existing, unrelated consumer. On kernels ≥5.11,
this preallocated map's memory (≈2.6MB at 512 entries) is charged to the
loading process's own cgroup limit.

## External API

For a consumer embedding this fork:

- `containerhook.SetExecHoldBinaries(names []string)` — sets the allowlist.
- `ContainerCollection.MarkExecHoldCandidateByMntns(mntnsID uint64, path string) ExecHoldMarkResult`
  — request a pre-mark from an external trigger. Every outcome
  (`NotApplicable`, `NotAllowlisted`, `Installed`, `NotInstalled`) is a
  routine value, never an error — a caller racing container lifecycle
  should see routine outcomes, not alarms.
- `ebpfoperator.UprobeTracerForGadget(gadgetCtx, progName)` /
  `UprobeTracersForGadget(gadgetCtx)` — reach the live
  `uprobetracer.Tracer` instance(s) for a running gadget, to wire as the
  `ExecHoldCrediter` a `ContainerNotifier.SetExecHoldHooks` call needs.
  "Not available" (not yet started, already torn down, or an unrelated
  context) is a single, undistinguished, routine outcome.

## Known limitations

- The very first invocation of a binary this mechanism has never seen
  before on a given real inode always races exactly as it did before this
  feature existed — there is no way to hold an exec for a binary whose
  existence isn't yet known. Enumeration and first-exec marking narrow this
  to "the first invocation after install"; write-time pre-marking narrows
  it further to "installers that don't write-then-rename."
- A container that mounts a filesystem legitimately inside itself (e.g. a
  separate `/usr` volume) has any allowlisted binary on that filesystem
  skipped rather than marked, since its `st_dev` won't match the rootfs
  device. This is the safe direction of that trade: the alternative is a
  bind-mount-based host-binary marking vulnerability.
- A container whose *entire* rootfs is a bind-mounted host directory
  (non-overlay) is not covered by the `st_dev` check the same way an
  overlay-rootfs container is — this is a narrow, documented residual gap,
  not closed in this version.
