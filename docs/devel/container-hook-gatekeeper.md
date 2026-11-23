# container-hook: permission-event gatekeeper

The container hook (`pkg/container-hook`) detects containers with fanotify
permission events: `FAN_OPEN_EXEC_PERM` on the OCI runtime binary (every runc
call) and `FAN_ACCESS_PERM` on pid-file directories (container create→start).
The kernel blocks the process that triggered the event until the fanotify
reader answers, and there is no timeout. If the reader is alive but cannot make
progress (throttled in memcg reclaim, CPU-starved, stopped), every container
start, stop and exec on the host blocks, kubelet cannot restart the reader
through the same runtime, and the node stays `Ready`.

The gatekeeper bounds that wait. It is a small separate process that reads both
fanotify groups and answers every permission event when the container hook is
done with it, or when the bound expires, whichever comes first.

## Flow

1. `install()` loads the eBPF program, then starts the gatekeeper before adding
   any mark. It passes the two fanotify fds, the `ig_fa_records` map fd and one
   end of a `SOCK_SEQPACKET` socket pair.
2. The gatekeeper reads an event. For the runtime group it dequeues the
   matching `ig_fa_records` entry right away, which keeps the events and
   records in lockstep.
3. It sends the event to the hook: a 24-byte header, the record, and the event
   fd as `SCM_RIGHTS`. The send never blocks. If the socket is full, the
   gatekeeper allows the event at once and drops it.
4. The hook processes the event as before (marks, pid-file read through its copy
   of the event fd, AddContainer callback) and replies with the event's
   sequence number.
5. The gatekeeper answers `FAN_ALLOW` on the reply, or at the deadline, and
   closes its copy of the event fd. The fd stays open until then, so its number
   cannot be reused by another pending event.

The hook never reads or answers the fanotify groups itself while a gatekeeper
runs.

## Bounds

| Group | Bound | Set by |
|---|---|---|
| runtime binary (every runc call) | 1s | `SetPermissionResponseBound` (100ms–60s) |
| pid file (create→start) | runtime bound, at least the AddContainer callback budget + 500ms | `PidFileResponseBound` |

## Process and cgroup

- Binary: `/usr/bin/ig-container-hook-gatekeeper` (`cmd/container-hook-gatekeeper`,
  ~1.6 MB, ~2 MB RSS), or `IG_CONTAINER_HOOK_GATEKEEPER_BIN`. Without it, the
  hook re-executes its own binary and an `init()` in `pkg/container-hook` runs
  the gatekeeper before `main`. That works for any embedder, but the process
  pays for the embedder's package initialization (about 120 MB for
  node-agent), so images should ship the binary.
- Cgroup: the gatekeeper moves itself into
  `<host root>/sys/fs/cgroup/ig-container-hook-gatekeeper` with `memory.max`
  64Mi, `pids.max` 32 and `cpu.max` 0.5 CPU. Reading an event charges its
  `struct file` to the reader's memcg, so a gatekeeper left in the hook's
  memcg is throttled with it. The hook usually runs in a private cgroup
  namespace, which forbids migrating out of it, so the move is done from a
  locked thread that first joins the host cgroup namespace through
  `/proc/1/ns/cgroup` (requires hostPID). If the move fails, the gatekeeper
  logs it and stays. `IG_CONTAINER_HOOK_GATEKEEPER_CGROUP_DIR` overrides the
  directory; `none` disables the move. The directory is reused across restarts
  and stays on the host after uninstall.
- The gatekeeper closes any other fanotify group fd it inherited, so it never
  keeps a group alive that the hook closed.

## Failure behavior

| What fails | Result |
|---|---|
| Hook stuck or slow | Events allowed at the bound; those containers may be missed |
| Hook exits | Socket closes; the gatekeeper allows everything pending and exits |
| Gatekeeper exits | The hook closes its fanotify fds; the kernel drops the marks. Detection stops, container lifecycle keeps working |
| Gatekeeper cannot start | The hook answers in-process, without a deadline, and logs a warning |

The gatekeeper only ever allows. It never denies an event.

`IG_CONTAINER_HOOK_GATEKEEPER_DISABLE=1` turns the gatekeeper off and restores
in-process answering.

## Logs

The gatekeeper writes to the hook's stderr:

- `container-hook gatekeeper: running in cgroup ...`, or why it stayed
- `container-hook gatekeeper: started (pid ..., bounds: ...)`
- `container-hook gatekeeper: fail-open: expired=N dropped=N evicted=N (forwarded=N answered=N)`,
  at most every 10s and only when a fail-open counter changed

Upstream issue: inspektor-gadget/inspektor-gadget#5996.
