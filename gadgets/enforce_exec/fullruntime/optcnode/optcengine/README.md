# Option C exec engine (G004)

Design 005 §7 option C: per-task state in BPF task storage, one frozen
generation per exec, the real `fullpolicy` evaluator (compat build: staged,
bounded loops, tail-call rule windows). It runs behind the node contract in
`../` (package `optcnode`); admission is `../admission`.

## Objects

`build.sh` (or `$U/G004/build-bpf.sh`, the pinned clang-21 container) builds two
objects from `bpf/optc.bpf.c`, both embedded by `engine.go`:

- `optc_product_bpfel.o`: the product object. Every test switch is compiled
  out: mutants (`OC_MUT` is 0), the stage-cap override (`oc_stage_cap` is the
  constant 16), the owner-stamp clobber and the binding test flags.
  `Load(Options{Product: true})` refuses any test option.
- `optc_test_bpfel.o`: the same source with `-DOC_TEST_BUILD`: mutants,
  test knobs, for the oracle only.

## Programs

- `lsm/task_alloc`: inheritance, the R12 per-binding task ceiling, witness marks
  (watched tasks only).
- `lsm/bprm_creds_for_exec`: pending reset, frozen generation and class, the
  R31 root anchor (captured at the seeded init's first exec; the init is
  bound to its start time, R6).
- `lsm/bprm_check_security`: one pass per binary handler: anchor and
  reachability, `bpf_d_path`, evaluation in windows of `RulesPerWindow` rules
  (`oc_check_stages`), accumulation.
- `lsm/bprm_committed_creds`: commit with generation revalidation and the
  compromise-8 re-evaluation; the decided-exec receipt (every pass reached a
  decision); an exec with an undecided pass latches the witness.
- `tp_btf/sched_process_fork`, `sched_process_exec`, `sched_process_exit`:
  the witness, the exec-receipt guard (SIGKILL; a failed signal latches),
  task counts.

## Wiring contract (runtime integration)

- **Bind AND the first Publish complete before the runtime releases the
  init** (runc: before `runc start` opens exec.fifo; crun is not supported yet,
  see below).
  The init's first exec after that is the entrypoint; it captures the root
  anchor.
- **Bind proves the init is the runtime's init, before its entrypoint**
  (review R3-C1, option A; `initProof` in node.go). All of: the init holds
  an fd to `<RuntimeConfig.StateRoot>/<container id>/exec.fifo` (same path,
  st_dev and st_ino; default root `/run/runc`); it is blocked in open(2) or
  openat(2) (`/proc/<pid>/syscall`); its image's sha256 is a configured
  runtime binary's (runc's memfd clone has the same content); and that
  image is not on a mount of its own namespace (N1). Anything unproven:
  `ErrInitStarted`, no binding. The state directory is the runtime's, on the
  host: a container workload cannot hold an fd to its fifo, so a late Bind
  of a running workload (whatever it exec'd, a memfd included) is refused.
- **Kernel layer (N1).** At anchor capture the init's pre-exec image must be
  outside its own mount namespace, and it must be the init's first exec
  since Bind. It cannot tell a workload's memfd from runc's memfd clone: for
  a memfd late bind the Bind proof is the closure (shown by
  `KnownGapProbe_MemfdLateBindWithoutTheBindProof`; summaries report it as
  "1 known-gap probe, gap reproduced", never as a pass of the kernel layer,
  n4).
- **`Config.BindDeadline` must cover the create-to-start gap** (kubelet:
  between CreateContainer and StartContainer). A binding whose anchor is not
  captured by the deadline stays NotReady for the container's life.
- Residual: a process that can open the runtime's state fifo (host root,
  the runtime itself) can impersonate a waiting init; that is the trusted
  side of the boundary.
- **A late Bind fails at the first check (n2).** runc removes exec.fifo
  once `start` has read it: `handleFifoResult` ends with
  `return os.Remove(f.Name())` (runc v1.3.1
  `libcontainer/container_linux.go:293`), and the fifo's presence is what
  marks a container "created" (`:896-899`). So after `start`, `Lstat` of
  `<StateRoot>/<id>/exec.fifo` fails and Bind returns `ErrInitStarted`. crun
  (commit 829c4790, 2026-11-16) unlinks it in `start` too:
  `libcrun_status_write_exec_fifo` opens it `O_WRONLY`, then
  `unlink (fifo_path)` (`src/libcrun/status.c:880-886`), called from the
  start path (`src/libcrun/container.c:3757`); the same holds.
- **crun fails closed today.** The proof matches runc's init: runc's
  `create` opens the fifo `O_PATH` (`container_linux.go:471`) and the init
  blocks in `open("/proc/thread-self/fd/N", O_WRONLY)`
  (`libcontainer/standard_init_linux.go:262`). crun's init instead holds the
  fifo's read end, opened by `create` (`status.c:859`), and waits in
  `select(2)` then `read(2)` (`container.c:1698-1718`). Its fd does name the
  fifo, but `/proc/<pid>/syscall` shows select, not open/openat, so every
  crun Bind is refused (`ErrInitStarted`; never Ready). Supporting crun needs
  a crun-specific wait state in `initProof` (select/pselect6/read on that
  fd), qualified on crun (follow-up). Its default state root is `/run/crun`
  (`status.c:98`).
- **`StateRoot` is the agent's own view of the host path (n3).** The proof
  stats `<StateRoot>/<id>/exec.fifo` and compares it with the init's fd
  (st_dev, st_ino and path as seen through `/proc/<pid>/fd`; the kernel
  resolves that path against the root of the reading agent, which for runc
  on a host agent is the host path). A containerized
  agent must mount the runtime's state root at the same path (read-only)
  and set `RuntimeConfig.StateRoot` to it. A WRITABLE hostPath of the
  runtime state root is host-root-equivalent (it controls every
  container's exec.fifo and runtime state), so admission policy must forbid
  it for every pod but the agent's read-only mount.

### Open follow-ups (late bind)

- **n1, pidfd.** Bind reads `/proc/<pid>/...` by pid; between the proof
  and RegisterInit's start-time check a pid could be reused. A pidfd taken
  at Bind (`pidfd_open`), with the `/proc` reads done through it
  (`/proc/self/fdinfo/<pidfd>` or `PIDFD_GET_INFO` on new kernels), would
  bind the proof to the process itself.
- **n5, the open target.** The proof checks that the init is blocked in
  open(2)/openat(2) and that it holds an fd to the fifo, not that the
  blocked open's argument is that fifo (`/proc/<pid>/syscall` gives the
  path as a user pointer). Decoding it (reading the init's memory, or
  `/proc/<pid>/fdinfo` of the half-open file where available) would close
  that last step.
- **crun** (above).

## Review 1 behaviour (G004)

- **Binding and anchor (C4).** The node registers a binding's init at Bind
  (its tid and start time); the kernel counts the init's execs from then. The
  root anchor is captured only at the init's first exec since Bind, before
  the bind deadline (`Config.BindDeadline`, default 60 s). An init that
  exec'd after Bind but before its first policy, a deadline that passed, or
  a container bound after its entrypoint already ran: no anchor, the binding
  is never Ready (`Inspect().Ready` needs the anchor), and its path facts are
  UNKNOWN (Strict denies path-dependent execs). Bind at the runtime's
  exec.fifo point.
- **Re-evaluation kill (C5).** KILLED is counted only when `bpf_send_signal`
  queued the signal; a refusal latches the witness (SIGNAL_FAIL).
- **Child cgroups (R11).** An untracked task in a cgroup below a bound one
  is governed by the nearest bound ancestor (Strict denies its exec and
  fork), up to 32 levels; a task deeper than that on a node with bindings is
  treated as Strict-bound (denied).
- **R12 ceiling (M3).** Not race-free: forks of a binding that pass the
  check concurrently each count, so the count can exceed the ceiling by the
  binding's tasks forking at that moment (at most 2*MaxTasks-1).
- **Mount event (M4).** Without `mnt_namespace.event` the bracket cannot be
  read: the path is UNKNOWN.

## Readiness

`Engine.Ready` is false once the witness latches (an exec or fork the LSM
programs did not see, an undecided exec, a failed guard signal) and once a
task record, work area or mark could not be allocated. The start canary
requires all four LSM programs and both tracepoints to fire.

## Limits (measured)

- Rules: `Limits().MaxRules` (16 windows); a larger policy is refused at
  publish (`ErrUnsupportedPolicy`), never truncated.
- Kernel memory per tracked task: about 2.4 KB (task record 1120 B value,
  local-storage overhead, witness mark), measured by `TestG004TaskMemory` in
  the engine's own memcg.

## Compromises added by G004 (005 §10 style)

10. **Unknown actor facts (Kleene AND).** A rule is the Kleene AND of its
    conjuncts, in the Go reference and both C matchers: a conjunct known
    false makes the rule known false, whatever else is UNKNOWN; otherwise an
    UNKNOWN conjunct makes it an evaluation error; otherwise it matches. A
    conjunct's own value is unchanged, an error never becomes true, and a
    known result never changes (proven by `fullpolicy` TestKleeneANDRefinesSequential
    and caught mutants). Consequence for option C: a task adopted at bind (the
    seeded init, the runtime's process) has UNKNOWN exe facts (R15, R16), so
    an enforced rule that tests the actor AND whose other conjuncts all hold
    (for example the target matches) is an evaluation error: Strict denies
    that exec, Audit reports it. The container's first exec (the entrypoint)
    is such an exec. No trusted "runtime init" actor fact is offered. Where a
    conjunct is known false (the usual case: the target does not match), the
    exec is decided normally, as on the product.

Differences from the product that are not compromises:

- **Container predicate.** Option C compiles each binding's generation with
  its container name, so `Actor.Container` is a known fact. The product's
  shared objects are container-neutral, so the predicate is UNKNOWN there
  (Strict denies even a miss): option C is more precise; both fail closed.
- **Filesystem classes.** The product's per-class facts (`full/filesystem.h`):
  tmpfs, overlay and deleted are known; memfd needs the product's anon-inode
  marking hook, which option C does not attach, so memfd is UNKNOWN for
  tmpfs/hugetlbfs files (as for an unmarked file on the product) and known
  false elsewhere.
- **argv predicates** are refused at publish, as on the product (no
  authoritative argv fact). `StdinIsPipe` is acquired (`full/stdio.h`).
- **Unacquirable container (stricter than Kleene).** The native program
  compiles the container name in; a program without it is malformed
  (FE_STRUCTURAL), so a container predicate that cannot be evaluated is an
  error that no known false conjunct masks, unlike an UNKNOWN fact (the Go
  reference agrees: `structuralError`).

## Tests

`oracle_test.go` (E1), `g003_test.go` (E2-E4), `g004_test.go` (review
conditions, R1-R6, R12, memory) and their mutants need root on an isolated VM:

```sh
CGO_ENABLED=0 go test -c . && sudo EE_OPTC_ORACLE=1 ./optcengine.test -test.v
```
