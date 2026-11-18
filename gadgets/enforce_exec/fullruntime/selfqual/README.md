# enforce_exec behavioural self-qualification (D4 research prototype)

**TEST-ONLY. Not a product admission path.** Nothing here is reachable from a
product build. The findings, the evidence and the limits are in the D4
report; this file says what the code is and how to run it.

## What it is

An alternative to the exact kernel pin (`VerifyKernel`: BTF sha256, GNU
build-id, release). Instead of asking "is this a kernel build we qualified?",
the agent loads the engine, drives it through synthetic exec probes in
throwaway cgroups and admits the kernel only if every probe shows the
contract's syscall outcome **and** the engine's own kernel-side bookkeeping.

- `engine.go`: the `Engine` interface the runner drives, and the counters and
  events it reads, in contract terms.
- `run.go`: `Run`, the admission: static preconditions, every probe in Strict
  and in Audit, a clean engine and a clean teardown. Everything else is
  `ErrNotQualified`.
- `probes.go`: the 18 probes. `model.go`: the contract as one function
  (`model`), plus the invariants that hold for racy probes too (`session.go`).
- `stage.go`, `helper/probe.c`: the embedded, sha256-pinned static helper. It
  runs from a sealed memfd in a private mount namespace and builds the probe
  fixtures on a private tmpfs.
- `hold.go`: parks an exec between two binfmt passes with a fanotify
  `FAN_OPEN_EXEC_PERM` mark, for the deterministic mid-exec probes.
- `refengine/`: a reference engine (BPF LSM + BTF tracepoints + CO-RE) that
  loads on stock kernels. **It is not the shared product engine.** It exists
  because the product engine's objects are pinned per kernel build and do not
  load anywhere else. It also carries the deliberate bugs ("mutants") of the
  negative controls.
- `refengine/oracle_test.go`: the semantic oracle, with hand-written
  expectations that do not use the admission suite's model.
- `cmd/ee-selfqual`: runs a qualification on the node it is started on.

## The flag

`fullruntime` has the gate (`kernel_selfqual.go`): a node started with
`WithKernelSelfQualification(ctx, qualifier)` skips the pinned identity check,
keeps the static preconditions, and stays NotReady with every binding refused
until the qualifier admits. A refusal is terminal for the process. The option
does nothing unless the binary is built with `-tags enforce_exec_selfqual`.

The product image admission (`admitSharedProductImage`) is unchanged and
still needs a pinned product object, so with today's engine this path cannot
admit a kernel the pin would not: it needs an engine object that is not built
per kernel.

## Build and run

```sh
./build.sh                       # helper + pinned sha256, reference engine object
CGO_ENABLED=0 go build ./cmd/ee-selfqual
sudo ./ee-selfqual               # ADMITTED or REFUSED, with the probe table
sudo ./ee-selfqual -detach rq_bprm_check   # negative control: must be REFUSED
sudo ./ee-selfqual -mutant audit-blocks    # negative control: must be REFUSED
EE_SELFQUAL_ORACLE=1 go test -c ./refengine && sudo EE_SELFQUAL_ORACLE=1 ./refengine.test -test.v
```

Needs root, x86_64, cgroup v2, kernel BTF, `bpf` in the active LSM list
(`lsm=...,bpf` on the kernel command line where the distro default lacks it),
fanotify permission events and exec from a memfd (`vm.memfd_noexec` < 2).
