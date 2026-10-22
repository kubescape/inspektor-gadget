# enforce_exec privileged integration tests

These opt-in tests load real BPF LSM programs and block executions in dedicated
cgroup-v2 or explicitly selected process targets. Run them on a disposable Linux x86-64 host with root access,
BPF LSM enabled, kernel BTF, `bpf_path_d_path`, `bpf_loop`, Clang, libbpf headers,
and bpftool. Kernel version alone is insufficient: the programs must load and
attach. Nothing attaches without `IG_EXEC_KERNEL_TEST=1`.

## Reproduce

`TestExecKernel` compiles a wrapper around the shipped `program.bpf.c`, adding a
companion LSM program to check return-value chaining. From the repository:

```sh
IG_EXEC_KERNEL_TEST=1 go test -v -count=3 -run '^TestExecKernel$' -timeout=2m \
  ./gadgets/enforce_exec/test/kernel
```

`TestExecRuntime` runs the production object and actual WASM guest through IG's
OCI handler and local runtime. Synthetic container notifications exercise target
binding and updates without requiring a container runtime installation:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -Iinclude/gadget/amd64 -Iinclude \
  -c gadgets/enforce_exec/program.bpf.c -o /tmp/enforce-exec.bpf.o
GOOS=wasip1 GOARCH=wasm go build -C gadgets/enforce_exec/go \
  -buildmode=c-shared -o /tmp/enforce-exec.wasm .
IG_EXEC_KERNEL_TEST=1 \
IG_EXEC_BPF_OBJECT=/tmp/enforce-exec.bpf.o \
IG_EXEC_WASM=/tmp/enforce-exec.wasm \
IG_EXEC_METADATA="$PWD/gadgets/enforce_exec/gadget.yaml" \
  go test -v -run '^TestExecRuntime$' -timeout=2m ./gadgets/enforce_exec/test/kernel
```

`TestExecLaunchRuntime` uses the same three artifacts to exercise the controlled
launcher through the production guest and host. It verifies that an allow policy
lets the application execute in the registered PID, and a deny policy rejects its
first exec before it can write a marker file:

```sh
IG_EXEC_KERNEL_TEST=1 \
IG_EXEC_BPF_OBJECT=/tmp/enforce-exec.bpf.o \
IG_EXEC_WASM=/tmp/enforce-exec.wasm \
IG_EXEC_METADATA="$PWD/gadgets/enforce_exec/gadget.yaml" \
  go test -v -run '^TestExecLaunchRuntime$' -timeout=2m ./gadgets/enforce_exec/test/kernel
```

`TestExecProcessKernel` uses the production object to check task-storage process
scope, child exclusion and a nonleader thread replacing the process through
exec. It needs `IG_EXEC_BPF_OBJECT` and Clang for its small native helper:

```sh
IG_EXEC_KERNEL_TEST=1 IG_EXEC_BPF_OBJECT=/tmp/enforce-exec.bpf.o \
  go test -v -run '^TestExecProcessKernel$' -timeout=2m ./gadgets/enforce_exec/test/kernel
```

`TestExecProcessMarkerFailure` uses a test-only wrapper that forces process marker
creation to fail. The production gadget has no runtime fault-injection parameter:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -Iinclude/gadget/amd64 -Iinclude \
  -c gadgets/enforce_exec/test/kernel/bpf/process_failure.bpf.c \
  -o /tmp/enforce-exec-process-failure.bpf.o
IG_EXEC_KERNEL_TEST=1 \
IG_EXEC_PROCESS_FAILURE_OBJECT=/tmp/enforce-exec-process-failure.bpf.o \
  go test -v -run '^TestExecProcessMarkerFailure$' -timeout=2m ./gadgets/enforce_exec/test/kernel
```

It verifies audit/off permit nonleader exec and mark tracking degraded; enforce
rejects with ENOMEM and retains selection. Persistent health survives a full
reporting ring and is recorded even while off, when ordinary reports are disabled.

`TestExecTraceLSMCoexistence` loads the production execution hook from `trace_lsm`
in both attachment orders, with tracing enabled, disabled and filtered:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -Iinclude/gadget/amd64 -Iinclude \
  -c gadgets/trace_lsm/program.bpf.c -o /tmp/trace-lsm.bpf.o
IG_EXEC_KERNEL_TEST=1 \
IG_EXEC_BPF_OBJECT=/tmp/enforce-exec.bpf.o \
IG_EXEC_TRACE_LSM_OBJECT=/tmp/trace-lsm.bpf.o \
  go test -v -run '^TestExecTraceLSMCoexistence$' -timeout=2m ./gadgets/enforce_exec/test/kernel
```

Tests can also be compiled with `go test -c` and copied to the test host. For the
kernel compiler test, copy the source tree including `include/` and set
`IG_EXEC_BPF_SOURCE` to the wrapper's absolute path and `IG_EXEC_INCLUDE` to the
include directory. Set the three artifact paths for the runtime test.

The host-side WASM map test additionally checks actual freezing and FD ownership:

```sh
go test -race -v ./pkg/operators/wasm \
  -run 'TestMapFreezeInvalidHandle|TestOwnedMapCleanupAndFreeze|TestStoppedGuestIgnoresCallbacks'
```

## Launcher validation — 2026-10-22

Validated on a disposable Debian 13 amd64 VM with Linux
`6.12.111+deb13-amd64` and BPF LSM enabled, without a container runtime:

- `TestExecLaunchRuntime` passed three consecutive runs with the production
  BPF object, freshly built WASM guest, and native host. An allow policy executed
  the application under the registered PID; deny rejected its first exec before
  its marker file could be written.
- The actual `ig launch` command passed allow, first-exec deny, missing enforcement
  consent, startup-timeout, and SIGTERM cleanup checks using a local OCI image.
- Native race tests covered the private capability, identity rejection, failed
  binding, gating, cancellation, same-PID exec, environment confidentiality and
  descriptor cleanup. A nonexistent proc root in the WASM binding test confirms
  that controlled launches bypass discovery and the ptrace path.
- Startup callback lifecycle tests, policy tests, targeted existing-process
  binding tests, vet and scoped lint passed. No BPF program logic changed.

The reusable launcher and integration tests are in `pkg/processlaunch` and
`launch_runtime_test.go`. These checks cover initial activation; they do not
establish crash-persistent enforcement or extend process selection to children.

## Results — 2026-10-21

Validated on a temporary DigitalOcean Debian 13 x86-64 VM:

- Kernel: `6.12.111+deb13-amd64`, Debian `6.12.111-1 (2026-09-28)`.
- Clang: Debian `19.1.7 (3+b1)`; bpftool `7.5.0`, libbpf `1.5`.
- Active LSMs: `lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm`.

The earlier unthrottled probe passed three consecutive runs, with 17,241
reported generation-correlated decisions and zero mismatches. The current tests
use the shipped program, including its reporting rate limit:

| Scenario | Observed result |
| --- | --- |
| Scope and paths | Managed allow succeeds; managed deny returns EPERM; unmanaged execution succeeds. Sibling-directory boundaries, symlink escape, rename out of an allowed directory, and recreated allowed file behave as expected. |
| Modes and precedence | Explicit deny overrides prefix allow; audit and off permit execution. |
| Scripts | Allowing a script alone is insufficient; also allowing its resolved interpreter permits execution. |
| Path resolution failure | Buffer overflow denies in enforce mode, permits in audit, and increments the error counter. |
| Reporting saturation | All 1,000 requested executions return EPERM. Both buffer-loss and rate-limit counters increase. One recorded run lost 215 reports to buffer pressure and suppressed 785 through the rate limit. |
| Generation replacement | 200 replacements while executing concurrently; both allow and deny reports observed with zero generation/verdict mismatches and zero unexpected execution errors. One recorded run observed 580 rate-limited reports (182 allow, 398 deny). |
| Actual OCI/runtime lifecycle | Production BPF + guest WASM: binding activates enforcement; invalid/stale updates retain the prior generation; a valid update reverses allowed/denied paths; target deletion and runtime shutdown release enforcement. |
| Host map lifecycle | Freeze prevents modification; cleanup closes owned FDs and retains borrowed maps; stopped callbacks return without deadlocking. |

Ordinary CLI/Docker smoke validation also passed with an image built by
`ig image build --local` (amd64 and arm64 compilation):

1. Default admission rejects the mutator before activation.
2. `ig run --allow-enforcement --verify-image=false ...` discovers an existing
   Docker container through the normal local manager and emits enforcing status.
3. Its `/usr/bin/true` allow rule permits that executable; `/usr/bin/false` is
   rejected with an execution permission error.
4. Stopping IG restores `/usr/bin/false`'s normal exit code of 1.

This smoke test exercised the container's mount namespace and Docker OverlayFS.
It exposed and led to fixes for datasource-only manager activation in both local
and Kubernetes managers. Unit regressions cover both managers; the subsequent live Kubernetes validation
is recorded below.

After the earlier Docker validation, bpftool showed no enforcement programs/maps
and no test cgroups remained. That temporary VM and its SSH key were deleted.

## Process, coexistence and Kubernetes validation — 2026-10-21

A disposable Debian 13 x86-64 host ran the production kernel tests,
`TestExecProcessKernel`, and all six `TestExecTraceLSMCoexistence` cases successfully
on `6.12.111+deb13-amd64`. The process test verifies exact process scope, child
exclusion and continued enforcement after exec by a nonleader thread. The
coexistence test verifies denial preservation in both attachment orders even
when observation is disabled or filtered.

The same host ran K3s `v1.36.5+k3s1`, using the official chart's DaemonSet, RBAC and
configuration with a locally built daemon binary mounted into a Debian test
image. A local OCI store supplied the production gadget image. This was a
single-node integration test, not a published daemon-image test.

The ConfigMap smoke test passed these checks:

- Generation 1 allowed `/usr/bin/true` and blocked `/usr/bin/false`.
- Updating the policy to generation 2 reversed those decisions.
- An invalid update retained generation 2 and its execution decisions.
- A corrected update installed generation 3.
- The BPF program ID (350 initially, 576 on the final repeat) and daemon Pod UID remained unchanged within each run;
  there was no daemon restart.
- All 22 initial and 23 final-repeat `/usr/bin/echo` probes remained denied across the updates.
- Deleting the instance ConfigMap removed enforcement and restored normal execution.

The daemon used host-owned program-type and kfunc restrictions (`lsm` and
`bpf_path_d_path`). Pure admission tests additionally cover helper restrictions,
linked functions, callbacks, kfunc names, immutable administrator snapshots and
late instruction changes before loading.

The standalone daemon file-store smoke test also passed: valid edits installed
generations 1, 2 and 3 while preserving the BPF program ID; malformed instance
files and invalid policies retained the last-good decisions; deleting the file
released enforcement. The watcher polls once per second and stops when the
service closes.

The final repeat also ran the actual CLI process binding with exclusive ptrace
activation, a strict program/helper/kfunc allowlist, repeated and nonleader exec,
child exclusion and process-exit reporting. The standalone daemon file-store
repeat passed generations 1/2/3, malformed/invalid last-good retention, unchanged
BPF program ID and release on deletion. Host race tests covered exclusive stops,
external SIGCONT resistance, signal reinjection and partial-stop cleanup.

After the final tests, no enforcement programs, maps or test cgroups remained.
The temporary Kubernetes VM and its SSH key were deleted.

## Evidence boundaries

One kernel/compiler combination is feasibility and integration evidence, not a
compatibility/performance matrix. Generation replacement testing covers bounded
concurrency, not all schedules. The production `trace_lsm` execution hook is now tested in both attachment
orders; other LSM hooks and combinations remain outside this coverage. The
Kubernetes probes demonstrate sampled continuity, not every possible schedule.

These tests do not cover `execveat`, memfd/deleted
executables, concurrent filesystem mutation, descendant cgroups, container startup
gating or crash fail-closed behavior. Normal shutdown cleanup is tested; daemon
crash removes unpinned enforcement. Script/interpreter hooks can see different
generations if an update occurs between their separate decisions.

See the [gadget README](../../README.md) for the supported interface, reporting
limits, readiness semantics and remaining production work.

## Process marker failure validation — 2026-10-21

A fresh disposable Debian 13 amd64 droplet on Linux `6.12.111+deb13-amd64` ran:

- `TestExecProcessMarkerFailure`: forced marker-creation failure in enforce,
  audit and off; enforce returns ENOMEM without losing selection; audit/off
  execute successfully and retain sticky degraded health after marker loss.
  Health remains readable with the ordinary reporting ring full or reporting off.
- `TestExecProcessKernel`: production-object thread-group selection, successful
  nonleader exec continuity, child exclusion and exit cleanup.
- `TestExecProcessFailureRuntime`: actual OCI/WASM guest and exclusive host process
  binding, in both audit and off. Forced failure allows exec; status snapshots
  report degradation; attempted enforcement promotion is rejected at the same
  generation. A new instance validates and rebinds the same live process, then
  blocks denied executions before and after a subsequent leader exec.
- Existing container `TestExecRuntime`, full `TestExecKernel`, and all six
  `TestExecTraceLSMCoexistence` cases pass with the changed production program.

Run the new runtime test with `IG_EXEC_PROCESS_FAILURE_OBJECT`, `IG_EXEC_WASM`,
`IG_EXEC_METADATA`, and `IG_EXEC_KERNEL_TEST=1`. The failure object is compiled
using the wrapper command above. This exercises a deterministic helper-failure
substitute, not induced host-wide memory exhaustion. Production amd64 and arm64
objects compile; only amd64 has been exercised on a running kernel here.
