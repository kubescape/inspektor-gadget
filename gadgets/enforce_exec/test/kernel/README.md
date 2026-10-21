# enforce_exec privileged integration tests

These opt-in tests load real BPF LSM programs and block executions in dedicated
cgroup-v2 targets. Run them on a disposable Linux x86-64 host with root access,
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

Tests can also be compiled with `go test -c` and copied to the test host. For the
kernel compiler test, copy the source tree including `include/` and set
`IG_EXEC_BPF_SOURCE` to the wrapper's absolute path and `IG_EXEC_INCLUDE` to the
include directory. Set the three artifact paths for the runtime test.

The host-side WASM map test additionally checks actual freezing and FD ownership:

```sh
go test -race -v ./pkg/operators/wasm \
  -run 'TestMapFreezeInvalidHandle|TestOwnedMapCleanupAndFreeze|TestStoppedGuestIgnoresCallbacks'
```

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
and Kubernetes managers. Unit regressions cover both managers; a live Kubernetes
DaemonSet/ConfigMap run has not been performed.

After testing, bpftool showed no enforcement programs/maps and no test cgroups
remained. The temporary VM and its SSH key were deleted.

## Evidence boundaries

One kernel/compiler combination is feasibility and integration evidence, not a
compatibility/performance matrix. Generation replacement testing covers bounded
concurrency, not all schedules. The companion checks BPF-LSM return preservation;
it is not a test of IG's existing `trace_lsm` gadget or all LSM combinations.

The kernel probe does not test process targeting, `execveat`, memfd/deleted
executables, concurrent filesystem mutation, descendant cgroups, container startup
gating or crash fail-closed behavior. Normal shutdown cleanup is tested; daemon
crash removes unpinned enforcement. Script/interpreter hooks can see different
generations if an update occurs between their separate decisions.

See the [gadget README](../../README.md) for the supported interface, reporting
limits, readiness semantics and remaining production work.
