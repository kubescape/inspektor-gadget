# enforce_exec kernel feasibility probe

This opt-in test loads real BPF LSM programs and blocks executions in a dedicated
cgroup. It is separate from the gadget image: `build.yaml` still ships only the
WASM configuration spike. No Kubescape component is required.

## What it implements

- Global, non-sleepable `lsm/bprm_check_security`, preserving a previous BPF LSM
  return value. An explicit cgroup-v2 ID binding limits enforcement scope.
- `bpf_path_d_path` on the trusted `bprm->file->f_path`, matching resolved paths
  at execution time. Exact paths and directory prefixes ending in `/` are supported.
- A complete, frozen ARRAY holding a generation header and rules. A HASH_OF_MAPS
  binding is replaced with one map update; the hook looks up the inner map once.
  Deny rules take precedence over allow rules, followed by the default action.
- Synchronous `-EPERM` in enforce mode; audit reports the decision but permits
  execution. Off bypasses evaluation. Path-resolution errors deny in enforce mode.
- One shared 4 KiB ring buffer for this probe's bindings, with per-CPU decision,
  report-loss and path-error counters. Failure to reserve an event never changes
  the decision. This bounds buffering; it does not implement a reporting rate cap.
- Unpinned links owned by the test process; removing a binding restores execution.

The probe has **8 binding slots, 8 rules per generation and a 256-byte path buffer**.
Each inner map has 9 slots of 288 bytes (2,592 bytes of values, excluding kernel
metadata/allocation overhead). Replacement temporarily retains old and new maps;
these are test limits, not the production memory budget. They intentionally differ
from the WASM parser's illustrative limits. There is no parser-to-BPF compiler yet.

`bpf_loop` performs bounded byte comparisons. A regular nested comparison loop
exceeded the verifier's processed-instruction budget on the tested kernel. The
64-bit comparison offset retains a compiler barrier so bounds checking and pointer
arithmetic use the same verifier-tracked scalar. Explicit signed return handling
avoids compiler transformations that the tested LSM verifier could not bound.

## Run on a disposable Linux x86-64 host

Requires root, cgroup v2 with writable cgroupfs, BPF LSM enabled, kernel BTF,
`bpf_path_d_path`, `bpf_loop`, Clang and libbpf headers, and bpftool. Kernel version
alone is insufficient: the test compiles, loads, and attaches the actual program.
The initial target is Linux 6.12 or newer; other versions are not validated here.

```sh
IG_EXEC_KERNEL_TEST=1 go test -v -count=3 -timeout=2m ./gadgets/enforce_exec/test/kernel
```

Alternatively, compile with `go test -c`, copy the binary and `bpf/exec.bpf.c` to
the host, and set `IG_EXEC_BPF_SOURCE` to the source's absolute path. The host still
needs Clang, headers and bpftool. Without the opt-in environment variable, the test
skips without attaching anything.

## Results — 2026-10-21

Three consecutive runs passed on a temporary DigitalOcean Debian 13 x86-64 VM:

- Kernel: `6.12.111+deb13-amd64`, Debian `6.12.111-1 (2026-09-28)`.
- Clang: Debian `19.1.7 (3+b1)`; bpftool `7.5.0`, libbpf `1.5`.
- Active LSMs: `lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm`.

| Scenario | Observed result |
| --- | --- |
| Scope and paths | Managed allow succeeds; managed deny returns EPERM; unmanaged execution succeeds. Sibling-directory prefix, symlink escape, rename out of an allowed directory, and recreated allowed file behave as expected. |
| Modes and precedence | Explicit deny overrides prefix allow; audit and off permit execution. |
| Scripts | Allowing a script alone is insufficient; allowing its resolved interpreter as well permits execution. |
| Path resolution failure | A path exceeding the buffer denies in enforce mode, permits in audit, and increments the error counter. |
| Reporting saturation | All 100 requested executions return EPERM with no ring reader. Loss counters increase in every run. |
| Generation replacement | 200 replacements per run while executing concurrently; 5,543 / 5,614 / 6,084 reported decisions, both allow and deny observed, zero generation/verdict mismatches and zero unexpected execution errors. |
| Binding removal | Previously denied execution succeeds after deletion. |

After the tests, bpftool showed no probe programs or maps, and no test cgroup
remained. Local policy/WASM tests, `go vet` on this test package, and repository
`golangci-lint` on this test package passed (zero lint issues).

## Evidence boundaries and next integration work

This establishes feasibility on one kernel/compiler combination. Generation
replacement testing is bounded concurrency evidence, not an exhaustive proof.
The companion LSM program preserves previous returns; this is not a test of IG's
existing `trace_lsm` gadget or all other LSM combinations.

The test launches children directly into a cgroup using `UseCgroupFD`. It does not
resolve container IDs, watch container lifetimes, include descendant cgroups, or
guarantee that policy precedes a container's first execution. Process bindings,
container mount namespaces, OverlayFS, `execveat`, memfd/deleted executables,
concurrent filesystem changes, performance and multiple kernels remain untested.
Path authorization is not executable-content integrity, and an allowed interpreter
can execute code without another executable-file check.

Unpinned enforcement ends when its owning process exits; fail-closed crash/restart
behavior is not provided. Script and interpreter checks are separate hook calls;
a policy replacement can occur between them. Atomicity here is per hook decision.

Before wiring this into `ig run`, implement framework admission/consent before
attachment, lifetime-safe target resolution, preparation and replacement through
the host interface, readiness/cleanup, and a bounded verdict datasource. The
configuration compiler must enforce the actual kernel limits and define all
unsupported rule semantics. Kubernetes reconciliation and the optional node-agent
adapter remain separate integration work.
