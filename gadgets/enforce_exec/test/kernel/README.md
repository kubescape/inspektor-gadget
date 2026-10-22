# enforce_exec kernel validation

Run only on a disposable Linux amd64 host with root, cgroup v2, BPF LSM enabled,
kernel BTF, `bpf_path_d_path`, Clang, libbpf headers and bpftool. Kernel version
alone does not establish support. Nothing attaches without `IG_EXEC_KERNEL_TEST=1`.

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -Iinclude/gadget/amd64 -Iinclude \
  -c gadgets/enforce_exec/program.bpf.c -o /tmp/enforce-exec.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -Iinclude/gadget/amd64 -Iinclude \
  -c gadgets/trace_lsm/program.bpf.c -o /tmp/trace-lsm.bpf.o
IG_EXEC_KERNEL_TEST=1 \
IG_EXEC_BPF_OBJECT=/tmp/enforce-exec.bpf.o \
IG_EXEC_METADATA="$PWD/gadgets/enforce_exec/gadget.yaml" \
IG_EXEC_TRACE_LSM_OBJECT=/tmp/trace-lsm.bpf.o \
  go test -v -count=3 -timeout=5m ./gadgets/enforce_exec/test/kernel
```

For `TestExecKernel`, the wrapper source and `include/` must also be available.
Set `IG_EXEC_BPF_SOURCE` and `IG_EXEC_INCLUDE` if running a compiled test binary
outside the source checkout. Tests can be built with `go test -c` and copied to
the VM along with objects, metadata, wrapper and headers. No WASM artifact is used.

## Coverage

- `TestExecKernel`: real path/cgroup decisions, audit/enforce/off, scripts,
  reporting saturation, immutable-map write rejection, live membership changes,
  and sampled continuous denial across repeated overlapping replacements.
- `TestExecTraceLSMCoexistence`: both attachment orders with tracing enabled,
  disabled and filtered. The production enforcement object is used.
- `TestExecRuntime`: actual OCI/BPF/native control through the instance manager;
  startup bindings, frozen policy, synchronous bind/unbind, failed-candidate
  retention, explicit overlap (both conflicting policies deny), new revision,
  old cleanup and final release. Container-cache input is synthetic so the test
  isolates lifecycle and map control from discovery installation.

Local race tests cover manager startup/cleanup/cancellation, controller binding
errors and capacity, stale deletions, concurrent churn, compiled map validation,
and cache replay ordering. These replace the removed parameter-handshake and
process/launcher tests.

A runtime or overlap test does not establish first-container-exec protection,
crash persistence or exhaustive scheduling coverage. Only amd64 runtime behavior
has been exercised; arm64 compilation is checked separately.

## Validation on 2026-10-22

The complete privileged suite passed three consecutive times with Go's race
detector on Debian 13, amd64, kernel `6.12.111+deb13-amd64`, with BPF LSM enabled.
A separate native CLI check used two real Docker containers: the selected
container was denied, the control container remained unaffected, verdicts carried
revision 71, and stopping IG released enforcement. Production BPF objects also
compiled for amd64 and arm64.
