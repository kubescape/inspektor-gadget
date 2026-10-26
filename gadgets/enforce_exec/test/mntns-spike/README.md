# Mount namespace validation spike

Diagnostic experiment only; no production gadget or binding API is changed.
Run only on a disposable Linux amd64/arm64 host with root, BPF LSM, cgroup v2,
Docker, kernel BTF and `bpf_path_d_path`. Docker must be able to pull Alpine and
its package repositories; the privileged case installs util-linux inside the
container. The harness creates normal and privileged containers and removes
its own containers and BPF attachments on normal completion or assertion panic.
Do not run on a production host. It intentionally demonstrates an enforcement
bypass in the proposed experimental filter.

```sh
go build -o /tmp/mntns-spike ./gadgets/enforce_exec/test/mntns-spike
case "$(uname -m)" in
  x86_64) bpf_arch=x86; gadget_arch=amd64 ;;
  aarch64|arm64) bpf_arch=arm64; gadget_arch=arm64 ;;
  *) exit 1 ;;
esac
clang -O2 -g -target bpf -D__TARGET_ARCH_${bpf_arch} \
  -Iinclude/gadget/${gadget_arch} \
  -c gadgets/enforce_exec/test/mntns-spike/bpf/spike.bpf.c \
  -o /tmp/mntns-spike.bpf.o
sudo env IG_EXEC_KERNEL_TEST=1 /tmp/mntns-spike /tmp/mntns-spike.bpf.o
```

The harness uses the configured default Docker runtime. Record its version and
configuration; testing another installed binary without making Docker use it
would not validate that runtime. On the disposable Debian VM we first used the
distribution runtime, then replaced `/usr/sbin/runc` with the SHA256-checked
upstream v1.5.2 executable. No such replacement is needed on existing systems.

At `bprm_check_security`, the diagnostic records current cgroup, PID, current
mount-namespace inode, bound container init's mount-namespace inode, resolved
executable path, and decision. It compares two modes:

- `skip=0`: default-deny for the exact target cgroup, allowing `/bin/`, `/sbin/`,
  `/usr/bin/` and `/usr/sbin/` executable paths.
- `skip=1`: the same policy, but skip decisions when the current mount namespace
  differs from the bound namespace. A failed namespace read is not exempted.

The map is mutable to switch experimental modes; it is not the production frozen
policy implementation. Ring-buffer exhaustion denies without a report, so any
missing required workload verdict fails the experiment. This is a small sampled
test, not a proof of complete reporting or all runtime paths.

Checks cover allowed exec, blocked `/tmp/busybox`, a workload-owned `/runc`,
release after unbinding, and `unshare --mount` in the privileged container.
Assertions require workload verdicts in the expected namespace, preventing a
helper failure from masquerading as correct workload denial. Helper candidates
are diagnosed from namespace/path records, not authenticated by basename.

See [results and interpretation](results.md). Namespace-changing workloads,
rootless runtimes, shared namespaces, namespace reuse/lifetime, CRI/Kubernetes
exec and first-exec binding races need separate analysis before any production
change. This harness does not test live container-cache integration.
