# enforce_exec

An execution-policy gadget using IG's normal eBPF/WASM OCI image and lifecycle.
It blocks executable paths for one explicitly selected container or process using BPF LSM.
It runs with `ig` or the existing Kubernetes DaemonSet and stored gadget instances;
no Kubescape component is required.

The host must enable `operator.oci.allow-enforcement`. The image declares
`behavior: mutator`, so the default host rejects it before any image code runs.
Undeclared legacy gadgets retain their existing behavior. This is an explicit
consent mechanism for trusted, administrator-approved images, not a sandbox for
untrusted BPF code. Keep image verification and digest admission enabled in
production. Host-owned `operator.ebpf.policy` independently restricts program types,
builtin helpers and kfuncs; see [BPF admission](../../docs/spec/operators/oci.md#host-bpf-admission-policy).
An absent policy preserves legacy compatibility. Image parameters cannot override it.

## Configuration and limits

```yaml
version: 1
binding:
  container:
    runtime: containerd
    id: <full-container-id>
policy:
  mode: enforce
  exec:
    default: deny
    rules:
      - name: approved-executables
        target:
          path: ["/usr/bin/**", "/opt/app/bin/**"]
        action: allow
```

`exec-policy` is YAML passed by value, not a path read by the daemon. The kernel
compiler supports one container or process binding, audit/enforce/off, allow/deny default,
exact absolute paths and trailing `/**` directory patterns. Deny matches override
allow matches. Rule modes must be empty or match the policy mode. Unsupported
predicates fail before attachment. Named rules
and origin retain the standalone policy vocabulary used by the proposed
SandboxPolicy adapter; a complete CRD compiler is not included.

Actual kernel limits are **8 expanded paths per policy, 255 path bytes, and one
target binding per gadget instance**. An inner map holds a header and eight
288-byte entries: 2,592 bytes of values plus kernel allocation/metadata overhead.
Replacement temporarily retains two generations. These are rule-value sizes,
not a total BPF memory budget: map metadata, per-CPU scratch/counters and task
storage add overhead. Process task storage can grow with marked threads that
attempt exec and then fail before replacing the process; those entries remain
until their tasks exit. Only the rule count and reporting buffer have the fixed
bounds stated here. The parser additionally bounds
input to 64 KiB; its broader authoring limits do not override kernel limits.

For a process target, replace the container binding with:

```yaml
binding:
  process:
    node: <node-name>
    bootID: <host-boot-id>
    hostPID: 12345
    startTimeTicks: 987654
```

`hostPID` is the host thread-group leader PID. `startTimeTicks` is field 22 of its
`/proc/<pid>/stat`, and `bootID` comes from `/proc/sys/kernel/random/boot_id`.
`node` must match `NODE_NAME`, or the host name for standalone execution. The
host verifies all four fields, obtains a pidfd, and seeds BPF task storage tied
to the actual process. Reusing its numeric PID does not inherit enforcement.
The binding covers the selected thread group, including execution by a nonleader
thread and subsequent executions after it becomes leader. Child processes are
not included.

Activation briefly pauses every thread using exclusive ptrace ownership
(`PTRACE_SEIZE` and `PTRACE_INTERRUPT`) before seeding task storage. Another
process's SIGCONT cannot release these tracer-owned stops. IG then detaches and
resumes a previously running group; a fully stopped group remains stopped.
Partially stopped groups, an existing tracer and IG itself are rejected. The
bounded pause closes the race with an execution already past the LSM hook.
Process binding requires the host PID namespace and permission to trace the
target (`SYS_PTRACE` in the default chart capabilities). The pidfd exit watcher
removes the binding and emits `target-removed`.

Path resolution uses `bpf_path_d_path` on the executable file in the calling
task's root. A symlink is checked at its resolved destination; renaming a file
out of an allowed directory removes that path permission. Resolution errors,
including paths exceeding the fixed buffer, deny in enforce mode and permit in
audit mode. Scripts and their interpreters are checked separately. Allowing an
interpreter does not restrict the code it can interpret.

The enforce and audit examples deny `/usr/bin/dash`, assuming it is the resolved
executable behind `/usr/bin/sh`. Run `readlink -f /usr/bin/sh` inside the target
container and substitute its output in the deny rule. Denying the symlink path
alone will not match its resolved destination. Add the resolved paths of any
other shells you want to deny; this example only denies the selected shell.

## Build and run

Requires BPF LSM enabled, cgroup v2, kernel BTF and the `bpf_path_d_path` kfunc;
Linux 6.12 is the tested baseline. Successful loading/attachment is the final
capability check. Current WASM imports require the updated IG host: older hosts
without the map-freeze and process-binding imports fail image initialization
before any BPF program attaches.
Use matching host/image builds from this branch.

```sh
sudo ig image build --local -t enforce_exec:spike gadgets/enforce_exec
sudo ig run --allow-enforcement --verify-image=false enforce_exec:spike \
  --exec-policy "$(cat gadgets/enforce_exec/examples/enforce.yaml)"
```

Unsigned images and `verify-image=false` are for local development. The existing
container manager must discover the selected runtime and full ID, and ordinary
IG selectors must include that container. Other containers remain unaffected.
Do not put container-ID prefixes or cgroup IDs in the policy.

For Kubernetes, configure the existing Helm chart's daemon host settings:

```yaml
# Required only when using process bindings.
hostPID: true
config:
  operator:
    oci:
      allow-enforcement: true
```

The chart defaults `hostPID` to false. Custom capability lists must supply the
process-inspection and ptrace permissions needed for the activation pause. Container bindings
do not require this opt-in. Keep the production image trust settings. Supply policy through the ordinary
stored-instance `paramValues.operator.oci.wasm.exec-policy`, as in
[`examples/instance.yaml`](examples/instance.yaml). This does not introduce a new
Kubernetes operator or CRD. The future node-agent adapter translates SandboxPolicy
into this standalone interface; CRD watches, merging and status stay in node-agent.

## Activation, replacement and status

1. The host checks behavior admission before image operators initialize.
2. WASM pre-start parses and compiles the full policy before any BPF attachment.
3. IG loads/attaches the BPF program with an empty, inactive binding map. The guest
   creates and freezes a complete candidate generation.
4. IG's container datasource supplies runtime, full ID, cgroup ID and cgroup-v2 path. Only an exact
   runtime/ID match with a nonzero cgroup and clean, non-root v2 path binds the generation and activates policy.
   Process bindings instead use the validated pidfd and task-storage activation
   described above.
5. Container deletion or selected-process exit removes the binding. Instance shutdown releases the binding,
   generation maps and unpinned BPF links, including partial-start failure cleanup.

The `status` datasource emits state, revision, generation, cgroup ID, host PID,
request ID and message.
`waiting-for-target` means no target has been protected. `enforcing`, `auditing`
and `off` describe the installed mode. Other states include `target-removed`,
`update-rejected`, `error` and `stopped`. An update rejection leaves the reported
revision/generation and last-good kernel policy intact. These events describe
policy readiness; the daemon's generic running-instance state alone does not.

An embedding host can publish to the `exec_policy_updates` input datasource:

- `policy` (string): complete standalone policy YAML.
- `expected_generation` (uint64): last observed generation, initially 1.
- `request_id` (uint64): correlation identifier echoed in the status acknowledgment.

Callbacks serialize policy updates and container events. Updates require the same
container or process identity. Parsing, compilation, map population and freezing finish
before replacing the bound inner map with one update. Failures retain the prior
generation. Successful updates increment the generation and emit status. This
input is an embedding interface, not a new public RPC or CLI file watcher.
An embedding host must emit asynchronously when reacting to a guest status event;
synchronous emission back into the same guest would reenter its serialized callback.
The WASM host recognizes the image's `live-update-parameter`,
`live-update-datasource`, `live-update-status` and `live-update-field` annotations.
It supplies the expected generation and a request ID, then requires a matching
status acknowledgment before accepting the new instance configuration.

For this gadget, changes to the existing ConfigMap's
`operator.oci.wasm.exec-policy` go through that protocol without restarting the
instance or replacing its BPF program. Invalid policies retain the last-good
configuration and enforcement. Structural changes, such as the image, binding
identity or other parameters, are rejected for a running update-capable instance.
Deleting the ConfigMap or excluding the node explicitly removes the instance.
Legacy gadgets without update support retain IG's existing restart behavior.
There is no new public update RPC. The future node-agent adapter can use the same
standalone input and acknowledgment protocol.

Standalone `ig daemon` also reconciles its existing stored `.gadget` instance
files once per second. Changes to `exec-policy` use the same acknowledged update
path. Malformed files or invalid policies retain the running last-good instance;
deleting its file explicitly removes enforcement. Closing the service stops the
watcher. This watches daemon instance files, not policy files passed to `ig run`.
Last-good retention lasts for the running instance; restarting the daemon reads
the persisted desired configuration again.

The `verdict` datasource reports generation, cgroup, deny decision, mode,
path-resolution result and resolved path. `deny=1` in audit mode means would-deny;
only enforce mode blocks for ordinary policy decisions. If transferring a process
marker to an executing nonleader thread fails, enforce mode rejects the execution
with ENOMEM to preserve process selection. Audit and off permit execution; subsequent
process tracking may be lost. The helper does not identify the precise failure
cause; ENOMEM is the error chosen for the enforce-mode rejection.

The fixed-size `process_health` array stores cumulative `failures` and a sticky
`degraded` flag, independent of event delivery and policy generations. Degradation
means marker continuity is no longer guaranteed; it does not prove the execution
ultimately succeeded. Status includes `tracking_failures` and `tracking_degraded`
snapshots on lifecycle and update activity, rather than periodic notifications.
The map remains the persistent source when event buffers are full.

Process policy transitions from audit or off to enforce require explicitly removing
the instance and creating a new one, which validates identity and binds under the
exclusive activation pause again. This applies even when health is clean: a prior
audit/off execution could still be in flight when an update reads health. Live
updates within enforce, from enforce to audit/off, and between audit/off remain
supported. Rejected promotions leave the active generation unchanged. Container
mode changes retain their existing behavior.
A shared 4 KiB ring buffer bounds pending reports.
At most 100 report attempts per CPU per second are permitted, independently of
verdict evaluation. Per-CPU kernel counters track denied/allowed decisions,
submitted reports, buffer loss, path errors and rate-limited reports. The counters
are available in the `counters` BPF map; periodic metric export remains to be wired.
Enforcement continues when reports are dropped or rate limited.

## Validation and scope

```sh
go test -race ./gadgets/enforce_exec/policy ./gadgets/enforce_exec/test/unit
go vet ./gadgets/enforce_exec/policy ./gadgets/enforce_exec/test/unit
```

Unit tests compile the real WASM guest, test actual OCI admission and initialization,
and exercise callbacks with mock map/data services, including failure retention.
The [privileged tests and recorded evidence](test/kernel/README.md) run real BPF
and the actual guest through IG on a disposable Linux host.

This is an implementation spike. It protects future executions after target-bound
status; it does not gate a container's first execution. Binding covers the supplied
cgroup exactly, not all descendant cgroups. Discovery/removal notification delays
are possible. Links are unpinned, so daemon death ends enforcement. Policies from
multiple gadget instances compose through LSM (a denial from any remains a denial).
Generation atomicity is per hook, not across script/interpreter hooks. The
`trace_lsm` execution hook preserve earlier denials; its other hooks have not
been audited for other enforcement gadgets. Executable integrity, crash fail-closed semantics, the full
SandboxPolicy vocabulary and a kernel compatibility/performance matrix remain
outside this implementation.
