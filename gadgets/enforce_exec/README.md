# enforce_exec

An execution-policy gadget using IG's normal eBPF/WASM OCI image and lifecycle.
It blocks executable paths for one explicitly selected container using BPF LSM.
It runs with `ig` or the existing Kubernetes DaemonSet and stored gadget instances;
no Kubescape component is required.

The host must enable `operator.oci.allow-enforcement`. The image declares
`behavior: mutator`, so the default host rejects it before any image code runs.
Undeclared legacy gadgets retain their existing behavior. This is an explicit
consent mechanism for trusted, administrator-approved images, not a sandbox for
untrusted BPF code. Keep image verification and digest admission enabled in
production. BPF program/helper allowlists remain separate framework work.

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
compiler supports one container binding, audit/enforce/off, allow/deny default,
exact absolute paths and trailing `/**` directory patterns. Deny matches override
allow matches. Rule modes must be empty or match the policy mode. Process
bindings and other unsupported predicates fail before attachment. Named rules
and origin retain the standalone policy vocabulary used by the proposed
SandboxPolicy adapter; a complete CRD compiler is not included.

Actual kernel limits are **8 expanded paths per policy, 255 path bytes, and one
container binding per gadget instance**. An inner map holds a header and eight
288-byte entries: 2,592 bytes of values plus kernel allocation/metadata overhead.
Replacement temporarily retains two generations. The parser additionally bounds
input to 64 KiB; its broader authoring limits do not override kernel limits.

Path resolution uses `bpf_path_d_path` on the executable file in the calling
task's root. A symlink is checked at its resolved destination; renaming a file
out of an allowed directory removes that path permission. Resolution errors,
including paths exceeding the fixed buffer, deny in enforce mode and permit in
audit mode. Scripts and their interpreters are checked separately. Allowing an
interpreter does not restrict the code it can interpret.

## Build and run

Requires BPF LSM enabled, cgroup v2, kernel BTF and the `bpf_path_d_path` kfunc;
Linux 6.12 is the tested baseline. Successful loading/attachment is the final
capability check. Current WASM imports require the updated IG host: older hosts
without `ig.mapFreeze` fail image initialization before any BPF program attaches.
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
config:
  operator:
    oci:
      allow-enforcement: true
```

Keep the production image trust settings. Supply policy through the ordinary
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
5. Container deletion removes the binding. Instance shutdown releases the binding,
   generation maps and unpinned BPF links, including partial-start failure cleanup.

The `status` datasource emits state, revision, generation, cgroup ID and message.
`waiting-for-target` means no target has been protected. `enforcing`, `auditing`
and `off` describe the installed mode. Other states include `target-removed`,
`update-rejected`, `error` and `stopped`. An update rejection leaves the reported
revision/generation and last-good kernel policy intact. These events describe
policy readiness; the daemon's generic running-instance state alone does not.

An embedding host can publish to the `exec_policy_updates` input datasource:

- `policy` (string): complete standalone policy YAML.
- `expected_generation` (uint64): last observed generation, initially 1.

Callbacks serialize policy updates and container events. Updates require the same
container identity. Parsing, compilation, map population and freezing finish
before replacing the bound inner map with one update. Failures retain the prior
generation. Successful updates increment the generation and emit status. This
input is an embedding interface, not a new public RPC or CLI file watcher.
An embedding host must emit asynchronously when reacting to a guest status event;
synchronous emission back into the same guest would reenter its serialized callback.
Existing ConfigMap instance replacement still follows IG's restart semantics;
it is **not** a gap-free live policy update. Integrating this input with a
controller or node-agent is follow-up work.

The `verdict` datasource reports generation, cgroup, deny decision, mode,
path-resolution result and resolved path. `deny=1` in audit mode means would-deny;
only enforce mode blocks. A shared 4 KiB ring buffer bounds pending reports.
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
Generation atomicity is per hook, not across script/interpreter hooks. Process
identity resolution, executable integrity, crash fail-closed semantics, the full
SandboxPolicy vocabulary and a kernel compatibility/performance matrix remain
outside this implementation.
