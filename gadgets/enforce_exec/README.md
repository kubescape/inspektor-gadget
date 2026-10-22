# enforce_exec

Container execution enforcement using BPF LSM. The gadget image contains a fixed
BPF program; a native Go controller supplies compiled rules and manages container
membership. No WASM, policy parameter updates, request IDs or acknowledgement
protocol are involved. Process enforcement is deferred.

## Architecture

```text
CLI policy / node-agent CRD adapter
  -> shared Go compiler
  -> immutable policy map, populated and frozen before binding
  -> native container binding controller
  -> BPF LSM decisions and bounded verdict reporting
```

Each instance has two ordinary maps:

- `policy`: nine array entries (one revision/header and eight expanded path rules).
  Native code fills it once and freezes it. `BPF_F_RDONLY_PROG` also prevents BPF
  writes. Rules never change while this instance runs.
- `bindings`: up to 1,024 cgroup-v2 identities. Adding/removing a container is a
  synchronous map operation serialized by the native controller. Membership can
  change without restarting or changing policy.

Rule changes create a new instance. Both programs enforce during replacement;
there is no map-of-maps publication protocol or writable standby rule map.

## Try it

Requires root, cgroup v2, kernel BTF, BPF LSM enabled and `bpf_path_d_path`.
Linux 6.12 is the tested baseline; successful loading/attachment is the capability
check. Use a host binary built from this branch:

```sh
go build -o /tmp/ig-enforce-exec ./cmd/ig
sudo /tmp/ig-enforce-exec image build --local -t enforce_exec:spike gadgets/enforce_exec
```

Edit `examples/enforce.yaml` with the actual runtime and full container ID, then:

```sh
sudo /tmp/ig-enforce-exec enforce-exec enforce_exec:spike \
  --allow-enforcement --verify-image=false \
  --policy gadgets/enforce_exec/examples/enforce.yaml --revision 1
```

`--verify-image=false` is for unsigned local development. Keep verification and
approved signed images in production. Host behavior consent and BPF admission
restrictions still apply. Verdicts are printed as JSON; stderr reports native
startup readiness and the number of currently bound containers.

This command uses the existing IG container cache and discovery settings, such as
`--runtimes docker`. No Kubescape component is required. Generic `ig run` cannot
supply the typed native policy; use this command or the embedded interface below.

## Policy

```yaml
version: 1
binding:
  containers:
    - runtime: containerd
      id: full-container-id
policy:
  mode: enforce
  exec:
    default: deny
    rules:
      - name: approved-executables
        target:
          path: ["/usr/bin/**", "/opt/app/bin/**"]
        action: allow
      - name: deny-default-shell
        target:
          path: ["/usr/bin/dash"]
        action: deny
```

The singular `binding.container` spelling also works. Use exactly one spelling.
`binding.process` is unsupported. This file is CLI/compiler input, not a gadget
parameter or a file watched by a daemon.

Rules support exact clean absolute paths or trailing `/**` directory patterns,
allow/deny default, and audit/enforce/off mode. Denies override matching allows.
Rule modes must be empty or match the policy mode. Unsupported predicates,
duplicate selectors, oversized input or excess rules fail before loading.

Paths refer to resolved executable destinations. Check `readlink -f /usr/bin/sh`
inside the target container before adapting the shell example. Renaming an
executable can change its path permission. Scripts and interpreters are checked
separately; allowing an interpreter does not constrain the code it interprets.
Resolution failures deny in enforce mode and permit in audit mode. Off permits
without ordinary verdict reporting.

## Embedded owner

The compiler and native controller are ordinary IG Go packages:

```go
entries, err := execpolicy.CompileKernel(document, revision)
// Check err before constructing an instance.
config := execruntime.Config{
    Entries: entries,
    Targets: document.Binding.Targets(),
}
err = manager.StartGadget(ctx, instance,
    execruntime.WithConfig(config),
)
```

Import `gadgets/enforce_exec/runtime` and include its registered native operator
alongside the existing OCI and container-cache operators. The owner controls
`instance.Id` and supplies a nonzero revision. All required operators must start
successfully before `StartGadget` returns. Initial discovery and binding errors
fail startup instead of being accepted as readiness.

`GetBindings(gadgetContext)` returns the per-instance controller. Its
`Bind(ContainerIdentity)` and `Unbind(ContainerIdentity)` methods return the map
operation result synchronously; `Status()` returns revision, bound count,
readiness and the latest binding error. Startup errors remain sticky until the
final readiness check, even if another binding operation succeeds. Identities include runtime, full ID,
nonzero cgroup ID and clean non-root cgroup-v2 path. Stale deletions cannot remove
a newer identity. Map handles remain private and writes are rejected after stop.

Choose one input owner. CLI discovery uses `Targets` with the IG container cache.
An embedded cache owner can use empty `Targets`, `InitialBindings`, and direct
`Bind`/`Unbind`. For a cache outside IG, provide a native startup operator after
the binding controller (priority 1): subscribe before taking the snapshot, replay
it and drain queued lifecycle changes through `Bind` before returning from
`Start`, and unsubscribe on stop. Manager readiness follows **all** operator
startup, so this adapter participates in the replacement barrier. An initial
snapshot alone is insufficient while the cache changes concurrently.

The Kubescape SandboxPolicy CRD adapter belongs in node-agent. It owns CRD
watching, translation, policy merging and controller status. IG stays independent
of that CRD and Kubescape packages. This PR adds no ConfigMap/file policy watcher
or public policy RPC. Existing upstream stores retain their normal operation.

## Rule replacement

```go
err := manager.ReplaceGadget(ctx, oldInstanceID, candidate,
    execruntime.WithConfig(newConfig),
)
```

The candidate must have a distinct instance ID and a new revision:

1. Start it while retaining the old instance.
2. Load/attach BPF, freeze its rules, replay current bindings and apply concurrent
   container changes. A failed binding fails preparation.
3. Wait for every startup operator to succeed.
4. Stop the old instance and wait for its cleanup.

Startup failure discards the candidate and retains the old instance. Once the
candidate starts, it is committed: cancellation while waiting for old cleanup
leaves the candidate active; the returned error identifies it, and `StopGadget`
can finish waiting for the old ID. Manager lifecycle operations are serialized.

For a target covered by both enforcing instances, overlap allows an exec only
when both policies allow it. Temporary overblocking is deliberate. This is a
handoff guarantee for established bindings, not an atomic node-wide policy
transition or a guarantee about a container's first exec before discovery.

The verdict `generation` field carries the immutable revision; correlate it with
the instance ID.
Reporting can drop and an earlier LSM denial can skip later programs, so events
are not readiness acknowledgements. Native startup/binding results are authority.

## Limits and lifecycle

Eight expanded paths, 255 path bytes, 1,024 live bindings and 64 KiB authoring input
bound this prototype. Policy values total 2,592 bytes plus map overhead. Each
instance has a 4 KiB reporting ring and a per-CPU limit of 100 report attempts per
second; saturation loses reports while enforcement continues. Overlap temporarily
loads both instances and their resources. These are explicit map/rule limits,
not a total memory budget.

No programs or maps are pinned. Stopping or killing the owning IG/node-agent
releases enforcement; workloads continue. Removing a binding intentionally
removes protection for that cgroup. Container scope is exact, excluding descendant
cgroups. Enrichment/discovery is not a pre-exec admission mechanism.

See [privileged validation](test/kernel/README.md) for reproducible tests and
coverage limits. Broader kernel/architecture validation, executable integrity,
execveat/memfd/deleted-file coverage, crash persistence and production CRD
integration remain outside this prototype.
