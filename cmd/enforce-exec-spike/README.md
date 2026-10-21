# enforce_exec interface spike

This is a runnable **simulation**, not an enforcement gadget. It loads no BPF,
requires no root privileges or Kubescape components, and never blocks executions.
It exercises the proposed standalone input and generation lifecycle before those
interfaces are connected to `ig run`, OCI gadget initialization, or a real backend.

## Try it

From the repository root:

```sh
go run ./cmd/enforce-exec-spike \
  --policy-file cmd/enforce-exec-spike/testdata/enforce.yaml \
  --replace-policy-file cmd/enforce-exec-spike/testdata/audit.yaml \
  /usr/bin/tool /usr/bin/sh /tmp/tool /usr/bin-other/tool
```

The command prints JSON lines containing capabilities, activated simulated state,
and decisions for each supplied path. It first evaluates the enforcing policy,
then replaces it with the audit policy and evaluates the same paths. Finally it
removes the binding and reports the resulting state. Flags must precede paths.

- `/usr/bin/tool` is allowed by a rule.
- `/usr/bin/sh` is denied by an explicit rule, even though an allow also matches.
- `/tmp/tool` and `/usr/bin-other/tool` hit the deny default.
- An enforcing denial sets `wouldBlock: true`; an audit denial sets
  `wouldDeny: true`. Neither executes or blocks anything: `enforced` is always false.
- `mode: off` permits everything, including when a rule overrides mode to enforce.

An invalid replacement exits nonzero and prints `retained-state` for the old
simulated generation. That state exists only inside the command process and does
not persist after exit. There is no daemon or disk store in this spike.

## Interface under review

`pkg/enforcement/execpolicy` contains:

- Strict, bounded YAML decoding of a versioned document with one binding and policy.
- Execution rules using `mode`, `exec.default`, named rules, `target.path`, `action`,
  rule mode overrides, and optional `origin`. No Kubescape Go types are imported.
- A `Backend` contract with capabilities, prepare, activate, cancel, inspect, remove.
- A mutex-protected memory backend: one active document and at most one prepared
  candidate. Preparation deep-copies input and cannot change the active generation.
- Compare-and-swap generation checks, immutable target identity during replacement,
  consumed handles, cancellation, and a monotonic tombstone after deletion.
- A deterministic document revision hash and simulated evaluation of supplied paths.

Supported patterns are exact clean absolute paths and a trailing `/**` for
recursive directory membership. Other globs and unsupported predicates are
rejected, never silently dropped. There is no claim of full SandboxPolicy support.
Rule ordering does not affect the verdict; the revision hash retains document order.
Matching deny modes determine whether a denial would block or only audit. For an
allow verdict, the reported mode is the policy mode; per-rule allow modes do not
change an execution decision in this slice.

The illustrative limits are 64 KiB input/encoded document, 128 rules, and 512 path
entries, with one prepared candidate. `--max-rules` demonstrates administrator
capacity rejection. These are prototype limits, not measured production defaults
or kernel memory estimates. The decoder rejects multiple YAML documents, unknown
fields, duplicate rule names, and invalid modes. Preparation validates programmatic
callers too. Consumers must cancel abandoned handles; expiry is not implemented.

## Binding and integration boundaries

A container binding records a runtime and ID. A process binding instead requires
`node`, `bootID`, positive `hostPID`, and `startTimeTicks`. The spike checks structure
and prevents retargeting an active binding; **it does not resolve or verify any of
these identities against a running system**. Simulated paths are assumed resolved;
there are no filesystem walks, symlink handling, or executable-identity checks.

The IG repository owns this generic contract and the future standalone preparation
path. A future adapter in `kubescape/node-agent` owns CRD selection/imports/merge and
translates them to the contract. The standalone path must remain independent of
that adapter. This prototype accepts one policy per binding and does not implement
cross-policy merge or class/profile resolution. Unsupported features fail validation
rather than pretending that unresolved rules can safely be enforced.

Not implemented here:

- BPF, actual blocking, attachment readiness, OCI packaging, or production admission.
- `ig run`/RPC/ConfigMap wiring, image consent, capability negotiation with old daemons.
- Real container/process discovery or Kubernetes selectors.
- Event rings, reporting rate limits, OTLP, CRD status, or overload enforcement tests.
- Atomic kernel map replacement, prepared-handle expiry, persistent instances.

Next integration step: review the envelope/lifecycle against the IG operator API,
then wire shared policy preparation into normal gadget initialization while keeping
this fake backend available for tests. Do not expose simulated state as `Running`
or `Enforcing`. Real target resolution, admission and cleanup must precede release
of an actual enforcement gadget.

## Verification

```sh
go test -race ./pkg/enforcement/execpolicy ./cmd/enforce-exec-spike
go vet ./pkg/enforcement/execpolicy ./cmd/enforce-exec-spike
```

Tests cover strict parsing, capacities, directory boundaries, deny precedence,
audit/enforce/off, binding validation, invalid replacement preserving the active
policy, immutable snapshots, stale writers, cancellation/removal, concurrent
preparation, and CLI simulation output. These validate Go behavior, not enforcement.
