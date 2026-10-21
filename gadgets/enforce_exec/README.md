# enforce_exec — non-eBPF integration spike

This draft is organized as an IG gadget. It declares an `exec-policy` parameter in
`gadget.yaml`, builds `go/program.go` as a WASM layer, and consumes the parameter in
IG's existing `gadgetPreStart` lifecycle hook. There is no custom CLI command.

**It does not enforce anything.** Valid configuration reaches policy preparation,
then startup deliberately fails with `enforcement backend unavailable`. Invalid
configuration fails earlier with a policy diagnostic. Audit and off also fail
startup: this spike must not advertise a working runtime it does not provide.

## Structure

- `gadget.yaml`: metadata and mandatory WASM parameter.
- `build.yaml`, `go/`: normal IG Go/WASM packaging and exported pre-start hook.
- `policy/`: gadget-owned parser, bounded validation, immutable prepared input and
  explicit unavailable-backend result. This is execution-specific code, not yet a
  shared framework abstraction.
- `policy/*_test.go`: simulated generation lifecycle and path evaluator, used only
  for contract tests. They are not compiled into the gadget.
- `examples/`: standalone enforce/audit policies and an IG instance manifest.
- `test/unit/`: compiles the actual WASM guest, tests its parameter/log ABI, and
  exercises the real IG OCI handler, WASM operator and local runtime in memory.

No Kubescape packages, CRDs, service, or compiler are required. A future adapter in
`kubescape/node-agent` can translate SandboxPolicy inputs to this gadget's contract;
CRD watches/imports/merge/status stay in node-agent. Shared rule vocabulary does not
make Kubescape a prerequisite.

## Configuration path

```text
ig run --exec-policy <YAML string> / instance paramValues
  -> OCI metadata params.wasm.exec-policy
  -> operator.oci.wasm.exec-policy
  -> WASM GetParamValue("exec-policy") in gadgetPreStart
  -> policy.Prepare: strict decode, validation, immutable revision
  -> Start: explicit backend-unavailable failure (this spike)
```

Example input (`examples/enforce.yaml`):

```yaml
version: 1
binding:
  container:
    runtime: containerd
    id: demo-container-not-resolved-by-this-spike
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

The parameter is passed by value. No remote process reads a client-side filename.
There is no `--exec-policy-file` option in this spike; that was proposed, not an
existing IG facility. Use the existing string parameter or instance manifest:

```sh
sudo ig image build --local -t enforce_exec:spike gadgets/enforce_exec
sudo ig run enforce_exec:spike --verify-image=false \
  --exec-policy "$(cat gadgets/enforce_exec/examples/enforce.yaml)"
# Or:
sudo ig run -f gadgets/enforce_exec/examples/instance.yaml
```

The local build needs the existing IG build prerequisites and write access to the
local OCI store. The unsigned local development image uses `verify-image=false`
only for this example; this is not a production trust configuration. Expected run
result: nonzero exit, policy validation log, then backend-unavailable error.

`GetGadgetInfo`/help can expose metadata without activating enforcement because
preparation runs in pre-start, not `gadgetInit`. No behavior-declaration field is
invented in current metadata: framework enforcement admission and consent are
still required before a real backend can ship. This WASM-only artifact refuses
startup unconditionally after preparation.

## Supported validation and test contract

The parser supports one exact container or process binding, policy modes
`audit`/`enforce`/`off`, explicit exec default, named allow/deny path rules, optional
rule modes, and origin. Exact absolute paths and trailing `/**` patterns are the
first supported subset. Unsupported predicates/globs are rejected rather than
silently ignored. This is not a full SandboxPolicy implementation.

Illustrative preparation limits are 64 KiB input/encoded document, 128 rules and
512 path entries. They are not production kernel-memory measurements. Container
runtime/ID and process node/boot ID/PID/start-time fields are structurally checked;
there is no real identity resolution yet. The parser rejects unknown fields,
multiple YAML documents, duplicate names, invalid modes, and oversized input.

The test-only backend exercises prepare/activate/cancel/inspect/remove, immutable
snapshots, compare-and-swap generations, one pending candidate, retained last-good
configuration on invalid updates, and deletion tombstones. The test-only evaluator
checks deny precedence, directory boundaries, and audit/enforce/off decisions for
supplied paths; it never inspects or executes files. Its output is not a gadget
datasource and not evidence of real blocking.

## Run the tests without root or Kubescape

```sh
go test -race ./gadgets/enforce_exec/policy ./gadgets/enforce_exec/test/unit
go vet ./gadgets/enforce_exec/policy ./gadgets/enforce_exec/test/unit
```

The integration test compiles `go/program.go` for `wasip1/wasm`, supplies an in-memory
OCI image, skips the root-only `Runtime.Init` BPF setup, checks that the real
`GetGadgetInfo`/`RunGadget` path exposes `exec-policy`, and verifies
that startup fails at the actual guest pre-start hook. Additional ABI tests verify
valid, invalid, unsupported, oversized, and missing input diagnostics. They need a
Go toolchain supporting WASM reactor exports; they do not need a container runtime,
registry, writable `/var/lib/ig`, or BPF privileges.

## Framework work still needed

Before this can become an enforcement gadget, implement and review:

1. Enforcement metadata/admission, administrator limits, explicit consent and old
   daemon capability negotiation before image code initializes.
2. Real lifetime-safe target resolution, policy preparation against that target,
   and enforcement-specific readiness/cleanup.
3. A backend and host interface for prepared generation replacement; the test-only
   abstraction is an experiment, not an already exported production API.
4. BPF attachment, verdict datasource, bounded reporting and loss counters.
5. Kubernetes selector and stored-instance reconciliation semantics.

WASM pre-start validates configuration, but does not itself guarantee validation
before another operator attaches programs. The shared host admission/prepare order
must be established before adding an eBPF layer. This spike intentionally contains
no eBPF layer and never reports an attached or enforcing state.
