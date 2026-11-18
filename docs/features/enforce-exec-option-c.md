---
type: feature
status: draft
owner: "enforce_exec maintainers"
scope: repo
---

# enforce_exec option C engine (optcnode)

## Purpose

A portable exec-enforcement engine for the "option C" requirement set: success-only roles with inheritance, a simpler per-task state model, and no failure tracking. It runs one object on kernels from 5.14 to 6.18. The fail-closed contract of the product engine is unchanged.

Status: draft branch `universal/option-c`, an unwired prototype. Wiring it into the gadget needs files changed by PR #30.

## Behavior

- **Interface:** the facade `optcnode` (StartNode, Bind, Publish, Inspect, Remove, Ready, Degraded, StopNode) sits behind an `Enforcer` interface that `*fullruntime.NodeEnforcer` also satisfies unchanged.
- **Roles:**
  - committed at `lsm/bprm_committed_creds` and inherited at `task_alloc`;
  - an uncertain write commits UNKNOWN;
  - a generation or role-epoch change at commit makes roles UNKNOWN;
  - an exec straddling a publish is re-evaluated under the new generation, and Strict kills it if that denies.
- **Path facts:** anchored to the container root, which is captured in BPF at the init's first exec after Bind. Bind must prove the init is the runtime's init, blocked on this container's `exec.fifo`. Without that proof the binding is never Ready. Supported runtime: runc. crun is refused (fail closed).
- **Evaluator:** the `fullpolicy` evaluator in its staged, bounded-loop build (no `bpf_loop`).
- **Admission:** exact pin (release, BTF sha256, object sha256) by default. A BTF shape fingerprint and a four-part family test exist but are opt-in, and need a complete qualification record per family.
- **Requirements:** BPF LSM active, BTF, task storage, x86_64.
- **Qualified on** 5.15, 5.14, 6.1, 6.8, 6.12 and AL2023 6.12/6.18, test and product objects. On AL2023 its verdicts match the product engine on 60 of 66 meaningful parity steps; the differences are documented.
- **fullpolicy:** this branch changes the shared evaluator to Kleene AND, keeping structural faults hard. That changes product verdicts, so the product objects must be rebuilt, re-pinned and re-qualified before it merges.
- **Known gaps:**
  - `ld.so /path/bin` is not seen by any exec hook;
  - an orphaned task loses its ancestry, as in the product.

## Code

- `gadgets/enforce_exec/fullruntime/optcnode/` (`node.go`, `optcengine/`, `admission/`, `cmd/btfshape`, `parity/`)
- `gadgets/enforce_exec/fullruntime/optcnode/optcengine/README.md` (wiring contract, Bind proof, follow-ups)
- `gadgets/enforce_exec/fullpolicy/evaluate.go`, `gadgets/enforce_exec/fullpolicy/bpf/evaluator.h`
- `gadgets/enforce_exec/fullruntime/selfqual/` (reference harness)
