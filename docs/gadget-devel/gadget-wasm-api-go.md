---
title: 'Wasm Golang API'
sidebar_position: 400
description: 'Wasm API for Golang'
---

The online documentation is available at
https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget/wasmapi/go. The
[hello-world gadget with wasm](./hello-world-gadget-wasm.md) offers a quick
start to use WASM on your gadget.

## Freezing and releasing maps

After populating a policy map, call `Map.Freeze()` to prevent further userspace
updates before publishing it in a map of maps. Freezing does not prevent BPF
programs from updating the map.

Close maps created with `NewMap` when they are no longer needed. Use
`ReleaseHandle` for handles obtained through `GetMap` or map-of-maps lookups.
A `GetMap` handle borrows the gadget's map; releasing it leaves that map open.
A map-of-maps lookup owns a separate file descriptor, which releasing the handle
closes. The runtime also closes remaining owned maps during shutdown and when
startup fails.

A gadget that calls `Map.Freeze()` imports `ig.mapFreeze`. Runtimes without this
host function reject the WASM module during initialization, before attaching the
gadget's eBPF programs. The `enforce_exec` gadget requires this import so that an
older runtime cannot bypass its startup requirements.

## Binding a process

`BindProcess(target Map, node, bootID string, hostPID uint32, startTicks uint64) error`
validates a live host process and writes `uint64(1)` into its BPF task storage.
Obtain `target` with `GetMap`; it must be a `TaskStorage` map with a 4-byte key
and an 8-byte value. Normal map lookup, update, and delete functions reject task
storage because its keys are host pidfds, which are not exposed to WASM.

Call from `gadgetStart`. IG must run in the host PID namespace. The host checks
`node` against `NODE_NAME` (or the hostname when unset), `bootID` against the
host boot ID, and `startTicks` against field 22 of `/proc/PID/stat`. `hostPID`
identifies a thread-group leader. A pidfd ties the storage update to the
validated task, preventing a later reused PID from inheriting the binding.
The supplied start time has clock-tick precision; it does not distinguish two
processes whose PID was reused within the same tick before binding.

Before calling, register and subscribe to the single-event datasource
`process_lifecycle`, with these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `event_type` | string | `EXITED` when the selected process exits |
| `host_pid` | uint32 | The supplied host PID |
| `start_time_ticks` | uint64 | The supplied start time |

Exit notifications begin after `gadgetStart` returns. The kernel reclaims task
storage when its task exits; the notification lets the gadget release related
policy maps and update status. The runtime closes the monitoring pidfd on exit,
startup failure, or shutdown. One process binding is supported per gadget
instance. Children do not inherit task storage; an enforcement program must
explicitly preserve the marker when a nonleader thread performs `execve`.

The `enforce_exec` gadget attempts marker transfer before a nonleader exec in
every policy mode. On failure, enforce mode returns the chosen error `ENOMEM` to
preserve process selection; audit and off allow execution and record that tracking
may be lost. The fixed-size `process_health` map retains a cumulative failure count
and sticky degradation flag independently of reporting. Gadget status exposes
`tracking_failures` and `tracking_degraded` snapshots on lifecycle/update activity.

Process transitions from audit/off to enforce require removing the gadget instance
and creating a fresh instance with validated process binding, even when tracking
appears healthy. A prior nonblocking execution can still be in flight, so a health
snapshot cannot safely authorize promotion. Live updates within enforce, from
enforce to audit/off, and between audit/off remain supported. These are gadget
policy semantics, rather than requirements imposed by `BindProcess` itself.

This API imports `ig.bindProcess`; runtimes without the host function reject
modules importing it during initialization.

Process activation temporarily seizes each thread with `PTRACE_SEIZE` and
interrupts it into a tracer-owned stop, waiting up to two seconds for the group
to become stable. It checks identity again and seeds task storage before
detaching. External `SIGCONT` cannot resume these stops during binding. This
requires ptrace permission over the selected process. An initially fully
job-control-stopped group remains stopped; partially stopped groups, existing
tracers, and selecting IG itself are rejected. Failed activation detaches
threads; a dedicated tracer thread exits to release any thread that could not
stop within the deadline. No `PTRACE_O_EXITKILL` option is enabled.
