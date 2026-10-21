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
