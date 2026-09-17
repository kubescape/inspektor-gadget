---
title: Uprobe attach bookkeeping
sidebar_position: 230
description: >
  How uprobetracer tracks which inodes it has attached to, why two structures
  are needed, and what happens when they disagree
---

`pkg/uprobetracer` keeps two structures per tracer, and the difference between them matters
more than it looks.

`containerPid2Inodes` maps a container pid to the real inodes for which that pid has taken a
reference. It is a record of intent: this pid counted on this inode being instrumented.

`inodeRefCount` maps a real inode to the `inodeKeeper` that owns the open file and the bpf
links. It is the thing that actually holds the attachment alive.

Both are keyed by the *real* inode, meaning the underlying inode as reached through
`d_real_inode`, not the `<fsid, inode>` pair. overlayfs provides its own inode implementation
and overwrites the fsid, so containers started from the same image share one underlying inode.
The kernel attaches the uprobe to that underlying inode, which is why the tracer attaches once
per real inode and refcounts the pids that depend on it. Attaching per pid would attach the
same inode several times and produce duplicate records.

## The invariant

An inode recorded in `containerPid2Inodes` must have a live keeper in `inodeRefCount`.

The two are written together and are meant to stay consistent. `commitOpenedTargets` appends an
inode only when `attachOneOpenFile` reports that a reference was taken, so a failed attach (a
target that does not export the symbol, or a rolled-back multi-offset attach) records nothing.
`DetachContainer` deletes the pid's record and decrements the keeper once per recorded inode,
closing the links only on the last reference.

## When it breaks

If the invariant does break, the consequence used to be severe out of proportion to the cause.
`attachOneOpenFile` checks the pid's record first:

```go
// Already counted for THIS pid: nothing to do.
if existing[realInodePtr] {
    file.Close()
    return realInodePtr, false, nil
}
```

With the record present and the keeper gone, nothing is bound in the kernel, yet this returns
as though everything were fine. It is also the only short-circuit in that function that logs
nothing, so the target stays uncaptured for the lifetime of the container while every coverage
signal still reports it attached. No error, no metric, nothing to grep for.

That happened on a dev cluster with a TLS capture gadget. The agent held a recorded inode for a
CLI binary with no open fd for it, while an independent count-only bcc uprobe at the same file
offsets counted over 300 `SSL_read` hits during a single request that the agent never saw. A
second copy of the same build, installed at a different path and therefore a different inode,
captured immediately. Evicting the exe path from the exec LRU was not enough, because that
cache sits in front of this check, not behind it.

The tracer now verifies the keeper before trusting the record. When the keeper is gone it
re-attaches and warns, naming the target and counting the heals in `staleInodeRecords`:

```
uprobetracer: "trace_uprobe_ssl_read": inode of "/usr/bin/example" is recorded for
1 container(s) including 4697 but has no live attachment; re-attaching (count=1)
```

A rebuilt keeper starts at the number of pids that still record the inode, not at 1. Containers
sharing an image share the inode, and `DetachContainer` decrements once per record, so a keeper
that under-counts would let the next unrelated detach drop it to zero and close links other
containers still rely on.

A nonzero `staleInodeRecords` means something released links without clearing the pid record.
Treat the warn line as a bug report about that, not as normal operation.

## Diagnosing from outside the process

Neither structure is exported, so three signals are all you get:

The tracer keeps the target file open for as long as the keeper lives, so
`ls -l /proc/<agent-pid>/fd | grep <binary>` distinguishes a genuinely attached inode from a
recorded one. Expect one fd per bound probe program.

`DetachContainer` returns `internal error: finding inodeKeeper with realInodePtr` when it finds
a recorded inode with no keeper. A hit in the logs dates the inconsistency.

The heal warn line above fires on the first exec after the attachment went away, which is the
earliest point the tracer can notice.
