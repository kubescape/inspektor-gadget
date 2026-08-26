// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package uprobetracer

import "container/list"

// exeLRUCap bounds how many distinct, successfully-attached exe paths are
// remembered per containerPid. It is a placeholder default -- 8 is generous
// enough for the reported bug (a handful of short-lived binaries execing
// within seconds of each other under one container) without keeping every
// binary a container has ever run pinned in memory forever.
//
// Retuning guidance (two DISTINCT signals, see metrics.go):
//   - ig_uprobetracer_redundant_attach_total fires on a CONCURRENT-RACE
//     redundancy -- Phase-1 I/O ran for a path that, by commit time, was
//     already resident and current. This signals wasted work from racing
//     execs of the same not-yet-cached binary; it does NOT signal that the
//     cap itself is too small (an entry that ages out of the cap-N set is, by
//     definition, no longer resident, so re-adding it can never look
//     "already present").
//   - ig_uprobetracer_exe_cache_miss_total fires when add/touchAndReport
//     evicts an entry to make room for a new one -- i.e. the cache was
//     genuinely at capacity. THIS is the signal that exeLRUCap needs
//     retuning: a rising eviction rate means more than exeLRUCap distinct
//     binaries are staying "hot" (repeatedly re-exec'd) concurrently under
//     one container than the cap can hold without thrashing.
const exeLRUCap = 8

// exeIdentity is the (device, inode, mtime) triple identifying the CONTENT
// currently backing a resolved exe path, as observed by stat'ing the process's
// magic /proc/<execPid>/exe symlink (see tracer.go's defaultStatExeIdentity).
//
// dev+ino is the primary identity, per matthyx's review of this PR
// (armosec/private-node-agent#541): it is what catches the common case of a
// binary being replaced AT THE SAME PATH via rename or an overlayfs copy-up --
// the new file gets a new inode (and often a new device, across overlay
// layers), even though the path string a container execs is unchanged. Device
// is included alongside inode, not inode alone, to avoid a false MATCH from
// inode-number reuse across different filesystems/overlayfs layers.
//
// mtimeNano closes one further, narrower gap dev+ino alone cannot: a binary
// overwritten IN PLACE through the SAME already-existing inode (a non-atomic
// write to a file that is not currently mapped for execution, as opposed to
// the much more common unlink+rename replacement pattern deployment tooling
// uses specifically to avoid ETXTBSY). dev+ino would not change here, but
// mtime does. It is included at zero extra I/O cost -- stat(2) already
// returns it alongside dev+ino in the exact same syscall.
//
// This combination is what makes the exeLRUTTL backstop (introduced in an
// earlier code-review round, since removed) redundant: that TTL only ever
// bounded the worst-case staleness window to a fixed 5 minutes for exactly the
// gap dev+ino+mtime now closes immediately, on the very next exec, with no
// window at all. Two overlapping correctness mechanisms for the same gap make
// the code harder to reason about for no remaining benefit, so the weaker,
// time-bounded one was removed in favor of the immediate one.
type exeIdentity struct {
	dev       uint64
	ino       uint64
	mtimeNano int64
}

// exeLRUEntry is one exeLRUCache slot: the resolved exe path plus the
// exeIdentity last recorded for it (either at initial attach, or refreshed by
// a later touchIfCurrent hit / touchAndReport commit).
type exeLRUEntry struct {
	path  string
	ident exeIdentity
}

// exeLRUCache is a bounded, true LEAST-RECENTLY-USED set of distinct exe
// paths successfully attached for one containerPid, each paired with the
// exeIdentity it was last confirmed to have. "Used" means checked as a cache
// hit via touchIfCurrent, not merely inserted -- see touchIfCurrent's doc
// comment for why that distinction is load-bearing.
//
// Zero value is not usable; construct with newExeLRUCache. Not safe for
// concurrent use: callers serialize access via Tracer.mu, exactly like the
// map it replaces.
type exeLRUCache struct {
	cap int
	// order lists entries from most- to least-recently-used, front to back.
	// Each element's Value is a *exeLRUEntry.
	order *list.List
	elems map[string]*list.Element
}

func newExeLRUCache(capacity int) *exeLRUCache {
	return &exeLRUCache{
		cap:   capacity,
		order: list.New(),
		elems: make(map[string]*list.Element),
	}
}

// peek reports whether path is currently resident in the cache, WITHOUT
// consulting or comparing exeIdentity and WITHOUT touching LRU recency. It is
// the genuinely read-only counterpart to touchIfCurrent/touchAndReport --
// added per a code-review nit on this PR's earlier contains() (a mutating
// predicate whose name read as a pure one, a data-race hazard for any future
// caller -- e.g. one holding only an RLock, or a debug/observation path --
// that assumed read-only). Use this when you only want to know whether a path
// is a resident key at all (e.g. tests observing cache shape); use
// touchIfCurrent when the check is meant to also count as a genuine use.
//
// Still requires the same external synchronization as every other method
// here -- exeLRUCache itself is not internally synchronized.
func (c *exeLRUCache) peek(path string) bool {
	_, ok := c.elems[path]
	return ok
}

// touchIfCurrent reports whether path is currently resident in the cache AND
// its recorded exeIdentity equals ident -- the fast-path hit check
// (ReattachContainerExecPid). A hit counts as a USE and moves path to the
// most-recently-used end -- this is what makes eviction here true LRU rather
// than FIFO: two binaries that keep getting re-exec'd (repeatedly hitting this
// check) stay resident no matter how much cold, one-off exec churn is
// interleaved between them, because each hit refreshes their recency. Under
// FIFO (insertion-order eviction, recency of use never consulted) that same
// interleaving would eventually evict both, reproducing the exact flip-flop
// bug this cache exists to fix (armosec/private-node-agent#541).
//
// path present but ident DIFFERENT from what was recorded is a MISS, not a
// hit -- and, unlike a plain unseen-path miss, it is deliberately NOT
// refreshed/replaced here: the caller must fall through to a real Phase-1
// resolve+attach for the (now-different) content, and only a clean pass
// there commits the new identity via touchAndReport. This is the fix for
// matthyx's BLOCKER review comment: the pre-inode-check version of this
// method (then named contains) keyed purely on the path string, so a binary
// replaced in place at an already-cached path was silently served a stale hit
// that skipped re-attaching to the new content entirely.
func (c *exeLRUCache) touchIfCurrent(path string, ident exeIdentity) bool {
	e, ok := c.elems[path]
	if !ok {
		return false
	}
	entry := e.Value.(*exeLRUEntry)
	if entry.ident != ident {
		return false
	}
	c.order.MoveToFront(e)
	return true
}

// add records path as the most-recently-used entry with ident, evicting the
// least recently used entry if doing so would exceed the cache's capacity. It
// is a no-op reordering (move-to-front, identity refresh) if path is already
// present.
//
// Correctness invariant (do not weaken): eviction here only ever affects
// PERFORMANCE, never correctness. add is called (see ReattachContainerExecPid)
// only after a clean Phase-1 resolve+attach pass for path at the given ident,
// so evicting some OTHER path out of the set simply means that other path's
// NEXT exec will miss this cache's fast path and fall through to the full,
// correct Phase-1 attach again -- exactly as if it were being seen for the
// first time. Eviction must never cause a stale or incorrect exe path (or a
// stale identity for a live one) to be substituted for a live execPid; it
// only ever costs an extra round of I/O for the evicted binary. A full cache
// must never silently skip an attach -- callers only skip work on an actual
// touchIfCurrent hit (which itself never fires for a path whose recorded
// identity no longer matches -- see touchIfCurrent's doc comment), never
// because add() had to evict to make room.
//
// Implemented as a thin wrapper around touchAndReport (discarding its return
// values) -- code-review follow-up: add and touchAndReport used to duplicate
// the identical insert+evict logic verbatim, but add is only ever called from
// tests (production code only calls touchAndReport directly, see
// ReattachContainerExecPid), so a future change to the eviction/capacity logic
// applied to only one copy would silently leave the other behind its own test
// coverage. Routing through touchAndReport keeps exactly one copy of that
// logic and lets add's existing tests validate the same code path production
// actually uses.
func (c *exeLRUCache) add(path string, ident exeIdentity) {
	c.touchAndReport(path, ident)
}

// touchAndReport is the single-lookup combination of a touchIfCurrent() check
// followed by an add() -- used at commit time (see ReattachContainerExecPid),
// where the caller always wants to record path as freshly, successfully
// attached at ident AND learn (a) whether that work turned out to be
// redundant (path was already resident with the SAME ident) and (b) whether
// committing it evicted some other path to make room, without paying for two
// separate map lookups and up to two list.MoveToFront calls.
//
// current reports whether (path, ident) was ALREADY the resident value BEFORE
// this call touched it -- i.e. exactly what touchIfCurrent(path, ident) would
// have reported had it been called first. path present but with a DIFFERENT
// ident reports current=false (this call's Phase-1 work was NOT redundant --
// it correctly re-attached to genuinely new content), exactly like a
// brand-new path would. This is what feeds
// ig_uprobetracer_redundant_attach_total: it must only fire for a genuine
// concurrent-race duplicate, never for a legitimate content change.
//
// evicted reports whether committing path required evicting some OTHER,
// least-recently-used path to stay within capacity -- i.e. the cache was
// genuinely full. This is what feeds ig_uprobetracer_exe_cache_miss_total
// (see exeLRUCap's doc comment): the production signal for whether exeLRUCap
// itself needs retuning, as distinct from ordinary concurrent-race redundancy.
//
// Unconditionally, on return, path is resident as the most-recently-used
// entry with ident, identical to what touchIfCurrent(path, ident);
// add(path, ident) would have left behind.
func (c *exeLRUCache) touchAndReport(path string, ident exeIdentity) (current, evicted bool) {
	if e, ok := c.elems[path]; ok {
		entry := e.Value.(*exeLRUEntry)
		current = entry.ident == ident
		entry.ident = ident
		c.order.MoveToFront(e)
		return current, false
	}
	entry := &exeLRUEntry{path: path, ident: ident}
	e := c.order.PushFront(entry)
	c.elems[path] = e
	if c.order.Len() > c.cap {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.elems, oldest.Value.(*exeLRUEntry).path)
			evicted = true
		}
	}
	return false, evicted
}
