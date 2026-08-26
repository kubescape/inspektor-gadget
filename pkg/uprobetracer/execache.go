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

import (
	"container/list"
	"time"
)

// exeLRUCap bounds how many distinct, successfully-attached exe paths are
// remembered per containerPid. It is a placeholder default -- 8 is generous
// enough for the reported bug (a handful of short-lived binaries execing
// within seconds of each other under one container) without keeping every
// binary a container has ever run pinned in memory forever. Retune using the
// ig_uprobetracer_redundant_attach_total counter (see metrics.go) once real
// production churn patterns are observed.
const exeLRUCap = 8

// exeLRUTTL bounds how long a cache entry may satisfy the fast-path hit check
// before it must be reverified via a full Phase-1 resolve+attach, regardless
// of how much (or how little) LRU churn happens around it.
//
// Why this exists (code-review follow-up on the exeLRUCache PR): exeLRUCache
// is keyed by resolved PATH ONLY -- it has no way to detect that the file
// CONTENT at a cached path changed underneath it (e.g. a container hot-reloads
// or self-updates a binary in place at the same path). This limitation is
// pre-existing in the original single-slot cache this replaced (it also only
// ever compared resolved-path strings, never inode/mtime), but the bounded-LRU
// cache widens its practical impact: the old single-slot cache accidentally
// self-healed the moment ANY other distinct binary was exec'd (which
// overwrote the single slot), giving it an unpredictable but often-short
// staleness window. This cache can instead keep a stale-but-unchanged-path
// entry resident far longer -- up to exeLRUCap OTHER distinct paths being
// seen -- which for the exact workload this fix targets (a small, stable,
// repeatedly-exec'd set of binaries) could mean effectively indefinitely.
//
// A full fix -- actually verifying the file's current inode on every hit --
// is deliberately NOT done here: exeTarget (from
// os.Readlink("/proc/<execPid>/exe")) is a path resolved INSIDE the
// container's mount namespace, so it cannot be safely os.Stat'd directly from
// the host process (that would stat the HOST's own filesystem at that path
// string -- a different, unrelated, and dangerous operation). Properly
// verifying the file would require going through the same secure
// per-container-mount-namespace open machinery (openInContainer /
// t.openTargets) that the full Phase-1 attach path already uses, which costs
// nearly as much as just doing the real attach -- defeating the entire point
// of this fast path being fast.
//
// Instead, this TTL is a cheap, bounded backstop: one time.Now() comparison
// against a stored timestamp, no new I/O on the fast path. 5 minutes was
// chosen to be generous enough that a binary re-exec'd more often than that
// (the "small, stable, repeatedly-exec'd set of binaries" this whole cache
// exists to serve -- see exeLRUCache's doc comment) never ages out purely on
// time, since every hit (contains) and every commit (add/touchAndReport)
// refreshes the timestamp -- preserving nearly all of the throughput win for
// genuinely hot binaries. At the same time it gives a concrete, testable,
// worst-case staleness guarantee (at most exeLRUTTL, full stop) instead of
// the prior open-ended "until exeLRUCap other distinct binaries are seen",
// which could be effectively unbounded for a stable binary set.
const exeLRUTTL = 5 * time.Minute

// exeLRUEntry is one exeLRUCache slot: the resolved exe path plus the last
// time it was successfully touched (inserted or re-confirmed), used to
// enforce exeLRUTTL.
type exeLRUEntry struct {
	path        string
	lastTouched time.Time
}

// exeLRUCache is a bounded, true LEAST-RECENTLY-USED set of distinct exe
// paths successfully attached for one containerPid, with a TTL backstop (see
// exeLRUTTL) bounding how long any one entry may serve as a fast-path hit.
// "Used" means checked as a cache hit via contains, not merely inserted --
// see contains' doc comment for why that distinction is load-bearing.
//
// Zero value is not usable; construct with newExeLRUCache. Not safe for
// concurrent use: callers serialize access via Tracer.mu, exactly like the
// map it replaces.
type exeLRUCache struct {
	cap int
	ttl time.Duration
	// now is the injectable clock used for TTL bookkeeping, defaulting to
	// time.Now. Tests in this package may overwrite it directly (this field
	// is unexported, but tests live in the same package) to fast-forward
	// time deterministically instead of sleeping in real time.
	now func() time.Time
	// order lists entries from most- to least-recently-used, front to back.
	// Each element's Value is a *exeLRUEntry.
	order *list.List
	elems map[string]*list.Element
}

func newExeLRUCache(capacity int) *exeLRUCache {
	return &exeLRUCache{
		cap:   capacity,
		ttl:   exeLRUTTL,
		now:   time.Now,
		order: list.New(),
		elems: make(map[string]*list.Element),
	}
}

// contains reports whether path is currently resident in the cache AND has
// been touched within the last ttl -- an entry older than that is treated as
// a miss (see exeLRUTTL's doc comment for why). A hit counts as a USE and
// moves path to the most-recently-used end -- this is what makes eviction
// true LRU rather than FIFO: two binaries that keep getting re-exec'd
// (repeatedly hitting this check) stay resident no matter how much cold,
// one-off exec churn is interleaved between them, because each hit refreshes
// their recency. Under FIFO (insertion-order eviction, recency of use never
// consulted) that same interleaving would eventually evict both, reproducing
// the exact flip-flop bug this cache exists to fix.
//
// A TTL-expired entry is deliberately NOT moved to front and NOT refreshed
// here: it must be reported as a plain miss so the caller falls through to
// the full Phase-1 resolve+attach, which will correctly re-verify the target
// and re-stamp the entry's timestamp on its next successful add/touchAndReport.
func (c *exeLRUCache) contains(path string) bool {
	e, ok := c.elems[path]
	if !ok {
		return false
	}
	entry := e.Value.(*exeLRUEntry)
	if c.now().Sub(entry.lastTouched) > c.ttl {
		return false
	}
	c.order.MoveToFront(e)
	return true
}

// add records path as the most-recently-used entry with a fresh timestamp,
// evicting the least recently used entry if doing so would exceed the
// cache's capacity. It is a no-op reordering (move-to-front, timestamp
// refresh) if path is already present, TTL-expired or not.
//
// Correctness invariant (do not weaken): eviction here only ever affects
// PERFORMANCE, never correctness. add is called (see
// ReattachContainerExecPid) only after a clean Phase-1 resolve+attach pass
// for path, so evicting some OTHER path out of the set simply means that
// other path's NEXT exec will miss this cache's fast path and fall through
// to the full, correct Phase-1 attach again -- exactly as if it were being
// seen for the first time. Eviction must never cause a stale or incorrect
// exe path to be substituted for a live execPid; it only ever costs an extra
// round of I/O for the evicted binary. A full cache must never silently skip
// an attach -- callers only skip work on an actual contains() hit (which
// itself never fires for a TTL-expired entry -- see exeLRUTTL), never
// because add() had to evict to make room.
//
// Implemented as a thin wrapper around touchAndReport (discarding its
// alreadyPresent return) -- code-review follow-up: add and touchAndReport
// used to duplicate the identical insert+evict logic verbatim, but add is
// only ever called from tests (production code only calls touchAndReport
// directly, see ReattachContainerExecPid), so a future change to the
// eviction/capacity logic applied to only one copy would silently leave the
// other behind its own test coverage. Routing through touchAndReport keeps
// exactly one copy of that logic and lets add's existing tests validate the
// same code path production actually uses.
func (c *exeLRUCache) add(path string) {
	c.touchAndReport(path)
}

// touchAndReport is the single-lookup combination of a contains() check
// followed by an add() -- used at commit time (see ReattachContainerExecPid),
// where the caller always wants to record path as freshly, successfully
// attached AND learn whether that work turned out to be redundant (path was
// already a live, non-expired resident), without paying for two separate map
// lookups and up to two list.MoveToFront calls.
//
// alreadyPresent reports whether path was a non-expired resident BEFORE this
// call touched it -- i.e. exactly what contains(path) would have reported
// had it been called first, TTL included: a present-but-TTL-expired entry
// reports alreadyPresent=false, since (per exeLRUTTL's contract) it must be
// treated as a miss, not a redundant hit. Unconditionally, on return, path is
// resident as the most-recently-used entry with a freshly-stamped timestamp,
// identical to what contains(path); add(path) would have left behind.
func (c *exeLRUCache) touchAndReport(path string) (alreadyPresent bool) {
	now := c.now()
	if e, ok := c.elems[path]; ok {
		entry := e.Value.(*exeLRUEntry)
		alreadyPresent = now.Sub(entry.lastTouched) <= c.ttl
		entry.lastTouched = now
		c.order.MoveToFront(e)
		return alreadyPresent
	}
	entry := &exeLRUEntry{path: path, lastTouched: now}
	e := c.order.PushFront(entry)
	c.elems[path] = e
	if c.order.Len() > c.cap {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.elems, oldest.Value.(*exeLRUEntry).path)
		}
	}
	return false
}
