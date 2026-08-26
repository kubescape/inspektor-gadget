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
// binary a container has ever run pinned in memory forever. Retune using the
// ig_uprobetracer_redundant_attach_total counter (see metrics.go) once real
// production churn patterns are observed.
const exeLRUCap = 8

// exeLRUCache is a bounded, true LEAST-RECENTLY-USED set of distinct exe
// paths successfully attached for one containerPid. "Used" means checked as
// a cache hit via contains, not merely inserted -- see contains' doc comment
// for why that distinction is load-bearing.
//
// Zero value is not usable; construct with newExeLRUCache. Not safe for
// concurrent use: callers serialize access via Tracer.mu, exactly like the
// map it replaces.
type exeLRUCache struct {
	cap int
	// order lists paths from most- to least-recently-used, front to back.
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

// contains reports whether path is currently resident in the cache. A hit
// counts as a USE and moves path to the most-recently-used end -- this is
// what makes eviction true LRU rather than FIFO: two binaries that keep
// getting re-exec'd (repeatedly hitting this check) stay resident no matter
// how much cold, one-off exec churn is interleaved between them, because each
// hit refreshes their recency. Under FIFO (insertion-order eviction, recency
// of use never consulted) that same interleaving would eventually evict both,
// reproducing the exact flip-flop bug this cache exists to fix.
func (c *exeLRUCache) contains(path string) bool {
	e, ok := c.elems[path]
	if !ok {
		return false
	}
	c.order.MoveToFront(e)
	return true
}

// add records path as the most-recently-used entry, evicting the least
// recently used entry if doing so would exceed the cache's capacity. It is a
// no-op reordering (move-to-front) if path is already present.
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
// an attach -- callers only skip work on an actual contains() hit, never
// because add() had to evict to make room.
func (c *exeLRUCache) add(path string) {
	if e, ok := c.elems[path]; ok {
		c.order.MoveToFront(e)
		return
	}
	e := c.order.PushFront(path)
	c.elems[path] = e
	if c.order.Len() > c.cap {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.elems, oldest.Value.(string))
		}
	}
}
