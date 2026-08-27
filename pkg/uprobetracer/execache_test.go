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

import "testing"

// identA/identB/identC/identD are arbitrary, DISTINCT exeIdentity values used
// throughout this file wherever a test needs "some identity" for a path but
// is not itself exercising identity-mismatch behavior (that is covered by
// TestExeLRUCacheTouchIfCurrentMissesOnIdentityChange and
// TestReattachContainerExecPidStaleCacheHitOnInodeChange in
// exec_reattach_lru_test.go).
var (
	identA = exeIdentity{dev: 1, ino: 1}
	identB = exeIdentity{dev: 1, ino: 2}
	identC = exeIdentity{dev: 1, ino: 3}
	identD = exeIdentity{dev: 1, ino: 4}
)

// TestExeLRUCacheTouchIfCurrentIsTrueLRU pins the load-bearing behavior of
// exeLRUCache directly, without going through ReattachContainerExecPid: a
// touchIfCurrent() hit must refresh recency (move-to-front), not just report
// membership -- that is what makes eviction here true LRU instead of FIFO.
func TestExeLRUCacheTouchIfCurrentIsTrueLRU(t *testing.T) {
	c := newExeLRUCache(3)
	c.add("a", identA)
	c.add("b", identB)
	c.add("c", identC)

	// Touch "a" so it becomes most-recently-used, ahead of "b" and "c" even
	// though it was inserted first.
	if !c.touchIfCurrent("a", identA) {
		t.Fatalf("touchIfCurrent(a) = false, want true right after add")
	}

	// Adding a 4th distinct entry must evict the LEAST recently USED entry.
	// "b" was never touched after being added, and "a" was just refreshed by
	// the touchIfCurrent() call above, so "b" -- not "a" -- must be the one
	// evicted.
	c.add("d", identD)

	if !c.touchIfCurrent("a", identA) {
		t.Error(`touchIfCurrent("a") = false after evicting for "d", want true (a was refreshed, must survive)`)
	}
	if c.touchIfCurrent("b", identB) {
		t.Error(`touchIfCurrent("b") = true after evicting for "d", want false (b was the least recently used)`)
	}
	if !c.touchIfCurrent("c", identC) {
		t.Error(`touchIfCurrent("c") = false after evicting for "d", want true`)
	}
	if !c.touchIfCurrent("d", identD) {
		t.Error(`touchIfCurrent("d") = false right after add, want true`)
	}
}

// TestExeLRUCacheAddIsIdempotentReorder asserts that re-adding an already
// resident path (with the SAME identity) does not grow the set (no duplicate
// accounting) and refreshes its recency exactly like a touchIfCurrent() hit
// would.
func TestExeLRUCacheAddIsIdempotentReorder(t *testing.T) {
	c := newExeLRUCache(2)
	c.add("a", identA)
	c.add("b", identB)
	c.add("a", identA) // re-add: refresh "a", "b" becomes the least recently used
	c.add("c", identC) // exceeds cap: must evict "b", not "a"

	if !c.touchIfCurrent("a", identA) {
		t.Error(`touchIfCurrent("a") = false, want true (refreshed by the re-add)`)
	}
	if c.touchIfCurrent("b", identB) {
		t.Error(`touchIfCurrent("b") = true, want false (should have been evicted)`)
	}
	if !c.touchIfCurrent("c", identC) {
		t.Error(`touchIfCurrent("c") = false, want true`)
	}
	if got, want := len(c.elems), 2; got != want {
		t.Errorf("len(elems) = %d, want %d (re-add of an existing path must not grow the set)", got, want)
	}
}

// TestExeLRUCacheMissOnUnseenPath asserts a path that was never added is
// reported as a miss and never fabricates a hit.
func TestExeLRUCacheMissOnUnseenPath(t *testing.T) {
	c := newExeLRUCache(exeLRUCap)
	c.add("/usr/bin/bash", identA)
	if c.touchIfCurrent("/usr/bin/docker", identA) {
		t.Error("touchIfCurrent() reported a hit for a path that was never added")
	}
}

// TestExeLRUCacheTouchIfCurrentMissesOnIdentityChange pins the fix for
// matthyx's BLOCKER review comment (armosec/private-node-agent#541): a path
// that IS resident is still a MISS if the identity presented does not match
// what was recorded, and a failed identity check must not mutate recency or
// silently adopt the new identity (only touchAndReport -- a real,
// successfully-committed Phase-1 attach -- may do that).
func TestExeLRUCacheTouchIfCurrentMissesOnIdentityChange(t *testing.T) {
	c := newExeLRUCache(exeLRUCap)
	c.add("/opt/a/bin", identA)

	if !c.touchIfCurrent("/opt/a/bin", identA) {
		t.Fatal("touchIfCurrent with the SAME identity reported a miss, want a hit")
	}
	if c.touchIfCurrent("/opt/a/bin", identB) {
		t.Error("touchIfCurrent with a DIFFERENT identity at an already-resident path reported a hit, want a miss -- this is the exact stale-cache-hit bug matthyx's review found")
	}
	// The failed identity check above must not have adopted identB or moved
	// the entry: the ORIGINAL identity must still be what's recorded.
	if !c.touchIfCurrent("/opt/a/bin", identA) {
		t.Error("original identity no longer matches after a failed identity check, want it unchanged (a miss must not mutate the stored identity)")
	}
}

// TestExeLRUCacheTouchAndReport pins touchAndReport's combined contract: it
// must report (a) whether the path was ALREADY resident with the SAME
// identity ("current") and (b) whether committing it evicted another entry
// ("evicted"), while unconditionally leaving path resident with the given
// identity as the most-recently-used entry.
func TestExeLRUCacheTouchAndReport(t *testing.T) {
	c := newExeLRUCache(2)

	// First touch of a brand new path: not already current, no eviction (cache
	// has room).
	if current, evicted := c.touchAndReport("/opt/a/bin", identA); current || evicted {
		t.Errorf("touchAndReport on a brand new path = (current=%v, evicted=%v), want (false, false)", current, evicted)
	}
	if !c.touchIfCurrent("/opt/a/bin", identA) {
		t.Error("path is not resident after touchAndReport, want it added as a side effect")
	}

	// Second touch, SAME identity: already current, no eviction.
	if current, evicted := c.touchAndReport("/opt/a/bin", identA); !current || evicted {
		t.Errorf("touchAndReport on an unchanged, already-resident entry = (current=%v, evicted=%v), want (true, false)", current, evicted)
	}

	// Touch with a DIFFERENT identity at the SAME path: NOT current (the
	// content changed -- this must not be reported as redundant), no eviction
	// (still the same path, no new slot needed).
	if current, evicted := c.touchAndReport("/opt/a/bin", identB); current || evicted {
		t.Errorf("touchAndReport on a path with a CHANGED identity = (current=%v, evicted=%v), want (false, false)", current, evicted)
	}
	if !c.touchIfCurrent("/opt/a/bin", identB) {
		t.Error("path is not resident with its NEW identity right after touchAndReport recorded it")
	}
	if c.touchIfCurrent("/opt/a/bin", identA) {
		t.Error("path still matches its OLD identity after touchAndReport recorded a new one, want the old identity to no longer match")
	}

	// Fill the cache to capacity, then push it over: the next new path must
	// evict the least-recently-used one and report evicted=true.
	c.touchAndReport("/opt/b/bin", identB)
	if current, evicted := c.touchAndReport("/opt/c/bin", identC); current || !evicted {
		t.Errorf("touchAndReport pushing the cache over capacity = (current=%v, evicted=%v), want (false, true)", current, evicted)
	}
}

// TestExeLRUCacheTouchAndReportEvictsLeastRecentlyUsed asserts the "evicted"
// eviction case (feeding ig_uprobetracer_exe_cache_miss_total) fires for the
// LEAST recently used entry specifically, not an arbitrary one, and does not
// fire at all while the cache still has room.
func TestExeLRUCacheTouchAndReportEvictsLeastRecentlyUsed(t *testing.T) {
	c := newExeLRUCache(2)

	if _, evicted := c.touchAndReport("a", identA); evicted {
		t.Error("touchAndReport evicted while the cache had room for the 1st entry")
	}
	if _, evicted := c.touchAndReport("b", identB); evicted {
		t.Error("touchAndReport evicted while the cache had room for the 2nd entry")
	}

	// Refresh "a" so "b" becomes the least recently used.
	c.touchAndReport("a", identA)

	_, evicted := c.touchAndReport("c", identC)
	if !evicted {
		t.Fatal("touchAndReport did not report an eviction when pushing a full cache over capacity")
	}
	if c.touchIfCurrent("b", identB) {
		t.Error(`"b" survived eviction, want it gone (it was the least recently used)`)
	}
	if !c.touchIfCurrent("a", identA) {
		t.Error(`"a" was evicted, want it to survive (it was refreshed just before the eviction)`)
	}
}

// TestExeLRUCachePeekIsReadOnly asserts peek reports residency without
// consulting identity and without mutating LRU recency -- the genuinely
// read-only observer added alongside the touchIfCurrent rename (code-review
// nit: the old contains() mutated recency despite reading as a pure
// predicate).
func TestExeLRUCachePeekIsReadOnly(t *testing.T) {
	c := newExeLRUCache(2)
	c.add("a", identA)
	c.add("b", identB)

	if !c.peek("a") {
		t.Error("peek(a) = false, want true (a is resident)")
	}
	if c.peek("z") {
		t.Error("peek(z) = true, want false (z was never added)")
	}
	// peek must report residency regardless of identity -- it does not take
	// one as an argument at all.
	if !c.peek("a") {
		t.Error("peek(a) = false on a second call, want true")
	}

	// peek must not refresh recency: "a" was inserted first and never touched
	// via touchIfCurrent/touchAndReport since, so it must still be the least
	// recently used and get evicted first, even though peek was just called
	// on it repeatedly above.
	c.add("c", identC) // exceeds cap: must evict "a", not "b", if peek is truly read-only
	if c.touchIfCurrent("a", identA) {
		t.Error(`"a" survived eviction after being peek()'d, want it evicted -- peek must not refresh LRU recency`)
	}
	if !c.touchIfCurrent("b", identB) {
		t.Error(`"b" was evicted instead of "a", want "b" to survive -- peek on "a" must not have protected it`)
	}
}
