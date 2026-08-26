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
	"testing"
	"time"
)

// TestExeLRUCacheContainsIsTrueLRU pins the load-bearing behavior of
// exeLRUCache directly, without going through ReattachContainerExecPid: a
// contains() hit must refresh recency (move-to-front), not just report
// membership -- that is what makes eviction here true LRU instead of FIFO.
func TestExeLRUCacheContainsIsTrueLRU(t *testing.T) {
	c := newExeLRUCache(3)
	c.add("a")
	c.add("b")
	c.add("c")

	// Touch "a" so it becomes most-recently-used, ahead of "b" and "c" even
	// though it was inserted first.
	if !c.contains("a") {
		t.Fatalf("contains(a) = false, want true right after add")
	}

	// Adding a 4th distinct entry must evict the LEAST recently USED entry.
	// "b" was never touched after being added, and "a" was just refreshed by
	// the contains() call above, so "b" -- not "a" -- must be the one evicted.
	c.add("d")

	if !c.contains("a") {
		t.Error(`contains("a") = false after evicting for "d", want true (a was refreshed, must survive)`)
	}
	if c.contains("b") {
		t.Error(`contains("b") = true after evicting for "d", want false (b was the least recently used)`)
	}
	if !c.contains("c") {
		t.Error(`contains("c") = false after evicting for "d", want true`)
	}
	if !c.contains("d") {
		t.Error(`contains("d") = false right after add, want true`)
	}
}

// TestExeLRUCacheAddIsIdempotentReorder asserts that re-adding an already
// resident path does not grow the set (no duplicate accounting) and refreshes
// its recency exactly like a contains() hit would.
func TestExeLRUCacheAddIsIdempotentReorder(t *testing.T) {
	c := newExeLRUCache(2)
	c.add("a")
	c.add("b")
	c.add("a") // re-add: refresh "a", "b" becomes the least recently used
	c.add("c") // exceeds cap: must evict "b", not "a"

	if !c.contains("a") {
		t.Error(`contains("a") = false, want true (refreshed by the re-add)`)
	}
	if c.contains("b") {
		t.Error(`contains("b") = true, want false (should have been evicted)`)
	}
	if !c.contains("c") {
		t.Error(`contains("c") = false, want true`)
	}
	if got, want := len(c.elems), 2; got != want {
		t.Errorf("len(elems) = %d, want %d (re-add of an existing path must not grow the set)", got, want)
	}
}

// TestExeLRUCacheMissOnUnseenPath asserts a path that was never added is
// reported as a miss and never fabricates a hit.
func TestExeLRUCacheMissOnUnseenPath(t *testing.T) {
	c := newExeLRUCache(exeLRUCap)
	c.add("/usr/bin/bash")
	if c.contains("/usr/bin/docker") {
		t.Error("contains() reported a hit for a path that was never added")
	}
}

// fakeClock is a small, deterministic, manually-advanced injectable clock for
// exeLRUCache's "now" field -- lets tests fast-forward time without sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// TestExeLRUCacheTTLExpiryIsAMiss pins the TTL backstop's contract (code-
// review follow-up: see exeLRUTTL's doc comment for why it exists): an entry
// that is otherwise a cache hit by path/LRU criteria -- present, and would
// not have been evicted for capacity reasons -- must still be reported as a
// miss once it has aged past the TTL, and must NOT be refreshed (moved to
// front / re-stamped) by that failed check, so the caller's fallthrough to a
// real Phase-1 attach is exactly what re-validates and re-records it.
func TestExeLRUCacheTTLExpiryIsAMiss(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	c := newExeLRUCache(exeLRUCap)
	c.now = clock.now

	c.add("/opt/hot/bin")
	if !c.contains("/opt/hot/bin") {
		t.Fatal("contains() = false immediately after add, want true (well within TTL)")
	}

	// Still within the TTL (elapsed since the add above: ttl-1s): must remain
	// a hit. Note contains() itself must NOT refresh the timestamp on a hit --
	// only add()/touchAndReport() do -- otherwise a hot binary that is only
	// ever re-verified via contains() (never a real re-add) would perpetually
	// renew its own TTL window and the backstop would never actually fire for
	// exactly the workload it targets.
	clock.advance(exeLRUTTL - time.Second)
	if !c.contains("/opt/hot/bin") {
		t.Fatal("contains() = false just under the TTL, want true")
	}

	// Cross the TTL boundary: total elapsed since the ORIGINAL add is now
	// (ttl-1s)+(ttl+1s) = 2*ttl, past the limit -- since the contains() call
	// above must not have refreshed lastTouched.
	clock.advance(exeLRUTTL + time.Second)
	if c.contains("/opt/hot/bin") {
		t.Error("contains() = true after exceeding exeLRUTTL, want false (a stale-but-unchanged-path entry must be treated as a miss)")
	}

	// The failed, TTL-expired check above must not have refreshed the entry:
	// it should still report a miss on a later check that hasn't advanced
	// time further, proving the miss above did not silently re-stamp it.
	if c.contains("/opt/hot/bin") {
		t.Error("contains() = true on a second check right after a TTL-expired miss, want false (a failed TTL check must not refresh the entry)")
	}
}

// TestExeLRUCacheAddRefreshesTTL asserts that add() (the path used at commit
// time after a real Phase-1 attach) re-stamps an existing entry's timestamp,
// so a binary that keeps getting genuinely re-attached never ages out on time
// alone.
func TestExeLRUCacheAddRefreshesTTL(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	c := newExeLRUCache(exeLRUCap)
	c.now = clock.now

	c.add("/opt/hot/bin")
	clock.advance(exeLRUTTL - time.Second)
	c.add("/opt/hot/bin") // re-add: must refresh the timestamp
	clock.advance(exeLRUTTL - time.Second)

	if !c.contains("/opt/hot/bin") {
		t.Error("contains() = false, want true (the re-add should have refreshed the TTL clock, so total elapsed since the LAST touch is still under exeLRUTTL)")
	}
}

// TestExeLRUCacheTouchAndReport pins touchAndReport's combined contract: it
// must report the pre-touch presence (TTL included) while unconditionally
// leaving the entry resident and freshly stamped, matching what a
// contains()-then-add() sequence would have done.
func TestExeLRUCacheTouchAndReport(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	c := newExeLRUCache(exeLRUCap)
	c.now = clock.now

	// First touch of a brand new path: not already present.
	if alreadyPresent := c.touchAndReport("/opt/a/bin"); alreadyPresent {
		t.Error("touchAndReport on a brand new path reported alreadyPresent=true, want false")
	}
	if !c.contains("/opt/a/bin") {
		t.Error("path is not resident after touchAndReport, want it added as a side effect")
	}

	// Second touch, well within TTL: already present.
	if alreadyPresent := c.touchAndReport("/opt/a/bin"); !alreadyPresent {
		t.Error("touchAndReport on a fresh, non-expired entry reported alreadyPresent=false, want true")
	}

	// Let it age past the TTL without any intervening touch, then touch again:
	// a TTL-expired entry must report alreadyPresent=false (treated as a
	// miss), exactly like contains() would, while still refreshing it.
	clock.advance(exeLRUTTL + time.Second)
	if alreadyPresent := c.touchAndReport("/opt/a/bin"); alreadyPresent {
		t.Error("touchAndReport on a TTL-expired entry reported alreadyPresent=true, want false (must be treated as a miss)")
	}
	if !c.contains("/opt/a/bin") {
		t.Error("path is not resident right after touchAndReport refreshed it, want it present and fresh")
	}
}
