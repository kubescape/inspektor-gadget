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
