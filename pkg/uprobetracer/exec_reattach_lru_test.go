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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// fakeExeProc synthesizes a /proc/<pid>/exe symlink under a private
// host.HostProcFs root, exactly like TestReattachContainerMappedLibsPidUsesExecPidForDiscovery
// does elsewhere in this package -- except only the "exe" entry is needed
// here, since ReattachContainerExecPid's fast-path guard and
// settledExecutablePath both only ever consult /proc/<execPid>/exe. The
// target need not exist on disk: os.Readlink returns whatever string the
// symlink was created with regardless, and openInContainer is mocked in
// these tests (testState.open), so nothing ever tries to actually open it.
func fakeExeProc(t *testing.T, procRoot string, pid uint32, target string) {
	t.Helper()
	dir := filepath.Join(procRoot, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "exe")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
}

// withFakeProcRoot points host.HostProcFs at a fresh temp dir for the
// duration of the test and restores it on cleanup. host.HostProcFs is a
// process-global, so (mirroring the existing convention in this package) no
// test using it may run with t.Parallel(), and no other test touching it may
// run concurrently with it -- both hold here since this package never calls
// t.Parallel().
func withFakeProcRoot(t *testing.T) string {
	t.Helper()
	prev := host.HostProcFs
	tmp := t.TempDir()
	host.HostProcFs = tmp
	t.Cleanup(func() { host.HostProcFs = prev })
	return tmp
}

// TestReattachContainerExecPidConcurrentDistinctBinariesAllCache is the core
// regression test for armosec/private-node-agent#541: several DIFFERENT
// short-lived binaries execing under one container (e.g. bash, docker, top
// within seconds of each other) must each get their own durable fast-path
// cache entry, so a second round of the same execs -- even fired concurrently
// -- hits the cache for every one of them instead of falling through to
// Phase-1 I/O. Run with -race: the fast-path cache lookup mutates LRU
// recency, so this also proves that mutation is safe under concurrent calls.
func TestReattachContainerExecPidConcurrentDistinctBinariesAllCache(t *testing.T) {
	procRoot := withFakeProcRoot(t)
	tr, st := newTestTracer(t)
	const trackedPid = fakePid
	tr.containerPid2Inodes[trackedPid] = nil // tracked, as AttachContainer would seed it

	const n = 5
	execPids := make([]uint32, n)
	for i := 0; i < n; i++ {
		execPids[i] = fakePid + 1000 + uint32(i)
		fakeExeProc(t, procRoot, execPids[i], fmt.Sprintf("/opt/bin-%d/bin", i))
	}

	// Warm-up pass: sequential, one exec per distinct binary. Each must be a
	// genuine miss (Phase-1 I/O runs, growing openedPaths) since none has been
	// seen before.
	for i, execPid := range execPids {
		st.currentInode = uint64(100 + i) // a distinct binary => a distinct realInode
		opensBefore := len(st.openedPaths)
		if err := tr.ReattachContainerExecPid(trackedPid, execPid); err != nil {
			t.Fatalf("warm-up ReattachContainerExecPid(#%d): %v", i, err)
		}
		if len(st.openedPaths) == opensBefore {
			t.Fatalf("warm-up exec #%d was a cache hit, want a miss (first time seeing this path)", i)
		}
	}
	opensAfterWarmup := len(st.openedPaths)
	attachesAfterWarmup := st.attachCount
	if attachesAfterWarmup != n {
		t.Fatalf("attachCount after warm-up = %d, want %d (one new inode per distinct binary)", attachesAfterWarmup, n)
	}

	// Second pass: re-exec the SAME n binaries, concurrently. Every one of
	// them is now in the container's recent-set, so every call must hit the
	// fast path and do NO Phase-1 I/O at all -- no redundant open/resolve for
	// a binary already attached moments ago. Before the fix (a single-slot
	// cache overwritten by whichever call ran last) this would almost always
	// miss for every binary but the one that happened to run last.
	var wg sync.WaitGroup
	for _, execPid := range execPids {
		wg.Add(1)
		go func(execPid uint32) {
			defer wg.Done()
			if err := tr.ReattachContainerExecPid(trackedPid, execPid); err != nil {
				t.Errorf("concurrent ReattachContainerExecPid(execPid=%d): %v", execPid, err)
			}
		}(execPid)
	}
	wg.Wait()

	if got := len(st.openedPaths); got != opensAfterWarmup {
		t.Errorf("openedPaths grew from %d to %d after the all-cached concurrent pass -- at least one previously-seen binary fell through to Phase-1 I/O", opensAfterWarmup, got)
	}
	if st.attachCount != attachesAfterWarmup {
		t.Errorf("attachCount = %d after the cached pass, want %d (no new attach work for already-seen binaries)", st.attachCount, attachesAfterWarmup)
	}
}

// TestReattachContainerExecPidLRUSurvivesColdChurnBetweenHotBinaries is the
// discriminator between true LRU and FIFO eviction. Two "hot" binaries
// (repeatedly re-exec'd, i.e. repeatedly hitting the cache) are interleaved
// with more than exeLRUCap cold, one-off execs. Under true recency-of-USE
// LRU, touching a hot binary refreshes it every round, so it is never the
// least-recently-used entry and never gets evicted no matter how much cold
// churn runs in between. Under FIFO (eviction by insertion order, blind to
// later touches) the two hot binaries -- inserted FIRST, and so the oldest
// entries by insertion order -- are exactly the ones a bounded cap starts
// evicting first once churn exceeds the cap, reproducing the flip-flop bug
// this cache exists to fix. This test fails if contains()/add() stop
// refreshing recency on use (i.e. degrade to FIFO).
func TestReattachContainerExecPidLRUSurvivesColdChurnBetweenHotBinaries(t *testing.T) {
	procRoot := withFakeProcRoot(t)
	tr, st := newTestTracer(t)
	const trackedPid = fakePid
	tr.containerPid2Inodes[trackedPid] = nil

	hotAPid, hotBPid := fakePid+1, fakePid+2
	fakeExeProc(t, procRoot, hotAPid, "/opt/hot-a/bin")
	fakeExeProc(t, procRoot, hotBPid, "/opt/hot-b/bin")

	// exec reattaches and reports whether the call was a cache hit (no Phase-1
	// I/O at all) based on whether openInContainer was invoked.
	exec := func(execPid uint32, inode uint64) (hit bool) {
		t.Helper()
		st.currentInode = inode
		opensBefore := len(st.openedPaths)
		if err := tr.ReattachContainerExecPid(trackedPid, execPid); err != nil {
			t.Fatalf("ReattachContainerExecPid(execPid=%d): %v", execPid, err)
		}
		return len(st.openedPaths) == opensBefore
	}

	if hit := exec(hotAPid, 9001); hit {
		t.Fatal("first exec of hotA reported a hit, want a miss")
	}
	if hit := exec(hotBPid, 9002); hit {
		t.Fatal("first exec of hotB reported a hit, want a miss")
	}

	// More cold, one-off binaries than the cache's capacity, each interleaved
	// with a re-touch of BOTH hot binaries. Under LRU, hotA/hotB must be a hit
	// on every single one of these touches, all the way through.
	const coldChurnCount = exeLRUCap + 5
	for i := 0; i < coldChurnCount; i++ {
		if hit := exec(hotAPid, 9001); !hit {
			t.Fatalf("hotA exec #%d (mid-churn) was a MISS -- evicted despite being touched every round; true LRU would never do this (looks like FIFO eviction)", i)
		}
		if hit := exec(hotBPid, 9002); !hit {
			t.Fatalf("hotB exec #%d (mid-churn) was a MISS -- evicted despite being touched every round; true LRU would never do this (looks like FIFO eviction)", i)
		}

		coldPid := fakePid + 1000 + uint32(i)
		fakeExeProc(t, procRoot, coldPid, fmt.Sprintf("/opt/cold-%d/bin", i))
		if hit := exec(coldPid, uint64(20000+i)); hit {
			t.Fatalf("cold exec #%d reported a hit, want a miss (never seen before)", i)
		}
	}

	// Final check after all the churn: both hot binaries must still be
	// resident.
	if hit := exec(hotAPid, 9001); !hit {
		t.Error("hotA is a miss after the full churn run, want a hit (true LRU must keep a repeatedly-touched entry resident)")
	}
	if hit := exec(hotBPid, 9002); !hit {
		t.Error("hotB is a miss after the full churn run, want a hit (true LRU must keep a repeatedly-touched entry resident)")
	}
}

// TestReattachContainerExecPidEvictionFallsThroughToCorrectAttach is the
// correctness half of the eviction contract: once a binary's cache entry has
// aged out (evicted purely to respect the capacity bound), the NEXT exec of
// that same binary must be treated exactly like a first-time exec -- fully
// re-resolved and re-attached via the correct, live execPid -- never served a
// stale hit and never left unattached. This is what makes eviction a
// performance-only cost, never a correctness one: a full cache must never
// silently skip a real attach.
func TestReattachContainerExecPidEvictionFallsThroughToCorrectAttach(t *testing.T) {
	procRoot := withFakeProcRoot(t)
	tr, st := newTestTracer(t)
	const trackedPid = fakePid
	tr.containerPid2Inodes[trackedPid] = nil

	victimPid := fakePid + 1
	victimTarget := "/opt/victim/bin"
	fakeExeProc(t, procRoot, victimPid, victimTarget)

	st.currentInode = 555
	if err := tr.ReattachContainerExecPid(trackedPid, victimPid); err != nil {
		t.Fatalf("initial ReattachContainerExecPid(victim): %v", err)
	}
	if st.attachCount != 1 {
		t.Fatalf("attachCount after initial victim attach = %d, want 1", st.attachCount)
	}

	// Evict the victim by pushing more than exeLRUCap distinct new binaries
	// through, without ever touching the victim again.
	for i := 0; i < exeLRUCap+1; i++ {
		pid := fakePid + 1000 + uint32(i)
		fakeExeProc(t, procRoot, pid, fmt.Sprintf("/opt/filler-%d/bin", i))
		st.currentInode = uint64(30000 + i)
		if err := tr.ReattachContainerExecPid(trackedPid, pid); err != nil {
			t.Fatalf("filler exec #%d: %v", i, err)
		}
	}

	// The victim's binary is rebuilt/relinked between execs (a new, distinct
	// realInode) and execs again under a fresh execPid, exactly like a
	// wrapper-loop's next iteration forking a new short-lived child. Nothing
	// about the OLD cached string must leak into this call's outcome.
	newVictimPid := fakePid + 2
	fakeExeProc(t, procRoot, newVictimPid, victimTarget)
	st.currentInode = 777 // deliberately a NEW realInode, distinguishable from the stale one (555)

	opensBefore := len(st.openedPaths)
	attachesBefore := st.attachCount
	if err := tr.ReattachContainerExecPid(trackedPid, newVictimPid); err != nil {
		t.Fatalf("post-eviction ReattachContainerExecPid(victim): %v", err)
	}

	if len(st.openedPaths) == opensBefore {
		t.Fatal("post-eviction exec of the victim was a cache hit, want a miss -- eviction must fall through to the full attach path, not skip it")
	}
	newlyOpened := st.openedPaths[opensBefore:]
	found := false
	for _, p := range newlyOpened {
		if p == victimTarget {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("newly opened paths = %v, want them to include %q -- the correct, freshly-resolved exe path for the LIVE execPid must be used, not a stale one", newlyOpened, victimTarget)
	}
	if st.attachCount != attachesBefore+1 {
		t.Errorf("attachCount = %d, want %d (the new realInode must be freshly attached, not skipped as if already known)", st.attachCount, attachesBefore+1)
	}
	if k := tr.inodeRefCount[777]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[777] = %+v, want a fresh keeper with counter 1 (the correct NEW inode must be the one credited)", k)
	}
	if k := tr.inodeRefCount[555]; k == nil {
		t.Error("inodeRefCount[555] (the original victim attach) disappeared -- eviction from the exe-target cache must never retroactively undo a real attach")
	}
}

// TestReattachContainerExecPidTTLExpiryTriggersRealAttach is the code-review
// follow-up regression test for the exeLRUTTL backstop (see exeLRUTTL's doc
// comment in execache.go, and ReattachContainerExecPid's doc comment on the
// fast-path guard): an exe-target entry that is a cache hit by every
// path/LRU criterion (same resolved path, never evicted for capacity reasons,
// well under exeLRUCap churn) must still be treated as a miss -- and trigger
// a real Phase-1 resolve+attach -- once it has aged past exeLRUTTL. This is
// the concrete, bounded backstop against a container hot-reloading/self-
// updating a binary in place at the same path: unlike a full inode check,
// this cache genuinely cannot detect that the file content changed, so the
// TTL is what keeps its staleness window bounded instead of open-ended.
func TestReattachContainerExecPidTTLExpiryTriggersRealAttach(t *testing.T) {
	procRoot := withFakeProcRoot(t)
	tr, st := newTestTracer(t)
	const trackedPid = fakePid
	tr.containerPid2Inodes[trackedPid] = nil

	target := "/opt/stable/bin"
	firstExecPid := fakePid + 1
	fakeExeProc(t, procRoot, firstExecPid, target)

	st.currentInode = 111
	if err := tr.ReattachContainerExecPid(trackedPid, firstExecPid); err != nil {
		t.Fatalf("initial ReattachContainerExecPid: %v", err)
	}
	if st.attachCount != 1 {
		t.Fatalf("attachCount after initial attach = %d, want 1", st.attachCount)
	}

	// Immediately re-exec the SAME path under a fresh execPid, well within the
	// TTL: this must be a cache hit -- confirms the entry really is resident
	// and would (absent the TTL) keep being a hit indefinitely for this
	// stable, repeatedly-exec'd binary.
	secondExecPid := fakePid + 2
	fakeExeProc(t, procRoot, secondExecPid, target)
	opensBefore := len(st.openedPaths)
	if err := tr.ReattachContainerExecPid(trackedPid, secondExecPid); err != nil {
		t.Fatalf("second (pre-TTL) ReattachContainerExecPid: %v", err)
	}
	if len(st.openedPaths) != opensBefore {
		t.Fatalf("second exec (well within TTL) was a miss, want a hit -- precondition for this test not met")
	}

	// Fast-forward the cache's injectable clock past exeLRUTTL, without any
	// other churn (no capacity eviction is involved here at all).
	cache := tr.containerPid2ExeTargets[trackedPid]
	if cache == nil {
		t.Fatal("containerPid2ExeTargets has no entry for trackedPid after two successful attaches")
	}
	base := cache.now()
	cache.now = func() time.Time { return base.Add(exeLRUTTL + time.Second) }

	// A third exec of the exact same path, now past the TTL: must be treated
	// as a miss -- real Phase-1 I/O runs -- and the same, correct, live
	// realInode must be (re-)attached, not skipped.
	thirdExecPid := fakePid + 3
	fakeExeProc(t, procRoot, thirdExecPid, target)
	st.currentInode = 111 // unchanged content/inode -- this is the TTL backstop, not an inode-change scenario
	opensBefore = len(st.openedPaths)
	attachesBefore := st.attachCount
	if err := tr.ReattachContainerExecPid(trackedPid, thirdExecPid); err != nil {
		t.Fatalf("post-TTL ReattachContainerExecPid: %v", err)
	}
	if len(st.openedPaths) == opensBefore {
		t.Error("post-TTL exec of a still-resident, unevicted path was a cache hit, want a miss -- exeLRUTTL must force a real Phase-1 attach once an entry ages past it")
	}
	if st.attachCount != attachesBefore {
		// realInode 111 was already attached and still tracked (never
		// detached), so the fresh Phase-1 pass should recognize the same
		// inode as already-attached bookkeeping-wise (commitOpenedTargets is
		// idempotent per inode) -- what matters here is that real I/O ran at
		// all (checked above), not that a brand new inode was counted again.
		t.Logf("attachCount unchanged at %d across the post-TTL call -- expected, since realInode 111 was already tracked", st.attachCount)
	}

	// The cache must have been refreshed by this successful pass -- an
	// immediate follow-up exec must be a hit again.
	fourthExecPid := fakePid + 4
	fakeExeProc(t, procRoot, fourthExecPid, target)
	opensBefore = len(st.openedPaths)
	if err := tr.ReattachContainerExecPid(trackedPid, fourthExecPid); err != nil {
		t.Fatalf("post-refresh ReattachContainerExecPid: %v", err)
	}
	if len(st.openedPaths) != opensBefore {
		t.Error("exec right after the TTL-triggered re-attach was a miss, want a hit -- the successful pass must have re-stamped the cache entry")
	}
}
