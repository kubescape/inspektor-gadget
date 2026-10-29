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
	"errors"
	"os"
	"testing"
)

// creditCandidate opens a throwaway file to hand to CreditIfAttached. It is NOT
// registered in testState.openFiles: CreditIfAttached consumes and closes it, and
// the tests assert exactly that.
func creditCandidate(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("opening credit candidate: %v", err)
	}
	return f
}

// assertClosed fails unless f has already been closed: a second Close on an
// os.File whose fd was released returns os.ErrClosed, whereas a leaked-open file
// closes cleanly. This is the fd-leak check.
func assertClosed(t *testing.T, f *os.File, what string) {
	t.Helper()
	err := f.Close()
	if err == nil {
		t.Errorf("%s: file was still open after CreditIfAttached (fd leak)", what)
		return
	}
	if !errors.Is(err, os.ErrClosed) {
		t.Errorf("%s: unexpected Close error %v, want os.ErrClosed", what, err)
	}
}

// trackPidWithoutAttach registers pid as tracked (so it has a
// containerPid2Inodes entry) while making the create-time attach bind nothing,
// so the pid starts with an EMPTY inode set. That is the only interesting
// starting state for CreditIfAttached: tracked, but not yet crediting the inode.
func trackPidWithoutAttach(t *testing.T, tr *Tracer[any], st *testState, pid uint32) {
	t.Helper()
	savedOpenErr := st.openErr
	st.openErr = errors.New("open blocked for test setup")
	if err := tr.AttachContainer(testContainer(pid)); err != nil {
		t.Fatalf("AttachContainer(%d): %v", pid, err)
	}
	st.openErr = savedOpenErr
	if inodes, tracked := tr.containerPid2Inodes[pid]; !tracked || len(inodes) != 0 {
		t.Fatalf("setup: containerPid2Inodes[%d] = %v (tracked=%v), want tracked with no inodes", pid, inodes, tracked)
	}
}

// 1. Nothing is attached for the resolved inode: no credit, no side effects.
func TestCreditIfAttachedNotAttachedIsNoOp(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	attachesBefore := st.attachCount

	// A DIFFERENT inode than the one attached above.
	st.currentInode = 999
	f := creditCandidate(t)
	inode, credited, err := tr.CreditIfAttached(fakePid, f)
	if err != nil {
		t.Fatalf("CreditIfAttached: %v", err)
	}
	if inode != 999 {
		t.Errorf("realInodePtr = %d, want 999", inode)
	}
	if credited {
		t.Errorf("credited = true, want false (inode is not attached anywhere)")
	}
	assertClosed(t, f, "not-attached outcome")

	if st.attachCount != attachesBefore {
		t.Errorf("attachCount = %d, want %d (CreditIfAttached must never attach)", st.attachCount, attachesBefore)
	}
	if _, exists := tr.inodeRefCount[999]; exists {
		t.Errorf("inodeRefCount gained an entry for the uncredited inode")
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 1 (untouched)", k)
	}
	if got := tr.containerPid2Inodes[fakePid]; len(got) != 1 || got[0] != 100 {
		t.Errorf("containerPid2Inodes[pid] = %v, want [100] (untouched)", got)
	}
}

// 2. The inode is attached for another pid: a third, tracked pid gets credited
// both halves -- the shared refcount AND its own containerPid2Inodes entry.
func TestCreditIfAttachedCreditsThirdPid(t *testing.T) {
	tr, st := newTestTracer(t)
	pidA, pidB, pidC := fakePid, fakePid+1, fakePid+2
	st.currentInode = 100

	if err := tr.AttachContainer(testContainer(pidA)); err != nil {
		t.Fatalf("AttachContainer(A): %v", err)
	}
	if err := tr.AttachContainer(testContainer(pidB)); err != nil {
		t.Fatalf("AttachContainer(B): %v", err)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 2 {
		t.Fatalf("setup: inodeRefCount[100] = %+v, want counter 2", k)
	}
	attachesBefore := st.attachCount

	trackPidWithoutAttach(t, tr, st, pidC)

	f := creditCandidate(t)
	inode, credited, err := tr.CreditIfAttached(pidC, f)
	if err != nil {
		t.Fatalf("CreditIfAttached: %v", err)
	}
	if inode != 100 {
		t.Errorf("realInodePtr = %d, want 100", inode)
	}
	if !credited {
		t.Fatalf("credited = false, want true (inode 100 is attached for pids A and B)")
	}
	assertClosed(t, f, "credited outcome")

	if st.attachCount != attachesBefore {
		t.Errorf("attachCount = %d, want %d (credit must not re-attach)", st.attachCount, attachesBefore)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 3 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 3 after crediting a third pid", k)
	}
	// The half attachOneOpenFile alone would NOT do -- without it DetachContainer
	// could never release pidC's reference.
	if got := tr.containerPid2Inodes[pidC]; len(got) != 1 || got[0] != 100 {
		t.Errorf("containerPid2Inodes[pidC] = %v, want [100] (refcount credited with no owner = permanent leak)", got)
	}
}

// 3. A repeat call for the SAME pid is idempotent: no double-count, no duplicate
// entry, and the file is still consumed.
func TestCreditIfAttachedIdempotentForSamePid(t *testing.T) {
	tr, st := newTestTracer(t)
	pidA, pidC := fakePid, fakePid+2
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(pidA)); err != nil {
		t.Fatalf("AttachContainer(A): %v", err)
	}
	trackPidWithoutAttach(t, tr, st, pidC)

	for i := 0; i < 4; i++ {
		f := creditCandidate(t)
		inode, credited, err := tr.CreditIfAttached(pidC, f)
		if err != nil {
			t.Fatalf("CreditIfAttached #%d: %v", i, err)
		}
		if inode != 100 || !credited {
			t.Fatalf("CreditIfAttached #%d = (%d, %v), want (100, true)", i, inode, credited)
		}
		assertClosed(t, f, "repeat credit")
	}

	if k := tr.inodeRefCount[100]; k == nil || k.counter != 2 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 2 (pidA + one credit for pidC)", k)
	}
	if got := tr.containerPid2Inodes[pidC]; len(got) != 1 || got[0] != 100 {
		t.Errorf("containerPid2Inodes[pidC] = %v, want exactly [100]", got)
	}
}

// 4. Detaching one pid must not disturb another pid's credited reference to the
// same real inode: the refcount drops only by what the detached pid owned.
func TestCreditIfAttachedDetachIsPerPid(t *testing.T) {
	tr, st := newTestTracer(t)
	pidA, pidB, pidC := fakePid, fakePid+1, fakePid+2
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(pidA)); err != nil {
		t.Fatalf("AttachContainer(A): %v", err)
	}
	if err := tr.AttachContainer(testContainer(pidB)); err != nil {
		t.Fatalf("AttachContainer(B): %v", err)
	}
	trackPidWithoutAttach(t, tr, st, pidC)
	if _, credited, err := tr.CreditIfAttached(pidC, creditCandidate(t)); err != nil || !credited {
		t.Fatalf("CreditIfAttached(pidC) = (%v, %v), want credited", credited, err)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 3 {
		t.Fatalf("setup: inodeRefCount[100] = %+v, want counter 3", k)
	}

	if err := tr.DetachContainer(testContainer(pidA)); err != nil {
		t.Fatalf("DetachContainer(A): %v", err)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 2 {
		t.Fatalf("after detaching A: inodeRefCount[100] = %+v, want counter 2", k)
	}
	if got := tr.containerPid2Inodes[pidC]; len(got) != 1 || got[0] != 100 {
		t.Errorf("detaching A disturbed pidC's reference: containerPid2Inodes[pidC] = %v", got)
	}

	// pidC's credited reference is releasable exactly like a real attach's.
	if err := tr.DetachContainer(testContainer(pidC)); err != nil {
		t.Fatalf("DetachContainer(C): %v", err)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 1 {
		t.Fatalf("after detaching C: inodeRefCount[100] = %+v, want counter 1", k)
	}
	if err := tr.DetachContainer(testContainer(pidB)); err != nil {
		t.Fatalf("DetachContainer(B): %v", err)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount not empty after every pid detached: %v (leak/over-ref)", tr.inodeRefCount)
	}
}

// 5. An untracked pid must not gain an entry (nothing would release it), and the
// file is consumed there too.
func TestCreditIfAttachedUntrackedPidIsNoOp(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	untracked := fakePid + 7
	f := creditCandidate(t)
	inode, credited, err := tr.CreditIfAttached(untracked, f)
	if err != nil {
		t.Fatalf("CreditIfAttached: %v", err)
	}
	if inode != 100 {
		t.Errorf("realInodePtr = %d, want 100", inode)
	}
	if credited {
		t.Errorf("credited = true for an untracked pid (would leak: DetachContainer never runs for it)")
	}
	assertClosed(t, f, "untracked pid outcome")

	if _, ok := tr.containerPid2Inodes[untracked]; ok {
		t.Errorf("containerPid2Inodes gained an entry for an untracked pid")
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 1 (untouched)", k)
	}
}

// 6. A failed inode resolve is a distinguishable error, never a silent
// credited/uncredited answer -- and the file is still consumed.
func TestCreditIfAttachedInodeErrorClosesFile(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	sentinel := errors.New("kfilefields round trip timed out")
	st.inodeErr = sentinel
	f := creditCandidate(t)
	inode, credited, err := tr.CreditIfAttached(fakePid, f)
	if err == nil {
		t.Fatalf("CreditIfAttached returned nil error on inode resolve failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error %v does not wrap the underlying failure", err)
	}
	if inode != 0 || credited {
		t.Errorf("got (%d, %v), want (0, false) on error", inode, credited)
	}
	assertClosed(t, f, "inode error outcome")

	if k := tr.inodeRefCount[100]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 1 (untouched on error)", k)
	}
	if got := tr.containerPid2Inodes[fakePid]; len(got) != 1 {
		t.Errorf("containerPid2Inodes[pid] = %v, want untouched on error", got)
	}
}

// 7. A closed tracer is an error, not a silent success, and nothing is touched.
func TestCreditIfAttachedOnClosedTracer(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	tr.Close()

	f := creditCandidate(t)
	inode, credited, err := tr.CreditIfAttached(fakePid, f)
	if err == nil {
		t.Fatalf("CreditIfAttached on a closed tracer returned nil error")
	}
	if inode != 0 || credited {
		t.Errorf("got (%d, %v), want (0, false) on a closed tracer", inode, credited)
	}
	assertClosed(t, f, "closed tracer outcome")
}

// 8. CreditIfAttached's t.mu hold time is recorded into its own histogram
// (MuHoldCredit), distinct from commitOpenedTargets' MuHold: a credit must not
// move MuHold, and a create-time attach (exercised via AttachContainer, which
// calls commitOpenedTargets) must not move MuHoldCredit. Conflating the two
// would make it impossible to tell "hold-time credit contention" apart from
// "create-time attach contention".
func TestCreditIfAttachedRecordsMuHoldCredit(t *testing.T) {
	tr, st := newTestTracer(t)
	pidA, pidC := fakePid, fakePid+2
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(pidA)); err != nil {
		t.Fatalf("AttachContainer(A): %v", err)
	}
	trackPidWithoutAttach(t, tr, st, pidC)

	muHoldBefore := tr.Stats().MuHold.Count
	if got := tr.Stats().MuHoldCredit.Count; got != 0 {
		t.Fatalf("MuHoldCredit.Count = %d before any credit, want 0", got)
	}

	f := creditCandidate(t)
	if _, credited, err := tr.CreditIfAttached(pidC, f); err != nil || !credited {
		t.Fatalf("CreditIfAttached = (%v, %v), want credited", credited, err)
	}
	assertClosed(t, f, "credited outcome")

	if got := tr.Stats().MuHoldCredit.Count; got != 1 {
		t.Errorf("MuHoldCredit.Count = %d after one credit, want 1", got)
	}
	if got := tr.Stats().MuHold.Count; got != muHoldBefore {
		t.Errorf("MuHold.Count = %d after CreditIfAttached, want unchanged %d (CreditIfAttached must not move MuHold)", got, muHoldBefore)
	}

	// Reverse direction: a create-time attach must not move MuHoldCredit.
	muHoldCreditBefore := tr.Stats().MuHoldCredit.Count
	if err := tr.AttachContainer(testContainer(fakePid + 3)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	if got := tr.Stats().MuHold.Count; got <= muHoldBefore {
		t.Errorf("MuHold.Count = %d, want > %d after a create-time attach", got, muHoldBefore)
	}
	if got := tr.Stats().MuHoldCredit.Count; got != muHoldCreditBefore {
		t.Errorf("MuHoldCredit.Count = %d, want unchanged %d after a create-time attach", got, muHoldCreditBefore)
	}
}
