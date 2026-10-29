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

// attachCandidate opens a throwaway file to hand to AttachOpenFile. It is NOT
// registered in testState.openFiles: AttachOpenFile consumes and closes it
// (attachOneOpenFile does, on every path), and the tests assert exactly that.
func attachCandidate(t *testing.T) *os.File {
	t.Helper()
	return creditCandidate(t)
}

// 1. Tracked pid, nothing attached yet for the resolved inode: a fresh attach,
// credited to this pid, with the real uprobe attach actually performed --
// unlike CreditIfAttached, which must never attach.
func TestAttachOpenFileFreshAttach(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	trackPidWithoutAttach(t, tr, st, fakePid)
	attachesBefore := st.attachCount

	f := attachCandidate(t)
	inode, added, err := tr.AttachOpenFile(fakePid, f, "candidate")
	if err != nil {
		t.Fatalf("AttachOpenFile: %v", err)
	}
	if inode != 100 {
		t.Errorf("realInodePtr = %d, want 100", inode)
	}
	if !added {
		t.Fatalf("added = false, want true (fresh attach)")
	}
	// A fresh attach's file is NOT closed here: attachOneOpenFile hands
	// ownership to the new inodeKeeper, which keeps it open until
	// DetachContainer releases the last reference -- unlike every other
	// outcome (already-attached, symbol-absent, untracked, error), where
	// attachOneOpenFile closes it immediately.
	if err := f.Close(); err != nil {
		t.Errorf("fresh attach outcome: file was already closed (want it kept open by the new inodeKeeper): %v", err)
	}

	if st.attachCount != attachesBefore+1 {
		t.Errorf("attachCount = %d, want %d (AttachOpenFile must perform a real attach)", st.attachCount, attachesBefore+1)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 1", k)
	}
	if got := tr.containerPid2Inodes[fakePid]; len(got) != 1 || got[0] != 100 {
		t.Errorf("containerPid2Inodes[pid] = %v, want [100]", got)
	}
}

// TestAttachOpenFileOffsetResolverSeesHoldPathTrue pins AttachRequest.HoldPath
// for the ONE call site it exists to mark: a resolver invoked from
// AttachOpenFile (the exec-hold dispatcher's resolve+attach hand-off) must see
// HoldPath == true, so it can choose to pay extra latency (e.g. a real-inode
// lookup) here specifically, without paying it on openTargets'/
// discoverAndOpenMappedLibraries' synchronous, latency-sensitive paths (see
// TestMultiOffsetResolverReceivesProgName for the false case on those).
func TestAttachOpenFileOffsetResolverSeesHoldPathTrue(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 200
	trackPidWithoutAttach(t, tr, st, fakePid)

	elfFile := writeSyntheticELF(t, testBuildID)
	f, err := os.Open(elfFile.Name())
	if err != nil {
		t.Fatalf("opening synthetic ELF candidate: %v", err)
	}

	var got AttachRequest
	tr.SetAttachOffsetsResolver(func(req AttachRequest) ([]uint64, error) {
		got = req
		return nil, errors.New("no offsets: resolver only needs to observe HoldPath here")
	})

	if _, _, err := tr.AttachOpenFile(fakePid, f, "exec-hold candidate"); err != nil {
		t.Fatalf("AttachOpenFile: %v", err)
	}

	if !got.HoldPath {
		t.Error("HoldPath = false, want true: this request came from AttachOpenFile")
	}
}

// 2. The inode is already attached for another pid: AttachOpenFile must NOT
// attach again -- only bump the shared refcount and credit this pid, exactly
// like CreditIfAttached's third-pid case.
func TestAttachOpenFileBumpsExistingInode(t *testing.T) {
	tr, st := newTestTracer(t)
	pidA, pidC := fakePid, fakePid+2
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(pidA)); err != nil {
		t.Fatalf("AttachContainer(A): %v", err)
	}
	trackPidWithoutAttach(t, tr, st, pidC)
	attachesBefore := st.attachCount

	f := attachCandidate(t)
	inode, added, err := tr.AttachOpenFile(pidC, f, "candidate")
	if err != nil {
		t.Fatalf("AttachOpenFile: %v", err)
	}
	if inode != 100 || !added {
		t.Fatalf("AttachOpenFile = (%d, %v), want (100, true)", inode, added)
	}
	assertClosed(t, f, "bumped outcome")

	if st.attachCount != attachesBefore {
		t.Errorf("attachCount = %d, want %d (already-attached inode must not re-attach)", st.attachCount, attachesBefore)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 2 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 2", k)
	}
	if got := tr.containerPid2Inodes[pidC]; len(got) != 1 || got[0] != 100 {
		t.Errorf("containerPid2Inodes[pidC] = %v, want [100]", got)
	}
}

// 3. A repeat call for the SAME pid never re-attaches or double-counts, and
// the file is consumed every time. Per AttachOpenFile's documented contract
// (matching attachOneOpenFile's own "added" semantics, deliberately NOT
// CreditIfAttached's "credited" semantics — see its doc comment on why a
// second pre-check would cost an extra kfilefields round trip), only the
// FIRST call reports added=true; repeat calls report added=false because no
// NEW reference is recorded, even though the inode remains attached
// throughout.
func TestAttachOpenFileIdempotentForSamePid(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	trackPidWithoutAttach(t, tr, st, fakePid)

	var attachesAfterFirst int
	for i := 0; i < 4; i++ {
		f := attachCandidate(t)
		inode, added, err := tr.AttachOpenFile(fakePid, f, "candidate")
		if err != nil {
			t.Fatalf("AttachOpenFile #%d: %v", i, err)
		}
		if inode != 100 {
			t.Fatalf("AttachOpenFile #%d realInodePtr = %d, want 100", i, inode)
		}
		if i == 0 {
			if !added {
				t.Fatalf("AttachOpenFile #0: added = false, want true (fresh attach)")
			}
			// First call: fresh attach, file kept open by the new inodeKeeper.
			if err := f.Close(); err != nil {
				t.Errorf("call #0: file was already closed (want it kept open by the new inodeKeeper): %v", err)
			}
			attachesAfterFirst = st.attachCount
			continue
		}
		if added {
			t.Fatalf("AttachOpenFile #%d: added = true, want false (already credited to this pid)", i)
		}
		// Repeat calls: idempotent no-op (existing[realInodePtr]), so
		// attachOneOpenFile closes the file itself.
		assertClosed(t, f, "repeat attach")
	}

	if st.attachCount != attachesAfterFirst {
		t.Errorf("attachCount = %d, want %d (repeat calls must not re-attach)", st.attachCount, attachesAfterFirst)
	}
	if got := tr.containerPid2Inodes[fakePid]; len(got) != 1 || got[0] != 100 {
		t.Errorf("containerPid2Inodes[pid] = %v, want exactly [100]", got)
	}
}

// 4. An untracked pid: nothing is attached, nothing is credited, and no
// bookkeeping entry is created for it -- matching CreditIfAttached's untracked
// case, since attaching for a pid DetachContainer will never walk would leak.
func TestAttachOpenFileUntrackedPidIsNoOp(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	attachesBefore := st.attachCount

	untracked := fakePid + 7
	f := attachCandidate(t)
	inode, added, err := tr.AttachOpenFile(untracked, f, "candidate")
	if err != nil {
		t.Fatalf("AttachOpenFile: %v", err)
	}
	if inode != 0 {
		t.Errorf("realInodePtr = %d, want 0 (no resolve should even be attributed)", inode)
	}
	if added {
		t.Errorf("added = true for an untracked pid (would leak: DetachContainer never runs for it)")
	}
	assertClosed(t, f, "untracked pid outcome")

	if st.attachCount != attachesBefore {
		t.Errorf("attachCount = %d, want %d (untracked pid must not attach)", st.attachCount, attachesBefore)
	}
	if _, ok := tr.containerPid2Inodes[untracked]; ok {
		t.Errorf("containerPid2Inodes gained an entry for an untracked pid")
	}
}

// 5. The candidate binary does not export the attach symbol: a non-fatal skip
// (attached=false, err=nil), not an error -- matching attachOneOpenFile's own
// "symbol absent" outcome, and no reference is taken.
func TestAttachOpenFileSymbolAbsentIsSkipNotError(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	st.attachErr = errors.New("symbol not found")
	trackPidWithoutAttach(t, tr, st, fakePid)

	f := attachCandidate(t)
	inode, added, err := tr.AttachOpenFile(fakePid, f, "candidate")
	if err != nil {
		t.Fatalf("AttachOpenFile: %v", err)
	}
	if added {
		t.Errorf("added = true, want false (symbol absent)")
	}
	if inode != 100 {
		t.Errorf("realInodePtr = %d, want 100 (still resolved)", inode)
	}
	assertClosed(t, f, "symbol-absent outcome")

	if _, exists := tr.inodeRefCount[100]; exists {
		t.Errorf("inodeRefCount gained an entry despite the symbol being absent")
	}
	if got := tr.containerPid2Inodes[fakePid]; len(got) != 0 {
		t.Errorf("containerPid2Inodes[pid] = %v, want empty (nothing attached)", got)
	}
}

// 6. A failed inode resolve is a distinguishable hard error, and the file is
// still consumed.
func TestAttachOpenFileInodeErrorClosesFile(t *testing.T) {
	tr, st := newTestTracer(t)
	trackPidWithoutAttach(t, tr, st, fakePid)
	st.inodeErr = errors.New("kfilefields round trip failed")

	f := attachCandidate(t)
	_, added, err := tr.AttachOpenFile(fakePid, f, "candidate")
	if err == nil {
		t.Fatalf("AttachOpenFile: want error, got nil")
	}
	if added {
		t.Errorf("added = true despite inode resolve error")
	}
	assertClosed(t, f, "inode-error outcome")
}

// 7. A closed tracer refuses to attach and reports an error, consuming the
// file rather than leaking it.
func TestAttachOpenFileClosedTracerErrors(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	trackPidWithoutAttach(t, tr, st, fakePid)
	tr.closed = true

	f := attachCandidate(t)
	_, added, err := tr.AttachOpenFile(fakePid, f, "candidate")
	if err == nil {
		t.Fatalf("AttachOpenFile: want error on closed tracer, got nil")
	}
	if added {
		t.Errorf("added = true on a closed tracer")
	}
	assertClosed(t, f, "closed-tracer outcome")
}
