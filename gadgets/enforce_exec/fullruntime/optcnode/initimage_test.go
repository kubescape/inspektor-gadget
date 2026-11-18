// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package optcnode

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/parity"
)

// memfdImage copies path into a memfd and returns it: a process exec'd
// from /proc/self/fd/<fd> runs an image on no mount of its namespace (as a
// runtime's sealed init clone does).
func memfdImage(t *testing.T, path string) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("ig15-g004-runtime-init", 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "memfd")
	t.Cleanup(func() { f.Close() })
	src, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := io.Copy(f, src); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestInitRunsRuntimeImage(t *testing.T) {
	// This test binary runs from a mount of its own namespace: refused.
	if err := initRunsRuntimeImage(uint32(os.Getpid())); !errors.Is(err, ErrInitStarted) {
		t.Fatalf("own process: %v, want ErrInitStarted", err)
	}
	// A process exec'd from a memfd: accepted.
	img := memfdImage(t, "/bin/sleep")
	cmd := exec.Command(fmt.Sprintf("/proc/self/fd/%d", img.Fd()), "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	// Start returns once the child exec'd the memfd image.
	if err := initRunsRuntimeImage(uint32(cmd.Process.Pid)); err != nil {
		t.Fatalf("memfd image: %v, want accepted", err)
	}
}

// TestInitProofOnHost (review R3-C1) checks the Bind proof against
// unprivileged processes: a runtime-like init blocked on its container's
// exec.fifo is proven; a memfd workload, a runtime binary blocked on another
// fifo, and another binary blocked on the right fifo are refused, and each
// refusal is the one its mutant knob removes.
func TestInitProofOnHost(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "state")
	bin := filepath.Join(dir, "fifoinit")
	if err := os.WriteFile(bin, parity.FifoInitELF(0), 0o755); err != nil {
		t.Fatal(err)
	}
	mkfifo := func(p string) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	startInit := func(image []byte, fifo string) int {
		img := memfdBytes(t, image)
		cmd := exec.Command(fmt.Sprintf("/proc/self/fd/%d", img.Fd()), fifo, "/bin/true")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		waitBlocked(t, cmd.Process.Pid)
		return cmd.Process.Pid
	}
	proof := func(edit func(*initProof)) *initProof {
		p, err := newInitProof(RuntimeConfig{StateRoot: root, Binaries: []string{bin}})
		if err != nil {
			t.Fatal(err)
		}
		if edit != nil {
			edit(p)
		}
		return p
	}
	runtimeBin, _ := os.ReadFile(bin)
	good := startInit(runtimeBin, mkfifo(filepath.Join(root, "good", "exec.fifo")))
	if err := proof(nil).prove(uint32(good), "good"); err != nil {
		t.Fatalf("runtime init blocked on its fifo: %v", err)
	}
	if err := proof(nil).prove(uint32(good), "other"); !errors.Is(err, ErrInitStarted) {
		t.Fatalf("another container's id: %v, want ErrInitStarted", err)
	}
	mkfifo(filepath.Join(root, "wrongfifo", "exec.fifo"))
	wrongFifo := startInit(runtimeBin, mkfifo(filepath.Join(dir, "own.fifo")))
	if err := proof(nil).prove(uint32(wrongFifo), "wrongfifo"); !errors.Is(err, ErrInitStarted) {
		t.Fatalf("runtime binary on its own fifo: %v, want ErrInitStarted", err)
	}
	if err := proof(func(p *initProof) { p.skipFifo = true }).prove(uint32(wrongFifo), "wrongfifo"); err != nil {
		t.Fatalf("fifo mutant should accept it: %v", err)
	}
	wrongHash := startInit(parity.FifoInitELF(64), mkfifo(filepath.Join(root, "wronghash", "exec.fifo")))
	if err := proof(nil).prove(uint32(wrongHash), "wronghash"); !errors.Is(err, ErrInitStarted) {
		t.Fatalf("other binary on the right fifo: %v, want ErrInitStarted", err)
	}
	if err := proof(func(p *initProof) { p.skipHash = true }).prove(uint32(wrongHash), "wronghash"); err != nil {
		t.Fatalf("hash mutant should accept it: %v", err)
	}
	if err := proof(nil).prove(uint32(os.Getpid()), "good"); !errors.Is(err, ErrInitStarted) {
		t.Fatalf("this process: %v, want ErrInitStarted", err)
	}
}
