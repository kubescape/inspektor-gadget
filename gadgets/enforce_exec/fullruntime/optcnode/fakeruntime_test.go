// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package optcnode

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/parity"
)

// fakeRuntime (review R3-C1) is a container runtime as the init proof sees
// one: a state root (<root>/<id>/exec.fifo) and a runtime binary
// (parity.FifoInitELF) whose init holds the fifo O_PATH and blocks opening
// it until the "runtime" (the test) releases it, then execs the entrypoint.
// The init runs from a memfd copy of the binary, as runc's cloned init does.
type fakeRuntime struct{ root, bin string }

func newFakeRuntime(t *testing.T) *fakeRuntime {
	t.Helper()
	// Not /run (noexec on Ubuntu) and not t.TempDir (it may be noexec).
	root := fmt.Sprintf("/var/tmp/g004rt-%d-%d", os.Getpid(), time.Now().UnixNano())
	if err := os.MkdirAll(filepath.Join(root, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	bin := filepath.Join(root, "fifoinit")
	if err := os.WriteFile(bin, parity.FifoInitELF(0), 0o755); err != nil {
		t.Fatal(err)
	}
	return &fakeRuntime{root: filepath.Join(root, "state"), bin: bin}
}

func (r *fakeRuntime) config() RuntimeConfig {
	return RuntimeConfig{StateRoot: r.root, Binaries: []string{r.bin}}
}

func (r *fakeRuntime) fifo(t *testing.T, id string) string {
	t.Helper()
	p := filepath.Join(r.root, id, "exec.fifo")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(p, 0o600); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	return p
}

// command is the runtime-like init of container id in cgroup: image (a
// memfd copy of it) blocked on fifo, then execs entry. Not started.
func (r *fakeRuntime) command(t *testing.T, cgroup, fifo string, image []byte, entry ...string) *exec.Cmd {
	t.Helper()
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	img := memfdBytes(t, image)
	cmd := exec.Command(fmt.Sprintf("/proc/self/fd/%d", img.Fd()), append([]string{fifo}, entry...)...)
	cmd.Args[0] = "ig15-g004-runtime-init"
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	cmd.Stderr = os.Stderr
	return cmd
}

// waitBlocked waits until pid blocks in open(2) on the fifo (holding it).
func waitBlocked(t *testing.T, pid int) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/syscall", pid)); err == nil && strings.HasPrefix(string(b), fmt.Sprintf("%d ", unix.SYS_OPEN)) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("init %d never blocked on its exec.fifo", pid)
}

// release opens the fifo for reading: the init's blocked open returns and
// it execs its entrypoint (runc start).
func release(fifo string) error {
	f, err := os.OpenFile(fifo, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

func memfdBytes(t *testing.T, b []byte) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("ig15-g004-image", 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "memfd")
	t.Cleanup(func() { f.Close() })
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	return f
}
