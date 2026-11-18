// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package parity

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

func TestOkELFRuns(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ok")
	if err := os.WriteFile(p, okELF(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(p).Run(); err != nil {
		t.Fatalf("ok ELF: %v", err)
	}
}

func TestScenariosCompile(t *testing.T) {
	for _, sc := range Scenarios() {
		for _, m := range Modes {
			ps := sc.Policies(m)
			for _, p := range ps {
				if _, err := fullpolicy.CompileKernelWithRoleEpochs([]fullpolicy.Policy{p}, 1, Container, nil); err != nil {
					t.Errorf("%s/%s: %v", sc.Name, m, err)
				}
			}
			for _, s := range sc.Steps {
				if s.Publish >= len(ps) {
					t.Errorf("%s: step %s publishes revision %d of %d", sc.Name, s.Label, s.Publish, len(ps))
				}
			}
		}
	}
}

func TestWaitExecELF(t *testing.T) {
	dir := t.TempDir()
	w, ok := filepath.Join(dir, "waitexec"), filepath.Join(dir, "ok")
	if err := os.WriteFile(w, WaitExecELF(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ok, okELF(), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(w, ok)
	cmd.Stdin = strings.NewReader("x")
	if err := cmd.Run(); err != nil {
		t.Fatalf("waitexec ok: %v", err)
	}
	cmd = exec.Command(w, filepath.Join(dir, "missing"))
	cmd.Stdin = strings.NewReader("x")
	var ee *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Fatalf("waitexec missing: %v, want exit 2 (ENOENT)", err)
	}
}

func TestChrootExecELFWithoutChroot(t *testing.T) {
	// Unprivileged, chroot fails (EPERM) and the exec of the absolute path
	// in the unchanged root runs; as root, the chroot succeeds and the path
	// is not there (ENOENT). Either way the control flow is checked.
	dir := t.TempDir()
	w, ok := filepath.Join(dir, "chrootexec"), filepath.Join(dir, "ok")
	if err := os.WriteFile(w, ChrootExecELF(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ok, okELF(), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(w, dir, ok)
	cmd.Stdin = strings.NewReader("x")
	out, err := cmd.Output()
	if string(out) != "ready\n" {
		t.Fatalf("chrootexec output %q", out)
	}
	var ee *exec.ExitError
	switch {
	case os.Geteuid() == 0 && (!errors.As(err, &ee) || ee.ExitCode() != 2):
		// Root: the chroot succeeds; ok's absolute path is gone there.
		t.Fatalf("chrootexec as root: %v, want exit 2 (ENOENT)", err)
	case os.Geteuid() != 0 && err != nil:
		t.Fatalf("chrootexec: %v", err)
	}
}

func TestFifoInitELF(t *testing.T) {
	dir := t.TempDir()
	fifo, init, ok := filepath.Join(dir, "exec.fifo"), filepath.Join(dir, "init"), filepath.Join(dir, "ok")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(init, FifoInitELF(0), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ok, okELF(), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(init, fifo, ok)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Blocked in open(2) on the fifo, holding an O_PATH fd to it.
	var st, ft unix.Stat_t
	if err := unix.Stat(fifo, &ft); err != nil {
		t.Fatal(err)
	}
	found, blocked := false, false
	for i := 0; i < 200 && !(found && blocked); i++ {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/syscall", cmd.Process.Pid))
		blocked = strings.HasPrefix(string(b), "2 ")
		ents, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", cmd.Process.Pid))
		for _, e := range ents {
			if unix.Stat(fmt.Sprintf("/proc/%d/fd/%s", cmd.Process.Pid, e.Name()), &st) == nil && st.Dev == ft.Dev && st.Ino == ft.Ino {
				found = true
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !found || !blocked {
		_ = cmd.Process.Kill()
		t.Fatalf("fifo init: fd found %v, blocked in open %v", found, blocked)
	}
	r, err := os.OpenFile(fifo, os.O_RDONLY, 0) // release
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("fifo init after release: %v", err)
	}
}
