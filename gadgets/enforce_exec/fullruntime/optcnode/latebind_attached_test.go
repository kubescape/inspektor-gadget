// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package optcnode

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/optcengine"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/parity"
)

// TestG004OptcLateBind (reviews C4, N1, R3-C1): the root anchor is captured
// only from a binding whose init Bind PROVED to be the runtime's init,
// blocked on this container's exec.fifo (initProof), at the init's first
// exec since Bind, before the bind deadline, from an image outside its own
// mount namespace; a binding without an anchor is never Ready.
//
//	IG_G004_OPTC_PARITY=1
func TestG004OptcLateBind(t *testing.T) {
	if os.Getenv("IG_G004_OPTC_PARITY") == "" || os.Geteuid() != 0 {
		t.Skip("set IG_G004_OPTC_PARITY=1, as root, on an isolated VM")
	}
	root := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ig15-g004-latebind-%d", os.Getpid()))
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	// Not /run: it is noexec on Ubuntu.
	fake := "/var/tmp/g004l/root"
	if err := os.MkdirAll(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll("/var/tmp/g004l") })
	for name, data := range map[string][]byte{"waitexec": parity.WaitExecELF(), "target": parity.OkELF(), "../chrootexec": parity.ChrootExecELF()} {
		if err := os.WriteFile(filepath.Join(fake, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	chrootBin, err := exec.LookPath("chroot")
	if err != nil {
		t.Fatal(err)
	}
	rt := newFakeRuntime(t)
	runtimeBin, err := os.ReadFile(rt.bin)
	if err != nil {
		t.Fatal(err)
	}
	// Strict, default deny: the fake root's paths as they read inside it.
	policy := fullpolicy.Policy{ID: "g004-late", Revision: "1", Mode: fullpolicy.Enforce, RootRole: "app", Default: fullpolicy.Deny,
		Rules: []fullpolicy.Rule{{Name: "spoofable", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{
			"/target", "/waitexec", chrootBin, "/usr/sbin/chroot", "/sbin/chroot", "/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/dash", "/usr/bin/dash"}}}}}
	audit := policy
	audit.Mode, audit.Default = fullpolicy.Audit, fullpolicy.Allow
	// probeWith is the host probe with the R3-C1 proof of rt, edited (the
	// mutant knobs), or a bypass when edit is nil and bypass is set.
	probeWith := func(t *testing.T, bypass bool, edit func(*initProof)) *Probe {
		t.Helper()
		p := hostProbe()
		if bypass {
			p.InitImage = func(uint32, string) error { return nil } // test knob: no Bind proof
			return p
		}
		proof, err := newInitProof(rt.config())
		if err != nil {
			t.Fatal(err)
		}
		if edit != nil {
			edit(proof)
		}
		p.InitImage = proof.prove
		return p
	}
	start := func(t *testing.T, cfg Config) *Node {
		t.Helper()
		cfg.Admission = DefaultAdmission()
		cfg.Runtime = rt.config()
		n, err := StartNode(context.Background(), cfg)
		if err != nil {
			t.Fatalf("StartNode: %v", err)
		}
		t.Cleanup(func() { _ = n.StopNode(context.Background()) })
		return n
	}
	cgroup := func(t *testing.T, name string) (string, uint64) {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(dir) })
		var st unix.Stat_t
		if err := unix.Stat(dir, &st); err != nil {
			t.Fatal(err)
		}
		return dir, st.Ino
	}
	bind := func(n *Node, ino uint64, pid int, id string) (*BindingSession, error) {
		return n.Bind(context.Background(), fullruntime.SharedBindingConfig{CgroupID: ino, InitHostPID: uint32(pid), ContainerID: id})
	}
	exitCode := func(t *testing.T, cmd *exec.Cmd) int {
		t.Helper()
		err := cmd.Wait()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return 0
	}
	waitExe := func(t *testing.T, pid int, base string) {
		t.Helper()
		for i := 0; i < 500; i++ {
			if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && filepath.Base(exe) == base {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("pid %d never ran %s", pid, base)
	}

	// execBeforePublish (C4): the runtime init, proven at Bind, is released
	// BEFORE the first Publish: it execs chroot (exec 1), which execs
	// /waitexec in the fake root (exec 2); after Publish a byte makes it
	// exec /target (exec 3).
	execBeforePublish := func(t *testing.T, n *Node, name string) (fullruntime.SharedBindingStatus, uint64, int) {
		dir, ino := cgroup(t, name)
		fifo := rt.fifo(t, name)
		cmd := rt.command(t, dir, fifo, runtimeBin, chrootBin, fake, "/waitexec", "/target")
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
		waitBlocked(t, cmd.Process.Pid)
		s, err := bind(n, ino, cmd.Process.Pid, name)
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		if err := release(fifo); err != nil {
			t.Fatal(err)
		}
		waitExe(t, cmd.Process.Pid, "waitexec")
		if _, err := s.Publish(context.Background(), fullruntime.SharedBindingPolicy{Source: &policy, Container: "late"}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if _, err := io.WriteString(in, "x"); err != nil {
			t.Fatal(err)
		}
		code := exitCode(t, cmd)
		refused, _ := n.eng.Raw(optcengine.CAnchorRefused)
		return s.Inspect(), refused, code
	}
	// workloadInit (N1, R3-C1): an init that already runs workload code
	// before Bind: image (fromMemfd: a memfd copy of chrootexec, exec'd
	// from the memfd with no capability; else chrootexec from the init's
	// own mounts, exec'd by a memfd shell). It prints "ready" and waits;
	// after Bind and Publish a byte makes it chroot(2) into the fake root
	// and execve("/target") once.
	workloadInit := func(t *testing.T, name string, fromMemfd bool) (*exec.Cmd, io.WriteCloser, uint64) {
		dir, ino := cgroup(t, name)
		rt.fifo(t, name) // the container's fifo exists; the workload holds no fd to it
		f, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		var cmd *exec.Cmd
		if fromMemfd {
			img := memfdBytes(t, parity.ChrootExecELF())
			cmd = exec.Command(fmt.Sprintf("/proc/self/fd/%d", img.Fd()), fake, "/target")
		} else {
			img := memfdImage(t, "/usr/bin/bash")
			cmd = exec.Command(fmt.Sprintf("/proc/self/fd/%d", img.Fd()), "-c", `exec "$1" "$2" /target`, "ig15-g004-n1-init", filepath.Dir(fake)+"/chrootexec", fake)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(f.Fd())}
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
		if l, err := bufio.NewReader(out).ReadString('\n'); err != nil || l != "ready\n" {
			t.Fatalf("workload init: %q %v", l, err)
		}
		return cmd, in, ino
	}
	// chrootAndExec: after Bind succeeded, Publish, then chroot(2) and
	// execve("/target"); the status and /target's exit code.
	chrootAndExec := func(t *testing.T, n *Node, s *BindingSession, cmd *exec.Cmd, in io.WriteCloser) (fullruntime.SharedBindingStatus, int) {
		if _, err := s.Publish(context.Background(), fullruntime.SharedBindingPolicy{Source: &policy, Container: "late"}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if _, err := io.WriteString(in, "x"); err != nil {
			t.Fatal(err)
		}
		code := exitCode(t, cmd)
		return s.Inspect(), code
	}

	t.Run("Control_RuntimeInitBlockedOnFifo", func(t *testing.T) {
		// R3 (3): the proof holds, the init's exec anchors: Ready.
		n := start(t, Config{})
		dir, ino := cgroup(t, "control")
		p := startHeldPipeInit(t, rt, dir, "control")
		s, err := bind(n, ino, p.cmd.Process.Pid, "control")
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		if _, err := s.Publish(context.Background(), fullruntime.SharedBindingPolicy{Source: &audit, Container: "late"}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if st := s.Inspect(); st.Ready {
			t.Errorf("Ready before the init's exec (no anchor yet): %+v", st)
		}
		if err := p.release(); err != nil {
			t.Fatalf("init after its exec: %v", err)
		}
		if st := s.Inspect(); !st.RootAuthorized || !st.Ready {
			t.Errorf("proven runtime init: %+v, want anchored and Ready", st)
		}
	})
	t.Run("DeadlinePassed", func(t *testing.T) {
		n := start(t, Config{BindDeadline: time.Second})
		dir, ino := cgroup(t, "deadline")
		p := startHeldPipeInit(t, rt, dir, "deadline")
		s, err := bind(n, ino, p.cmd.Process.Pid, "deadline")
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		if _, err := s.Publish(context.Background(), fullruntime.SharedBindingPolicy{Source: &audit, Container: "late"}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		time.Sleep(1500 * time.Millisecond)
		if err := p.release(); err != nil {
			t.Fatalf("init after its exec (audit): %v", err)
		}
		if st := s.Inspect(); st.RootAuthorized || st.Ready {
			t.Errorf("anchored after the deadline: %+v", st)
		}
	})
	t.Run("ExecBeforePublish", func(t *testing.T) {
		n := start(t, Config{})
		st, refused, code := execBeforePublish(t, n, "exec-before-publish")
		t.Logf("status %+v, anchor refused %d, final exec exit %d", st, refused, code)
		if st.RootAuthorized || st.Ready || refused == 0 {
			t.Errorf("an init that exec'd after Bind and before Publish anchored, or no refusal counted: %+v (%d)", st, refused)
		}
		if code != int(unix.EPERM) {
			t.Errorf("the exec from the fake root: exit %d, want EPERM (path UNKNOWN)", code)
		}
	})
	t.Run("MemfdLateBind_RefusedAtBind", func(t *testing.T) {
		// R3 (1): workload code exec'd from a memfd before Bind (no
		// capability needed): outside its mount namespace, but not blocked
		// on the container's exec.fifo, and not the runtime binary.
		n := start(t, Config{})
		cmd, _, ino := workloadInit(t, "memfd-bind", true)
		if _, err := bind(n, ino, cmd.Process.Pid, "memfd-bind"); !errors.Is(err, ErrInitStarted) {
			t.Fatalf("Bind of a memfd workload init: %v, want ErrInitStarted", err)
		}
	})
	t.Run("KnownGapProbe_MemfdLateBindWithoutTheBindProof", func(t *testing.T) {
		// R3 (2): the same with the Bind proof bypassed (test knob). The
		// kernel layer cannot catch it: the init's pre-exec image is a
		// memfd (an internal mount, outside its namespace, like runc's
		// clone) and this is its first exec since Bind. The fake root
		// anchors: the Bind proof is the closure. This probe shows the
		// kernel check alone is insufficient; it asserts the gap.
		n := start(t, Config{Probe: probeWith(t, true, nil)})
		cmd, in, ino := workloadInit(t, "memfd-kernel", true)
		s, err := bind(n, ino, cmd.Process.Pid, "memfd-kernel")
		if err != nil {
			t.Fatalf("Bind (proof bypassed): %v", err)
		}
		st, code := chrootAndExec(t, n, s, cmd, in)
		t.Logf("KNOWN GAP without the Bind proof: status %+v, /target exit %d", st, code)
		if !st.RootAuthorized || code != 0 {
			t.Errorf("the kernel layer alone now refuses the memfd late bind (%+v, exit %d): update the report", st, code)
		}
	})
	t.Run("PreBindExec_RefusedAtBind", func(t *testing.T) {
		// N1: a pre-Bind exec of a file of the init's own mounts.
		n := start(t, Config{})
		cmd, _, ino := workloadInit(t, "n1-bind", false)
		if _, err := bind(n, ino, cmd.Process.Pid, "n1-bind"); !errors.Is(err, ErrInitStarted) {
			t.Fatalf("Bind of an init running its workload: %v, want ErrInitStarted", err)
		}
	})
	t.Run("PreBindExec_KernelRefusesTheAnchor", func(t *testing.T) {
		// N1, the kernel layer alone (Bind proof bypassed): the pre-exec
		// image is on the init's own mount namespace.
		n := start(t, Config{Probe: probeWith(t, true, nil)})
		cmd, in, ino := workloadInit(t, "n1-kernel", false)
		s, err := bind(n, ino, cmd.Process.Pid, "n1-kernel")
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		st, code := chrootAndExec(t, n, s, cmd, in)
		inWorkload, _ := n.eng.Raw(optcengine.CInitInWorkload)
		t.Logf("status %+v, init-in-workload %d, /target exit %d", st, inWorkload, code)
		if st.RootAuthorized || st.Ready || inWorkload == 0 || code != int(unix.EPERM) {
			t.Errorf("an init that ran its workload from its own mounts anchored: %+v (%d), exit %d", st, inWorkload, code)
		}
	})
	t.Run("Mutant38Caught", func(t *testing.T) {
		probe := probeWith(t, true, nil)
		probe.Load = func(o optcengine.Options) (*optcengine.Engine, error) {
			o.Product, o.Mutant = false, optcengine.MutantExeAnyMount
			return optcengine.Load(o)
		}
		n := start(t, Config{Probe: probe})
		cmd, in, ino := workloadInit(t, "n1-mutant", false)
		s, err := bind(n, ino, cmd.Process.Pid, "n1-mutant")
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		if st, code := chrootAndExec(t, n, s, cmd, in); !st.RootAuthorized || code != 0 {
			t.Fatalf("mutant 38 not caught: %+v exit %d", st, code)
		}
	})
	t.Run("Mutant36Caught", func(t *testing.T) {
		probe := probeWith(t, false, nil)
		probe.Load = func(o optcengine.Options) (*optcengine.Engine, error) {
			o.Product, o.Mutant = false, optcengine.MutantLateAnchor
			return optcengine.Load(o)
		}
		n := start(t, Config{Probe: probe})
		if st, _, code := execBeforePublish(t, n, "mutant36"); !st.RootAuthorized || code != 0 {
			t.Fatalf("mutant 36 not caught: %+v exit %d", st, code)
		}
	})
	// The R3-C1 proof's mutants: an init that passes every part of the
	// proof but one; the real proof refuses it, the mutant accepts it.
	proofMutant := func(t *testing.T, name string, image []byte, ownFifo bool, edit func(*initProof)) {
		dir, ino := cgroup(t, name)
		fifo := rt.fifo(t, name)
		if !ownFifo {
			// A fifo of the workload's own, not the container's.
			fifo = filepath.Join(filepath.Dir(rt.root), name+"-own.fifo")
			if err := unix.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cmd := rt.command(t, dir, fifo, image, "/usr/bin/true")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		waitBlocked(t, cmd.Process.Pid)
		real := start(t, Config{Probe: probeWith(t, false, nil)})
		if _, err := bind(real, ino, cmd.Process.Pid, name); !errors.Is(err, ErrInitStarted) {
			t.Fatalf("real proof: %v, want ErrInitStarted", err)
		}
		mut := start(t, Config{Probe: probeWith(t, false, edit)})
		if _, err := bind(mut, ino, cmd.Process.Pid, name); err != nil {
			t.Fatalf("mutant not caught: the mutated proof refused too: %v", err)
		}
	}
	t.Run("FifoCheckMutantCaught", func(t *testing.T) {
		// The runtime binary (hash matches), blocked on a fifo of its own.
		proofMutant(t, "fifo-mutant", runtimeBin, false, func(p *initProof) { p.skipFifo = true })
	})
	t.Run("HashCheckMutantCaught", func(t *testing.T) {
		// Blocked on the container's fifo, but not the runtime binary (same
		// behaviour, other bytes).
		proofMutant(t, "hash-mutant", parity.FifoInitELF(64), true, func(p *initProof) { p.skipHash = true })
	})
}
