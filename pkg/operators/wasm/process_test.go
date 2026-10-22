// Copyright 2024 The Inspektor Gadget authors
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

package wasm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	api "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/processlaunch"
)

func TestProcessStartTicks(t *testing.T) {
	fields := append([]string{"S"}, strings.Fields(strings.Repeat("0 ", 18))...)
	fields = append(fields, "12345")
	valid := "42 (a tricky ) process) " + strings.Join(fields, " ")
	if got, err := processStartTicks(valid, 42); err != nil || got != 12345 {
		t.Fatalf("got %d, %v", got, err)
	}
	for _, bad := range []string{"", "42 (short) S 0", "43 (wrong) " + strings.Join(fields, " "), strings.Replace(valid, "12345", "bad", 1)} {
		if _, err := processStartTicks(bad, 42); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestValidateProcessIdentity(t *testing.T) {
	node, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NODE_NAME", node)
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := uint32(cmd.Process.Pid)
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := processStartTicks(string(stat), pid)
	if err != nil {
		t.Fatal(err)
	}
	bootID := strings.TrimSpace(string(boot))
	called := false
	var ownedFD int
	bind := func(fd int) error { called = true; ownedFD = fd; return nil }
	if err := validateProcessIdentity("/proc", node, bootID, pid, ticks, bind); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("binding not invoked")
	}
	if _, err := unix.FcntlInt(uintptr(ownedFD), unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatalf("pidfd not closed: %v", err)
	}
	tests := []struct {
		node, boot string
		pid        uint32
		ticks      uint64
	}{
		{"wrong", bootID, pid, ticks},
		{node, "wrong", pid, ticks},
		{node, bootID, pid, ticks + 1},
		{node, bootID, 0, ticks},
	}
	for n, tt := range tests {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			err := validateProcessIdentity("/proc", tt.node, tt.boot, tt.pid, tt.ticks, func(int) error { t.Fatal("invalid identity reached binding"); return nil })
			if err == nil {
				t.Fatal("accepted invalid identity")
			}
		})
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if err := validateProcessIdentity("/proc", node, bootID, pid, ticks, bind); err == nil {
		t.Fatal("accepted exited process")
	}
}

func TestProcessExitWatcher(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "process_lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	for name, kind := range map[string]api.Kind{"event_type": api.Kind_String, "host_pid": api.Kind_Uint32, "start_time_ticks": api.Kind_Uint64} {
		if _, err := ds.AddField(name, kind); err != nil {
			t.Fatal(err)
		}
	}
	events := make(chan string, 1)
	if err := ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
		event, err := ds.GetField("event_type").String(data)
		events <- event
		return err
	}, 0); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	i := &wasmOperatorInstance{ctx: ctx, logger: log.New(), processLifecycleReady: make(chan struct{})}
	i.processWatchWG.Add(1)
	go i.watchProcess(fd, ds, uint32(cmd.Process.Pid), 123)
	t.Cleanup(func() { cancel(); i.processWatchWG.Wait() })
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	select {
	case <-events:
		t.Fatal("reported exit before gadgetStart completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(i.processLifecycleReady)
	select {
	case event := <-events:
		if event != "EXITED" {
			t.Fatal(event)
		}
	case <-time.After(time.Second):
		t.Fatal("exit not reported")
	}
	i.processWatchWG.Wait()
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatalf("watcher FD leaked: %v", err)
	}
}

func TestProcessWatcherCancellationBeforeStart(t *testing.T) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	i := &wasmOperatorInstance{ctx: ctx, processLifecycleReady: make(chan struct{})}
	i.processWatchWG.Add(1)
	go i.watchProcess(fd, nil, uint32(os.Getpid()), 1)
	cancel()
	done := make(chan struct{})
	go func() { i.processWatchWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatalf("cancelled watcher FD leaked: %v", err)
	}
}

func TestProcessBindingPreservesStops(t *testing.T) {
	node, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NODE_NAME", node)
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := uint32(cmd.Process.Pid)
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := processStartTicks(string(stat), pid)
	if err != nil {
		t.Fatal(err)
	}
	fail := errors.New("binding failed")
	callback := func(int) error {
		states, err := processThreadStates("/proc", pid)
		if err != nil {
			t.Fatal(err)
		}
		for _, state := range states {
			if state != "t" {
				return fmt.Errorf("binding running thread: %s", state)
			}
		}
		return fail
	}
	// A failed binding must resume a process that was initially running.
	err = validateProcessIdentity("/proc", node, strings.TrimSpace(string(boot)), pid, ticks, callback)
	if !errors.Is(err, fail) {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		states, err := processThreadStates("/proc", pid)
		if err != nil {
			t.Fatal(err)
		}
		if states[0] != "T" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed binding left process stopped")
		}
		time.Sleep(time.Millisecond)
	}
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, unix.SIGSTOP, nil, 0); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for {
		states, err := processThreadStates("/proc", pid)
		if err != nil {
			t.Fatal(err)
		}
		if states[0] == "T" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stop not observed")
		}
		time.Sleep(time.Millisecond)
	}
	// A preexisting stop is retained, including after failed binding.
	err = validateProcessIdentity("/proc", node, strings.TrimSpace(string(boot)), pid, ticks, callback)
	if !errors.Is(err, fail) {
		t.Fatal(err)
	}
	states, err := processThreadStates("/proc", pid)
	if err != nil {
		t.Fatal(err)
	}
	if states[0] != "T" {
		t.Fatal("preexisting stop was resumed")
	}
}

func TestProcessBindingRejectsSelf(t *testing.T) {
	if err := validateProcessIdentity("/proc", "node", "boot", uint32(os.Getpid()), 1, func(int) error {
		t.Fatal("self binding reached callback")
		return nil
	}); err == nil {
		t.Fatal("self binding accepted")
	}
}

func TestProcessTraceStopRejectsExternalResume(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := uint32(cmd.Process.Pid)
	err := withProcessQuiesced("/proc", pid, func() error {
		if err := exec.Command("kill", "-CONT", fmt.Sprint(pid)).Run(); err != nil {
			return err
		}
		// Give SIGCONT time to run: an ordinary job-control stop would resume.
		time.Sleep(20 * time.Millisecond)
		states, err := processThreadStates("/proc", pid)
		if err != nil {
			return err
		}
		for _, state := range states {
			if state != "t" {
				return fmt.Errorf("external SIGCONT resumed thread: %s", state)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProcessPartialSeizeFailureDetaches(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := uint32(cmd.Process.Pid)
	root := t.TempDir()
	for _, tid := range []string{fmt.Sprint(pid), "999999999"} {
		dir := filepath.Join(root, fmt.Sprint(pid), "task", tid)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(tid+" (sleep) S"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := withProcessQuiesced(root, pid, func() error { return fmt.Errorf("unexpected binding") }); err == nil {
		t.Fatal("missing thread accepted")
	}
	deadline := time.Now().Add(time.Second)
	for {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			t.Fatal(err)
		}
		states, err := processThreadStates("/proc", pid)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(status), "TracerPid:\t0\n") && states[0] != "t" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed activation left a tracee stopped or attached")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSignalForDetach(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status unix.WaitStatus
		want   unix.Signal
	}{
		{"SIGTERM", unix.WaitStatus(int(unix.SIGTERM)<<8 | 0x7f), unix.SIGTERM},
		{"real SIGTRAP", unix.WaitStatus(int(unix.SIGTRAP)<<8 | 0x7f), unix.SIGTRAP},
		{"interrupt stop", unix.WaitStatus(unix.PTRACE_EVENT_STOP<<16 | int(unix.SIGTRAP)<<8 | 0x7f), 0},
		{"group stop event", unix.WaitStatus(unix.PTRACE_EVENT_STOP<<16 | int(unix.SIGSTOP)<<8 | 0x7f), 0},
		{"exited", 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := signalForDetach(tt.status); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// An unavailable proc root proves the controlled launch path bypasses process
// discovery and ptrace. The pidfd comes from the parent that owns the barrier.
func TestBindLaunchedProcessWithoutPtrace(t *testing.T) {
	child, err := processlaunch.Start(context.Background(), []string{"/bin/true"}, processlaunch.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	id := child.Identity()
	called := false
	err = bindProcessIdentity(child.Context(context.Background()), "/proc-not-used-for-launch", id.Node, id.BootID, id.PID, id.StartTimeTicks, func(fd int) error {
		called = true
		_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("binding callback was not called")
	}
	if err := child.Release(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchCapabilityRejectsDifferentPolicyIdentity(t *testing.T) {
	child, err := processlaunch.Start(context.Background(), []string{"/bin/true"}, processlaunch.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	id := child.Identity()
	err = bindProcessIdentity(child.Context(context.Background()), "/proc-not-used-for-launch", id.Node, id.BootID, id.PID, id.StartTimeTicks+1, func(int) error {
		t.Fatal("wrong identity reached binding callback")
		return nil
	})
	if err == nil {
		t.Fatal("accepted different process identity")
	}
	if err := child.Release(); err == nil {
		t.Fatal("released unbound process")
	}
}
