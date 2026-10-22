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
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	api "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/processlaunch"
)

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

// The pidfd comes from the parent that owns the launch barrier.
func TestBindLaunchedProcess(t *testing.T) {
	child, err := processlaunch.Start(context.Background(), []string{"/bin/true"}, processlaunch.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	id := child.Identity()
	called := false
	err = bindProcessIdentity(child.Context(context.Background()), id.Node, id.BootID, id.PID, id.StartTimeTicks, func(fd int) error {
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
	err = bindProcessIdentity(child.Context(context.Background()), id.Node, id.BootID, id.PID, id.StartTimeTicks+1, func(int) error {
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

func TestProcessBindingRequiresLauncherCapability(t *testing.T) {
	child, err := processlaunch.Start(context.Background(), []string{"/bin/true"}, processlaunch.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	id := child.Identity()
	called := false
	err = bindProcessIdentity(context.Background(), id.Node, id.BootID, id.PID, id.StartTimeTicks, func(int) error { called = true; return nil })
	if err == nil || called || !strings.Contains(err.Error(), "requires an IG-controlled launch") {
		t.Fatalf("binding without launcher capability: error=%v callback=%v", err, called)
	}
}
