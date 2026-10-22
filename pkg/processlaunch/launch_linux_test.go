// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package processlaunch

import (
	"bytes"
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

	"golang.org/x/sys/unix"
)

func startTest(t *testing.T, ctx context.Context) (*Child, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "executed")
	c, err := Start(ctx, []string{"/bin/sh", "-c", `printf '%s' "$$" > "$1"`, "test", file}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, file
}

func installTest(t *testing.T, c *Child) {
	t.Helper()
	err := Bind(c.Context(context.Background()), c.Identity(), func(fd int) error {
		return unix.PidfdSendSignal(fd, 0, nil, 0)
	})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
}

func TestReleaseRequiresBinding(t *testing.T) {
	c, file := startTest(t, context.Background())
	if err := c.Release(); err == nil {
		t.Fatal("release without binding succeeded")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("application started before binding: %v", err)
	}
	installTest(t, c)
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("application started before release: %v", err)
	}
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != fmt.Sprint(c.Identity().PID) {
		t.Fatalf("exec changed PID: got %s want %d", data, c.Identity().PID)
	}
	if err := c.Release(); err == nil {
		t.Fatal("second release succeeded")
	}
}

func TestBindingCapabilityAndIdentity(t *testing.T) {
	c, _ := startTest(t, context.Background())
	calls := 0
	callback := func(int) error { calls++; return nil }
	err := Bind(context.Background(), c.Identity(), callback)
	if err == nil || calls != 0 {
		t.Fatal("plain context authorized binding")
	}
	for _, field := range []string{"node", "boot", "pid", "ticks"} {
		id := c.Identity()
		switch field {
		case "node":
			id.Node += "other"
		case "boot":
			id.BootID += "other"
		case "pid":
			id.PID++
		case "ticks":
			id.StartTimeTicks++
		}
		err = Bind(c.Context(context.Background()), id, callback)
		if err == nil || calls != 0 {
			t.Fatalf("%s mismatch accepted", field)
		}
	}
	installTest(t, c)
	err = Bind(c.Context(context.Background()), c.Identity(), callback)
	if err == nil || calls != 0 {
		t.Fatal("second binding accepted")
	}
}

func TestBindingFailurePreventsExec(t *testing.T) {
	c, file := startTest(t, context.Background())
	failure := errors.New("map update failed")
	err := Bind(c.Context(context.Background()), c.Identity(), func(int) error { return failure })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if err := c.Release(); err == nil {
		t.Fatal("released failed binding")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if c.Wait() == nil {
		t.Fatal("killed bootstrap exited successfully")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("failed binding executed application")
	}
}

func TestCancellationReapsBootstrap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, file := startTest(t, ctx)
	installTest(t, c)
	cancel()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not reap child")
	}
	if err := c.Release(); !errors.Is(err, context.Canceled) {
		t.Fatalf("release after cancel: %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("canceled bootstrap executed application")
	}
}

func TestCancellationKillsRunningApplication(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := Start(ctx, []string{"/bin/sleep", "60"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	installTest(t, c)
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not reap application")
	}
	if c.Wait() == nil {
		t.Fatal("expected killed application")
	}
}

func TestArgumentsAreNotShellCode(t *testing.T) {
	file := filepath.Join(t.TempDir(), "injected")
	c, err := Start(context.Background(), []string{"/bin/true", "$(touch " + file + ")"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	installTest(t, c)
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("argument interpreted as shell code")
	}
}

func TestEnvironmentIsLiteralAndRestoredAfterRelease(t *testing.T) {
	file := filepath.Join(t.TempDir(), "environment")
	value := "secret: apostrophe ' literal $(touch /should-not-be-created); `false` \"quoted\"\nwith spaces"
	c, err := Start(context.Background(), []string{"/bin/sh", "-c", `printf '%s' "$value:$count:$token" > "$1"`, "test", file}, Options{Env: []string{"value=" + value, "count=bad", "token=bad"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", c.Identity().PID))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cmdline), value) || strings.Contains(string(cmdline), "secret:") {
		t.Fatal("environment secret leaked through bootstrap argv")
	}
	installTest(t, c)
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != value+":bad:bad" {
		t.Fatalf("environment changed: %q", got)
	}
}

func TestRejectsInvalidEnvironmentName(t *testing.T) {
	for _, env := range []string{"=bad", "BAD-NAME=x", "1NAME=x", "missing_equals"} {
		c, err := Start(context.Background(), []string{"/bin/true"}, Options{Env: []string{env}})
		if c != nil {
			c.Close()
		}
		if err == nil {
			t.Fatalf("accepted environment %q", env)
		}
	}
}

func TestBootstrapDoesNotInheritApplicationEnvironment(t *testing.T) {
	c, err := Start(context.Background(), []string{"/bin/true"}, Options{Env: []string{"LD_PRELOAD=/does-not-exist", "ENV=/does-not-exist", "BASH_ENV=/does-not-exist"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", c.Identity().PID))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("bootstrap inherited environment: %q", data)
	}
}

func TestPrivateDescriptorsClosedBeforeExec(t *testing.T) {
	c, err := Start(context.Background(), []string{"/bin/sh", "-c", `[ ! -e /proc/self/fd/3 ] && [ ! -e /proc/self/fd/4 ] && [ ! -e /proc/self/fd/5 ]`}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	installTest(t, c)
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("private descriptor inherited: %v", err)
	}
}

func TestEnvironmentFileIsSealed(t *testing.T) {
	file, err := environmentFile([]string{"secret=value"})
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if seals != want {
		t.Fatalf("seals = %x, want %x", seals, want)
	}
	if _, err := file.WriteAt([]byte("x"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("sealed write: %v", err)
	}
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0o600 {
		t.Fatalf("environment permissions: %v", stat.Mode())
	}
}

func TestWaitBoundsInheritedOutputPipe(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "descendant-pid")
	var output bytes.Buffer
	c, err := Start(context.Background(), []string{"/bin/sh", "-c", `sleep 60 & printf '%s' "$!" > "$1"`, "test", pidfile}, Options{Stdout: &output, Stderr: &output})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Kill the explicitly created descendant, which is outside process scope.
		if data, err := os.ReadFile(pidfile); err == nil {
			if pid, err := strconv.Atoi(string(data)); err == nil {
				_ = unix.Kill(pid, unix.SIGKILL)
			}
		}
		c.Close()
	})
	installTest(t, c)
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("inherited output pipe prevented wait completion")
	}
	if err := c.Wait(); !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("Wait = %v, want ErrWaitDelay", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}
