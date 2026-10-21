// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestExecProcessKernel exercises the production object with task storage
// seeded through a pidfd, including de_thread() when a worker executes execve.
// The helper replaces itself so the same process can make multiple decisions.
func TestExecProcessKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" {
		t.Skip("requires disposable BPF LSM host and IG_EXEC_KERNEL_TEST=1")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	object := os.Getenv("IG_EXEC_BPF_OBJECT")
	require.NotEmpty(t, object)
	spec, err := ebpf.LoadCollectionSpec(object)
	require.NoError(t, err)
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["enforce_exec"]})
	require.NoError(t, err)
	defer attached.Close()
	tmp := t.TempDir()
	helper := filepath.Join(tmp, "helper")
	source := filepath.Join(tmp, "helper.c")
	require.NoError(t, os.WriteFile(source, []byte(processHelperSource), 0o600))
	out, err := exec.Command("clang", "-Wall", "-Werror", "-pthread", "-O2", source, "-o", helper).CombinedOutput()
	require.NoError(t, err, string(out))
	denied := filepath.Join(tmp, "denied")
	binary, err := os.ReadFile("/usr/bin/true")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(denied, binary, 0o755))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, denied)
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	output, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(output)
	read := func(want string) {
		t.Helper()
		require.True(t, scanner.Scan(), "expected %s; scan error: %v", want, scanner.Err())
		require.Equal(t, want, scanner.Text())
	}
	send := func(command, want string) {
		t.Helper()
		_, err := input.Write([]byte(command))
		require.NoError(t, err)
		read(want)
	}
	ready := fmt.Sprintf("READY %d", cmd.Process.Pid)
	read(ready)
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	inner, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 288, MaxEntries: 9})
	require.NoError(t, err)
	defer inner.Close()
	require.NoError(t, inner.Put(uint32(0), entry{Generation: 1, Mode: 2, DefaultDeny: 1, Count: 1}))
	rule := entry{Length: uint32(len(helper))}
	copy(rule.Path[:], helper)
	require.NoError(t, inner.Put(uint32(1), rule))
	require.NoError(t, inner.Freeze())
	require.NoError(t, collection.Maps["process_bindings"].Put(uint32(0), inner))
	targets := collection.Maps["process_targets"]
	require.NoError(t, targets.Update(int32(fd), uint64(1), ebpf.UpdateNoExist))
	send("d", "DENIED")
	send("f", "CHILD_ALLOWED")
	for range 3 {
		send("e", ready)
		send("d", "DENIED")
	}
	// A successful nonleader exec replaces the leader task object. Future
	// decisions must retain scope, while children still remain outside it.
	send("t", ready)
	send("d", "DENIED")
	send("f", "CHILD_ALLOWED")
	var health struct{ Failures, Degraded uint64 }
	require.NoError(t, collection.Maps["process_health"].Lookup(uint32(0), &health))
	require.Zero(t, health.Failures)
	require.Zero(t, health.Degraded)
	send("e", ready)
	send("d", "DENIED")
	_, err = input.Write([]byte("q"))
	require.NoError(t, err)
	require.NoError(t, cmd.Wait())
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	_, err = unix.Poll(fds, 1000)
	require.NoError(t, err)
	require.NotZero(t, fds[0].Revents&unix.POLLIN, "pidfd must report process exit")
	var marker uint64
	err = targets.Lookup(int32(fd), &marker)
	require.Error(t, err, "exited task must no longer expose storage")
	require.True(t, errors.Is(err, ebpf.ErrKeyNotExist) || errors.Is(err, unix.ESRCH), "unexpected task-storage lookup error: %v", err)
	t.Log("exact process, repeated exec, child exclusion, nonleader exec continuity and exit cleanup passed")
}

const processHelperSource = `
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
static char *self_path, *denied_path;
static void execute_self(void) {
 char *args[] = {self_path, denied_path, NULL};
 execv(self_path, args);
 perror("self exec");
 _exit(20);
}
static void *thread_exec(void *unused) {
 (void)unused;
 execute_self();
 return NULL;
}
int main(int argc, char **argv) {
 if (argc != 2) return 10;
 self_path = argv[0]; denied_path = argv[1];
 setbuf(stdout, NULL);
 printf("READY %d\n", getpid());
 int command;
 while ((command = getchar()) != EOF) {
  if (command == 'q') return 0;
  if (command == 'e') execute_self();
  if (command == 'd') {
   char *args[] = {denied_path, NULL};
   execv(denied_path, args);
   if (errno != EPERM) { perror("denied exec"); return 11; }
   puts("DENIED");
  }
  if (command == 'f') {
   pid_t child = fork();
   if (child < 0) return 12;
   if (child == 0) {
    char *args[] = {denied_path, NULL};
    execv(denied_path, args);
    _exit(13);
   }
   int status;
   if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 14;
   puts("CHILD_ALLOWED");
  }
  if (command == 't') {
   pthread_t thread;
   if (pthread_create(&thread, NULL, thread_exec, NULL)) return 15;
   pthread_join(thread, NULL);
   return 16;
  }
 }
 return 17;
}
`
