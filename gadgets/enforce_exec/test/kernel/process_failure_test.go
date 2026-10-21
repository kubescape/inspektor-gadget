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
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestExecProcessMarkerFailure uses a test-only object that forces marker
// creation to fail. No runtime fault-injection switch exists in the gadget.
func TestExecProcessMarkerFailure(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" {
		t.Skip("requires disposable BPF LSM host")
	}
	object := os.Getenv("IG_EXEC_PROCESS_FAILURE_OBJECT")
	require.NotEmpty(t, object, "compile bpf/process_failure.bpf.c")
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	for _, mode := range []uint32{0, 1, 2} {
		t.Run(fmt.Sprintf("mode%d", mode), func(t *testing.T) {
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
			// A failed worker exec returns to the command loop, permitting repeated
			// attempts and verification that enforce mode keeps the original marker.
			code := strings.Replace(processHelperSource, " execute_self();\n return NULL;", ` char *args[] = {self_path, denied_path, NULL};
 execv(self_path, args);
 if (errno != ENOMEM) _exit(30);
 puts("TRANSFER_FAILED");
 return NULL;`, 1)
			code = strings.Replace(code, "   return 16;", "   continue;", 1)
			require.NoError(t, os.WriteFile(source, []byte(code), 0o600))
			out, err := exec.Command("clang", "-Wall", "-Werror", "-pthread", "-O2", source, "-o", helper).CombinedOutput()
			require.NoError(t, err, string(out))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, helper, "/usr/bin/true")
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
				require.True(t, scanner.Scan(), "expected %s: %v", want, scanner.Err())
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
			require.NoError(t, inner.Put(uint32(0), entry{Generation: 1, Mode: mode, DefaultDeny: 1, Count: 1}))
			rule := entry{Length: uint32(len(helper))}
			copy(rule.Path[:], helper)
			require.NoError(t, inner.Put(uint32(1), rule))
			require.NoError(t, inner.Freeze())
			require.NoError(t, collection.Maps["process_bindings"].Put(uint32(0), inner))
			targets := collection.Maps["process_targets"]
			require.NoError(t, targets.Update(int32(fd), uint64(1), ebpf.UpdateNoExist))
			// Leave the ring unread: regular allowed execs fill it before transfer
			// fails. Off produces no reports at all. Health must work in either case.
			for range 32 {
				send("e", ready)
			}
			var counts []uint64
			require.NoError(t, collection.Maps["counters"].Lookup(uint32(2), &counts))
			var lost uint64
			for _, n := range counts {
				lost += n
			}
			if mode == 0 {
				require.Zero(t, lost)
			} else {
				require.Positive(t, lost, "ring must be full before failure")
			}
			var health struct{ Failures, Degraded uint64 }
			require.NoError(t, collection.Maps["process_health"].Lookup(uint32(0), &health))
			require.Zero(t, health.Failures)
			require.Zero(t, health.Degraded)
			if mode == 2 {
				// The path is allowed by policy, but losing identity is fail-closed.
				for attempt := uint64(1); attempt <= 2; attempt++ {
					send("t", "TRANSFER_FAILED")
					require.NoError(t, collection.Maps["process_health"].Lookup(uint32(0), &health))
					require.Equal(t, attempt, health.Failures)
					require.Zero(t, health.Degraded)
					var marker uint64
					require.NoError(t, targets.Lookup(int32(fd), &marker))
					require.Equal(t, uint64(1), marker)
				}
				send("d", "DENIED")
			} else {
				send("t", ready)
				require.NoError(t, collection.Maps["process_health"].Lookup(uint32(0), &health))
				require.Equal(t, uint64(1), health.Failures)
				require.Equal(t, uint64(1), health.Degraded)
				var marker uint64
				require.ErrorIs(t, targets.Lookup(int32(fd), &marker), ebpf.ErrKeyNotExist, "successful de_thread loses marker")
				send("e", ready)
				require.NoError(t, collection.Maps["process_health"].Lookup(uint32(0), &health))
				require.Equal(t, uint64(1), health.Failures)
				require.Equal(t, uint64(1), health.Degraded)
			}
			_, err = input.Write([]byte("q"))
			require.NoError(t, err)
			require.NoError(t, cmd.Wait())
		})
	}
}
