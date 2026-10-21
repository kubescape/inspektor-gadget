// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type entry struct {
	Generation                                     uint64
	Mode, DefaultDeny, Count, Deny, Prefix, Length uint32
	Path                                           [256]byte
}

func TestExecKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" {
		t.Skip("set IG_EXEC_KERNEL_TEST=1 on a disposable BPF-LSM/cgroup-v2 host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_EXEC_BPF_SOURCE")
	if source == "" {
		source = "bpf/exec.bpf.c"
	}
	tmp := t.TempDir()
	run := func(t *testing.T, name string, args ...string) []byte {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		return out
	}
	t.Logf("kernel: %s", run(t, "uname", "-a"))
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("LSMs: %s", lsm)
	if !strings.Contains(string(lsm), "bpf") {
		t.Fatal("BPF LSM is not enabled")
	}
	header := run(t, "bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c")
	if err := os.WriteFile(filepath.Join(tmp, "vmlinux.h"), header, 0o600); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(tmp, "exec.bpf.o")
	run(t, "clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object)
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("%+v", verifier)
		}
		t.Fatalf("load/verifier: %v", err)
	}
	defer collection.Close()
	attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["enforce_exec"]})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	observer, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["preserve_previous"]})
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	cg := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ig-exec-test-%d", os.Getpid()))
	if err := os.Mkdir(cg, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cg)
	cgFile, err := os.Open(cg)
	if err != nil {
		t.Fatal(err)
	}
	defer cgFile.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(cgFile.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	cgid := stat.Ino
	bindings := collection.Maps["bindings"]
	defer bindings.Delete(cgid)
	mkdir := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	allowed := filepath.Join(tmp, "allowed")
	mkdir(t, allowed)
	sibling := filepath.Join(tmp, "allowed-other")
	mkdir(t, sibling)
	copyExe := func(t *testing.T, dst string) {
		t.Helper()
		b, err := os.ReadFile("/usr/bin/true")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(dst, b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	good, bad := filepath.Join(allowed, "tool"), filepath.Join(sibling, "tool")
	copyExe(t, good)
	copyExe(t, bad)
	publish := func(t *testing.T, gen uint64, mode, def uint32, paths []string, denies []bool) {
		t.Helper()
		inner, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 288, MaxEntries: 9})
		if err != nil {
			t.Fatal(err)
		}
		defer inner.Close()
		h := entry{Generation: gen, Mode: mode, DefaultDeny: def, Count: uint32(len(paths))}
		if err := inner.Put(uint32(0), h); err != nil {
			t.Fatal(err)
		}
		for i, p := range paths {
			r := entry{}
			if strings.HasSuffix(p, "/**") {
				r.Prefix = 1
				p = strings.TrimSuffix(p, "**")
			}
			if len(p) >= 256 {
				t.Fatal("test rule too long")
			}
			r.Length = uint32(len(p))
			copy(r.Path[:], p)
			if denies[i] {
				r.Deny = 1
			}
			if err := inner.Put(uint32(i+1), r); err != nil {
				t.Fatal(err)
			}
		}
		if err := inner.Freeze(); err != nil {
			t.Fatal(err)
		}
		if err := bindings.Put(cgid, inner); err != nil {
			t.Fatal(err)
		}
	}
	execute := func(path string, managed bool) error {
		cmd := exec.Command(path)
		if managed {
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgFile.Fd())}
		}
		return cmd.Run()
	}
	expect := func(t *testing.T, path string, managed, deny bool) {
		t.Helper()
		err := execute(path, managed)
		if deny {
			if !errors.Is(err, syscall.EPERM) {
				t.Fatalf("%s expected EPERM, got %v", path, err)
			}
		} else if err != nil {
			t.Fatalf("%s expected success: %v", path, err)
		}
	}
	t.Run("scope-and-path", func(t *testing.T) {
		publish(t, 1, 2, 1, []string{allowed + "/**"}, []bool{false})
		expect(t, good, true, false)
		expect(t, bad, true, true)
		expect(t, bad, false, false)
		alias := filepath.Join(allowed, "alias")
		if err := os.Symlink(bad, alias); err != nil {
			t.Fatal(err)
		}
		expect(t, alias, true, true)
		// Object identity remains unchanged, but moving out of the allowed directory must deny.
		moved := filepath.Join(sibling, "moved")
		if err := os.Rename(good, moved); err != nil {
			t.Fatal(err)
		}
		expect(t, moved, true, true)
		copyExe(t, good)
		expect(t, good, true, false)
	})
	t.Run("modes-and-precedence", func(t *testing.T) {
		publish(t, 2, 2, 1, []string{allowed + "/**", good}, []bool{false, true})
		expect(t, good, true, true)
		publish(t, 3, 1, 1, nil, nil)
		expect(t, good, true, false)
		publish(t, 4, 0, 1, nil, nil)
		expect(t, bad, true, false)
	})
	t.Run("scripts", func(t *testing.T) {
		script := filepath.Join(allowed, "script")
		if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		publish(t, 5, 2, 1, []string{allowed + "/**"}, []bool{false})
		expect(t, script, true, true)
		shell, err := filepath.EvalSymlinks("/bin/sh")
		if err != nil {
			t.Fatal(err)
		}
		publish(t, 6, 2, 1, []string{allowed + "/**", shell}, []bool{false, false})
		expect(t, script, true, false)
	})
	t.Run("path-resolution-error", func(t *testing.T) {
		longDir := filepath.Join(tmp, strings.Repeat("a", 120), strings.Repeat("b", 120))
		mkdir(t, longDir)
		longExe := filepath.Join(longDir, "tool")
		copyExe(t, longExe)
		publish(t, 7, 2, 0, nil, nil)
		expect(t, longExe, true, true)
		publish(t, 8, 1, 0, nil, nil)
		expect(t, longExe, true, false)
		var counts []uint64
		if err := collection.Maps["counters"].Lookup(uint32(4), &counts); err != nil {
			t.Fatal(err)
		}
		var failures uint64
		for _, n := range counts {
			failures += n
		}
		if failures < 2 {
			t.Fatalf("expected path resolution failures, got %d", failures)
		}
	})
	t.Run("reporting-saturation", func(t *testing.T) {
		publish(t, 7, 2, 1, nil, nil)
		for range 100 {
			expect(t, bad, true, true)
		}
		var counts []uint64
		if err := collection.Maps["counters"].Lookup(uint32(2), &counts); err != nil {
			t.Fatal(err)
		}
		var lost uint64
		for _, v := range counts {
			lost += v
		}
		if lost == 0 {
			t.Fatal("expected ring buffer loss with no reader")
		}
		t.Logf("reports lost while blocking: %d", lost)
	})
	t.Run("atomic-generation", func(t *testing.T) {
		reader, err := ringbuf.NewReader(collection.Maps["events"])
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		// Drain old records before starting the generation-specific oracle.
		reader.SetDeadline(time.Now().Add(20 * time.Millisecond))
		for {
			if _, err := reader.Read(); err != nil {
				break
			}
		}
		var mismatches, observed, even, odd, unexpected atomic.Uint64
		done := make(chan struct{})
		reader.SetDeadline(time.Time{})
		go func() {
			defer close(done)
			for {
				r, err := reader.Read()
				if err != nil {
					return
				}
				g := binary.LittleEndian.Uint64(r.RawSample[0:8])
				deny := binary.LittleEndian.Uint32(r.RawSample[16:20])
				if g >= 100 {
					observed.Add(1)
					if g%2 == 0 {
						even.Add(1)
					} else {
						odd.Add(1)
					}
					if (g%2 == 0 && deny != 0) || (g%2 == 1 && deny != 1) {
						mismatches.Add(1)
					}
				}
			}
		}()
		// Even generations default-deny + allow this path; odd generations default-allow + deny it.
		// Mixing a header and rules from different generations produces the wrong verdict.
		var readerOnce sync.Once
		stopReader := func() { readerOnce.Do(func() { reader.Close(); <-done }) }
		t.Cleanup(stopReader)
		stop := make(chan struct{})
		workerDone := make(chan struct{})
		publish(t, 100, 2, 1, []string{good}, []bool{false})
		go func() {
			defer close(workerDone)
			for {
				select {
				case <-stop:
					return
				default:
					if err := execute(good, true); err != nil && !errors.Is(err, syscall.EPERM) {
						unexpected.Add(1)
					}
				}
			}
		}()
		var workerOnce sync.Once
		stopWorker := func() { workerOnce.Do(func() { close(stop); <-workerDone }) }
		t.Cleanup(stopWorker)
		for g := uint64(101); g < 301; g++ {
			publish(t, g, 2, uint32(1-g%2), []string{good}, []bool{g%2 == 1})
			time.Sleep(time.Millisecond)
		}
		stopWorker()
		time.Sleep(30 * time.Millisecond)
		stopReader()
		if even.Load() == 0 || odd.Load() == 0 || mismatches.Load() != 0 || unexpected.Load() != 0 {
			t.Fatalf("observed=%d allow=%d deny=%d mixed-generation verdicts=%d unexpected=%d", observed.Load(), even.Load(), odd.Load(), mismatches.Load(), unexpected.Load())
		}
		t.Logf("generation-correlated decisions=%d (allow=%d deny=%d), mismatches=0 unexpected errors=%d", observed.Load(), even.Load(), odd.Load(), unexpected.Load())
	})
	t.Run("remove-binding", func(t *testing.T) {
		if err := bindings.Delete(cgid); err != nil {
			t.Fatal(err)
		}
		expect(t, bad, true, false)
	})
}
