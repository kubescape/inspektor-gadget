// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package uprobetracer

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// Run with go test -exec sudo ./pkg/uprobetracer -run TestCachedSymbolKernelCapture.
// Exercise the production attach path, including readable non-executable shared
// objects, both cold and warm lookups, and actual entry/return events.
func TestCachedSymbolKernelCapture(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for uprobe attachment")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("requires a C compiler")
	}
	dir := t.TempDir()
	library := filepath.Join(dir, "target.so")
	source := filepath.Join(dir, "target.c")
	require.NoError(t, os.WriteFile(source, []byte("__attribute__((noinline)) int cache_target(void) { return 7; }\n__attribute__((noinline)) int cache_target_return(void) { return 7; }\n"), 0o600))
	output, err := exec.Command(cc, "-shared", "-fPIC", "-o", library, source).CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.NoError(t, os.Chmod(library, 0o600))
	callerSource := filepath.Join(dir, "caller.c")
	caller := filepath.Join(dir, "caller")
	require.NoError(t, os.WriteFile(callerSource, []byte(`#include <dlfcn.h>
int main(int argc, char **argv) {
    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) return 1;
    int (*target)(void) = dlsym(handle, argv[2]);
    if (!target) return 2;
    for (int i = 0; i < 3; i++) if (target() != 7) return 3;
    return dlclose(handle) != 0;
}
`), 0o600))
	output, err = exec.Command(cc, "-o", caller, callerSource, "-ldl").CombinedOutput()
	require.NoError(t, err, "%s", output)
	file, err := os.Open(library)
	require.NoError(t, err)
	t.Cleanup(func() { file.Close() })
	before, err := file.Stat()
	require.NoError(t, err)

	for _, kind := range []ProgType{ProgUprobe, ProgUretprobe} {
		name := "cache_target"
		if kind == ProgUretprobe {
			name = "cache_target_return"
		}
		for range 2 {
			counter, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
			require.NoError(t, err)
			prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
				Type: ebpf.Kprobe, License: "GPL",
				Instructions: asm.Instructions{
					asm.StoreImm(asm.RFP, -4, 0, asm.Word),
					asm.LoadMapPtr(asm.R1, counter.FD()),
					asm.Mov.Reg(asm.R2, asm.RFP),
					asm.Add.Imm(asm.R2, -4),
					asm.FnMapLookupElem.Call(),
					asm.JEq.Imm(asm.R0, 0, "exit"),
					asm.Mov.Imm(asm.R1, 1),
					asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
					asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
					asm.Return(),
				},
			})
			require.NoError(t, err)
			tracer := &Tracer[any]{progType: kind, prog: prog, attachSymbol: name, logger: logger.DefaultLogger()}
			links, err := tracer.attachUprobe(file, nil)
			require.NoError(t, err)
			require.Len(t, links, 1)
			output, err = exec.Command(caller, library, name).CombinedOutput()
			require.NoError(t, err, "%s", output)
			var count uint64
			require.NoError(t, counter.Lookup(uint32(0), &count))
			require.Equal(t, uint64(3), count, "probe kind %d must capture all calls", kind)
			require.NoError(t, links[0].Close())
			require.NoError(t, prog.Close())
			require.NoError(t, counter.Close())
		}
	}
	for range 2 {
		tracer := &Tracer[any]{progType: ProgUprobe, attachSymbol: "missing_cache_target", logger: logger.DefaultLogger()}
		links, err := tracer.attachUprobe(file, nil)
		require.Empty(t, links)
		require.True(t, errors.Is(err, link.ErrNoSymbol), "missing symbol must fail before binding: %v", err)
	}
	after, err := file.Stat()
	require.NoError(t, err)
	require.Equal(t, before.Mode(), after.Mode())
	require.Equal(t, before.Sys().(*syscall.Stat_t).Ctim, after.Sys().(*syscall.Stat_t).Ctim, "attachment must not chmod the library")
}
