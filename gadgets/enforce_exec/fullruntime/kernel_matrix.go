// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// SupportedKernelBTF identifies the sole currently proved artifact. This is NOT a general Linux
// or released-kernel support claim. Expanding it requires new isolated proof,
// especially for private overlay fields, task lifecycle and the mutex barrier.
const SupportedKernelBTF = "12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b"

func verifySupportedKernel() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("persistent owner requires proved x86_64 kernel matrix")
	}
	file, err := os.Open("/sys/kernel/btf/vmlinux")
	if err != nil {
		return err
	}
	defer file.Close()
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return err
	}
	if fs.Type != unix.SYSFS_MAGIC {
		return fmt.Errorf("kernel BTF is not on sysfs")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, 128<<20+1))
	if err != nil {
		return err
	}
	if n > 128<<20 || hex.EncodeToString(h.Sum(nil)) != SupportedKernelBTF {
		return fmt.Errorf("kernel BTF is outside proved persistent-owner matrix")
	}
	return checkKernelControls()
}

func checkKernelControls() error {
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return err
	}
	found := false
	for _, name := range strings.Split(strings.TrimSpace(string(lsm)), ",") {
		if name == "bpf" {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("BPF LSM not active")
	}
	ftrace, err := os.ReadFile("/proc/sys/kernel/ftrace_enabled")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(ftrace)) != "1" {
		return fmt.Errorf("ftrace is not enabled")
	}
	return nil
}
