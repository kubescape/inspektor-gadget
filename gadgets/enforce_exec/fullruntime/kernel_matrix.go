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

// SupportedKernelBTF identifies the original isolated proof artifact. This is NOT
// a general Linux or released-kernel support claim. Expanding the exact matrix
// requires isolated proof of overlay fields, task lifecycle and the mutex barrier.
const SupportedKernelBTF = "12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b"

// SupportedKubernetesKernelBTF identifies the same pinned Linux source with the
// additional fanotify, networking and CPU bandwidth configuration needed by the
// isolated Kubernetes proof. It does not admit other builds of that source.
const SupportedKubernetesKernelBTF = "759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51"

func supportedKernelBTF(digest string) bool {
	switch digest {
	case SupportedKernelBTF, SupportedKubernetesKernelBTF:
		return true
	default:
		return false
	}
}

// sharedCandidateKernelBTF is the exact kernel matrix of the shared-node
// candidate (G019 qualification builds only): the BTF of the two AL2023
// guest kernels the candidate objects are compiled against (compile.sh
// vmlinux.h) and qualified on (G005/G009/G019 isolated VM runs). It is not
// the persistent-owner matrix above and admits nothing to that path.
var sharedCandidateKernelBTF = map[string]string{
	"0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82": "6.12.113-138.209.amzn2023.x86_64",
	"d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee": "6.18.56-125.164.amzn2023.x86_64",
}

func verifySupportedKernel() error {
	return verifyKernelBTF(supportedKernelBTF, "persistent-owner")
}

// verifySharedCandidateKernel admits only sharedCandidateKernelBTF.
func verifySharedCandidateKernel() error {
	return verifyKernelBTF(func(digest string) bool {
		_, ok := sharedCandidateKernelBTF[digest]
		return ok
	}, "shared candidate")
}

func verifyKernelBTF(supported func(string) bool, matrix string) error {
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
	if digest := hex.EncodeToString(h.Sum(nil)); n > 128<<20 || !supported(digest) {
		return fmt.Errorf("kernel BTF is outside proved %s matrix (sha256 %s)", matrix, digest)
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
