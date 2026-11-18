// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package selfqual

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Fingerprint identifies the kernel a qualification ran on. It is recorded,
// not matched against a list: its job is to tell the agent when a previous
// qualification no longer describes the running kernel.
type Fingerprint struct {
	Arch    string `json:"arch"`
	Release string `json:"release"`
	Version string `json:"version"`
	BTF     string `json:"btf_sha256"`
	Notes   string `json:"notes_sha256"` // /sys/kernel/notes (carries the GNU build-id)
	LSM     string `json:"lsm"`
	Cmdline string `json:"cmdline"`
}

// fileSHA256 returns "" for a file it cannot read. An empty digest never
// equals anything, itself included: see Fingerprint.Same.
func fileSHA256(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Complete reports whether every identifying field was read.
func (f Fingerprint) Complete() bool {
	return f.Release != "" && f.BTF != "" && f.Notes != "" && f.LSM != ""
}

// Same reports whether f and o identify the same kernel. Two fingerprints
// with an unread field are never the same: unreadable is not equal.
func (f Fingerprint) Same(o Fingerprint) bool {
	return f.Complete() && o.Complete() && f.Arch == o.Arch && f.Release == o.Release && f.BTF == o.BTF && f.Notes == o.Notes && f.LSM == o.LSM
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}

func cstr(b []byte) string {
	if i := slices.Index(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// ReadFingerprint reads the running kernel's fingerprint.
func ReadFingerprint() Fingerprint {
	var u unix.Utsname
	unix.Uname(&u)
	lsm, _ := readTrim("/sys/kernel/security/lsm")
	cmdline, _ := readTrim("/proc/cmdline")
	return Fingerprint{
		Arch: runtime.GOARCH, Release: cstr(u.Release[:]), Version: cstr(u.Version[:]),
		BTF: fileSHA256("/sys/kernel/btf/vmlinux"), Notes: fileSHA256("/sys/kernel/notes"),
		LSM: lsm, Cmdline: cmdline,
	}
}

// RuntimeControls re-reads the kernel controls that can change after
// admission (the same two CheckKernelRuntime reads): ftrace_enabled and the
// livepatch taint. Call it at every Ready, never cache it.
func RuntimeControls() error {
	ftrace, err := readTrim("/proc/sys/kernel/ftrace_enabled")
	if err != nil {
		return fmt.Errorf("ftrace_enabled: %w", err)
	}
	if ftrace != "1" {
		return fmt.Errorf("ftrace is not enabled (kernel.ftrace_enabled=%s)", ftrace)
	}
	tainted, err := readTrim("/proc/sys/kernel/tainted")
	if err != nil {
		return fmt.Errorf("kernel taint: %w", err)
	}
	mask, err := strconv.ParseUint(tainted, 10, 64)
	if err != nil {
		return fmt.Errorf("kernel taint %q: %w", tainted, err)
	}
	if mask&(1<<15) != 0 {
		return fmt.Errorf("kernel is livepatched (taint %d has TAINT_LIVEPATCH)", mask)
	}
	return nil
}

// StaticChecks are the cheap preconditions, checked before any probe runs.
// They are a pre-filter only: each one can refuse, none can admit.
func StaticChecks() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("arch %s: only amd64 has a probe helper", runtime.GOARCH)
	}
	lsm, err := readTrim("/sys/kernel/security/lsm")
	if err != nil {
		return fmt.Errorf("LSM list: %w", err)
	}
	if !slices.Contains(strings.Split(lsm, ","), "bpf") {
		return fmt.Errorf("bpf is not in the active LSM list (%s)", lsm)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf("kernel BTF: %w", err)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(cgroupRoot, &fs); err != nil {
		return fmt.Errorf("cgroup root: %w", err)
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("%s is not a cgroup v2 mount", cgroupRoot)
	}
	return RuntimeControls()
}
