// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
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

// Overlay exec-file private_data layouts consumed by se_image_classify through
// the se_image_ovl_layout rodata constant (full/shared_image_classify.h
// SE_IMAGE_OVL_LAYOUT_*). struct ovl_file is overlay-module private and absent
// from vmlinux BTF, so the layout is pinned per exact kernel, never CO-RE.
const (
	sharedImageOverlayLayoutUnset    uint32 = 0
	sharedImageOverlayLayoutRealFile uint32 = 1 // 6.12 fs/overlayfs/file.c:170
	sharedImageOverlayLayoutOvlFile  uint32 = 2 // 6.18 fs/overlayfs/file.c:92-95,232
)

// sharedImageOverlayLayouts maps every sharedCandidateKernelBTF release to its
// source-verified overlay layout.
var sharedImageOverlayLayouts = map[string]uint32{
	"6.12.113-138.209.amzn2023.x86_64": sharedImageOverlayLayoutRealFile,
	"6.18.56-125.164.amzn2023.x86_64":  sharedImageOverlayLayoutOvlFile,
}

// sharedImageOverlayLayout selects the se_image_ovl_layout constant for an
// exact shared-candidate vmlinux BTF digest AND the overlay module BTF split
// spec (review M6: struct ovl_file lives in the overlay module, not vmlinux,
// so the vmlinux digest alone does not pin it). The digest picks the expected
// layout; the module BTF must then confirm its exact type shape. A nil spec
// (overlay module BTF absent), any other kernel or any shape mismatch is
// refused (UNSET: the classifier then returns UNKNOWN).
func sharedImageOverlayLayout(btfDigest string, overlay *btf.Spec) (uint32, error) {
	release, ok := sharedCandidateKernelBTF[btfDigest]
	if !ok {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("kernel BTF %q outside the shared candidate matrix", btfDigest)
	}
	layout, ok := sharedImageOverlayLayouts[release]
	if !ok {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("no proved overlay layout for %s", release)
	}
	if overlay == nil {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("overlay module BTF unavailable for %s", release)
	}
	if err := checkOverlayLayoutShape(overlay, layout); err != nil {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("%s: %w", release, err)
	}
	return layout, nil
}

// checkOverlayLayoutShape verifies the overlay module BTF against the layout:
// 6.18 (OvlFile) requires struct ovl_file {struct file *realfile @0; struct
// file *upperfile @8} size 16 (fs/overlayfs/file.c:92-95); 6.12 (RealFile)
// requires struct ovl_file ABSENT (private_data is the realfile itself).
func checkOverlayLayoutShape(overlay *btf.Spec, layout uint32) error {
	var st *btf.Struct
	err := overlay.TypeByName("ovl_file", &st)
	switch layout {
	case sharedImageOverlayLayoutRealFile:
		if err == nil {
			return fmt.Errorf("struct ovl_file present in overlay BTF, expected absent for the realfile layout")
		}
		if !errors.Is(err, btf.ErrNotFound) {
			return fmt.Errorf("overlay BTF lookup: %w", err)
		}
		return nil
	case sharedImageOverlayLayoutOvlFile:
		if err != nil {
			return fmt.Errorf("struct ovl_file in overlay BTF: %w", err)
		}
		if st.Size != 16 || len(st.Members) != 2 {
			return fmt.Errorf("struct ovl_file size %d members %d, want 16 and 2", st.Size, len(st.Members))
		}
		for i, name := range []string{"realfile", "upperfile"} {
			m := st.Members[i]
			if m.Name != name || m.Offset != btf.Bits(i*64) || m.BitfieldSize != 0 || !isFilePointer(m.Type) {
				return fmt.Errorf("struct ovl_file member %d is %q @%d bits, want struct file *%s @%d bits", i, m.Name, m.Offset, name, i*64)
			}
		}
		return nil
	default:
		return fmt.Errorf("no overlay shape for layout %d", layout)
	}
}

func isFilePointer(t btf.Type) bool {
	p, ok := t.(*btf.Pointer)
	if !ok {
		return false
	}
	st, ok := p.Target.(*btf.Struct)
	return ok && st.Name == "file"
}

// overlayModuleSpec loads /sys/kernel/btf/overlay (sysfs-checked, bounded) as
// a split spec over the running vmlinux BTF. A missing file means the overlay
// module is not loaded (or is built in): refused.
func overlayModuleSpec() (*btf.Spec, error) {
	vmlinux, err := readSysfsBTF("/sys/kernel/btf/vmlinux")
	if err != nil {
		return nil, err
	}
	base, err := btf.LoadSpecFromReader(bytes.NewReader(vmlinux))
	if err != nil {
		return nil, fmt.Errorf("vmlinux BTF: %w", err)
	}
	module, err := readSysfsBTF("/sys/kernel/btf/overlay")
	if err != nil {
		return nil, fmt.Errorf("overlay module BTF: %w", err)
	}
	return btf.LoadSplitSpecFromReader(bytes.NewReader(module), base)
}

// Seams for tests: the live layout read and the overlay module autoload.
var (
	overlayLayoutReader = liveSharedImageOverlayLayout
	overlayModuleLoader = autoloadOverlayModule
)

// sharedOverlayLayoutFailure is why the last constants computation could not
// select an overlay layout (nil: it did). Kernel-global, so process-global.
var sharedOverlayLayoutFailure atomic.Pointer[error]

// sharedImageOverlayUnavailable is the node-visible "overlay layout
// unavailable" reason, nil when the layout is set. FromImage publishes are
// refused with it (productImageIndex.build) and node health is Degraded.
func sharedImageOverlayUnavailable() error {
	if p := sharedOverlayLayoutFailure.Load(); p != nil {
		return fmt.Errorf("overlay layout unavailable: %w", *p)
	}
	return nil
}

// resolveSharedImageOverlayLayout reads the live layout. If the overlay
// module BTF is absent (overlay.ko not loaded yet: the agent started before
// any container) it first asks the kernel to load the module, then re-reads.
func resolveSharedImageOverlayLayout() (uint32, error) {
	layout, err := overlayLayoutReader()
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return layout, err
	}
	if lerr := overlayModuleLoader(); lerr != nil {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("%w; module autoload: %w", err, lerr)
	}
	return overlayLayoutReader()
}

// autoloadOverlayModule triggers the kernel's filesystem-type autoload
// (request_module("fs-overlay")) with fsopen(2), which creates no mount. It
// needs CAP_SYS_ADMIN (fsopen) and the kernel's modprobe path; no
// CAP_SYS_MODULE is used by the agent itself.
func autoloadOverlayModule() error {
	fd, err := unix.Fsopen("overlay", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("fsopen overlay: %w", err)
	}
	return unix.Close(fd)
}

// liveSharedImageOverlayLayout is the layout of the running kernel: vmlinux
// digest plus overlay module BTF shape; any failure is UNSET with the error.
func liveSharedImageOverlayLayout() (uint32, error) {
	digest, err := kernelBTFDigest()
	if err != nil {
		return sharedImageOverlayLayoutUnset, err
	}
	overlay, err := overlayModuleSpec()
	if err != nil {
		return sharedImageOverlayLayoutUnset, err
	}
	return sharedImageOverlayLayout(digest, overlay)
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
	digest, err := kernelBTFDigest()
	if err != nil {
		return err
	}
	if !supported(digest) {
		return fmt.Errorf("kernel BTF is outside proved %s matrix (sha256 %s)", matrix, digest)
	}
	return checkKernelControls()
}

var (
	kernelBTFDigestOnce  sync.Once
	kernelBTFDigestValue string
	kernelBTFDigestErr   error
)

// kernelBTFDigest is the sha256 of the running kernel's sysfs vmlinux BTF,
// computed once per process (value and error cached: the running kernel's BTF
// cannot change).
func kernelBTFDigest() (string, error) {
	kernelBTFDigestOnce.Do(func() {
		var data []byte
		if data, kernelBTFDigestErr = readSysfsBTF("/sys/kernel/btf/vmlinux"); kernelBTFDigestErr == nil {
			sum := sha256.Sum256(data)
			kernelBTFDigestValue = hex.EncodeToString(sum[:])
		}
	})
	return kernelBTFDigestValue, kernelBTFDigestErr
}

// readSysfsBTF reads a kernel BTF file, refusing anything not on sysfs or
// larger than 128 MiB.
func readSysfsBTF(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.SYSFS_MAGIC {
		return nil, fmt.Errorf("kernel BTF is not on sysfs")
	}
	data, err := io.ReadAll(io.LimitReader(file, 128<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 128<<20 {
		return nil, fmt.Errorf("kernel BTF exceeds 128 MiB")
	}
	return data, nil
}

// sharedImageOverlayConstants are the native constants (operators.
// NativeConstantsKey) of one shared candidate collection load on the running
// kernel: the se_image_ovl_layout of the exact matrix kernel (off the matrix
// UNSET: the classifier then refuses every overlay file as UNKNOWN (AUTH),
// never from-image), and the load's random nonzero se_verdict_load_epoch
// (review M7: task_cookie restarts per load, so verdict events are keyed by
// (load_epoch, task_cookie, exec_id)).
func sharedImageOverlayConstants() (map[string]any, error) {
	layout, err := resolveSharedImageOverlayLayout()
	if err != nil {
		layout = sharedImageOverlayLayoutUnset
		reason := err
		sharedOverlayLayoutFailure.Store(&reason)
	} else {
		sharedOverlayLayoutFailure.Store(nil)
	}
	epoch, err := sharedVerdictLoadEpoch()
	if err != nil {
		return nil, err
	}
	return map[string]any{sharedImageOverlayLayoutConstant: layout, sharedVerdictLoadEpochConstant: epoch}, nil
}

// Native constant names (full/shared_image_classify.h,
// full/shared_verdict_event.h).
const (
	sharedImageOverlayLayoutConstant = "se_image_ovl_layout"
	sharedVerdictLoadEpochConstant   = "se_verdict_load_epoch"
)

// sharedVerdictLoadEpoch is a random nonzero 64-bit load epoch.
func sharedVerdictLoadEpoch() (uint64, error) {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("verdict load epoch: %w", err)
		}
		if epoch := binary.LittleEndian.Uint64(b[:]); epoch != 0 {
			return epoch, nil
		}
	}
}

// kernelLSMRoots are the roots under which sys/kernel/security/lsm is read,
// in order: the host root (HOST_ROOT), then this process's own view. An
// unprivileged agent pod's /sys has no securityfs mounted, while the host's
// boot-time securityfs is visible under its host root mount. Falling back to
// the own view is equally correct: securityfs is one kernel-wide superblock
// (not namespaced), so every mount of it shows the same list, and the
// SECURITYFS_MAGIC check refuses anything that is not that filesystem.
var kernelLSMRoots = func() []string { return []string{host.HostRoot, "/"} }

// readKernelLSM returns the active LSM list from the first root whose
// sys/kernel/security/lsm is on securityfs; every failure is reported.
func readKernelLSM(roots []string) (string, error) {
	var errs []error
	seen := map[string]bool{}
	for _, root := range roots {
		path := filepath.Join(root, "sys/kernel/security/lsm")
		if seen[path] {
			continue
		}
		seen[path] = true
		data, err := readSecurityFSFile(root, "sys/kernel/security/lsm")
		if err == nil {
			return data, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return "", fmt.Errorf("no LSM list root")
	}
	return "", errors.Join(errs...)
}

// readSecurityFSFile opens name with root as its filesystem root
// (RESOLVE_IN_ROOT): a symlink inside the host tree cannot redirect the read
// outside it, e.g. onto a file in the agent's own filesystem.
func readSecurityFSFile(root, name string) (string, error) {
	path := filepath.Join(root, name)
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("%s: %w", root, err)
	}
	fd, err := unix.Openat2(rootFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
	closeErr := unix.Close(rootFD)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if closeErr != nil {
		return "", closeErr
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return "", err
	}
	if fs.Type != unix.SECURITYFS_MAGIC {
		return "", fmt.Errorf("%s is not on securityfs", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", err
	}
	if len(data) > 4096 {
		return "", fmt.Errorf("%s exceeds 4096 bytes", path)
	}
	return string(data), nil
}

// requireBPFLSM refuses an LSM list without the exact "bpf" entry.
func requireBPFLSM(lsm string) error {
	for _, name := range strings.Split(strings.TrimSpace(lsm), ",") {
		if name == "bpf" {
			return nil
		}
	}
	return fmt.Errorf("BPF LSM not active")
}

func checkKernelControls() error {
	lsm, err := readKernelLSM(kernelLSMRoots())
	if err != nil {
		return err
	}
	if err = requireBPFLSM(lsm); err != nil {
		return err
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
