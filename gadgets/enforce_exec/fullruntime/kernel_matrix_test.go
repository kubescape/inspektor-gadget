// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestSupportedKernelBTFExactMatrix(t *testing.T) {
	for _, digest := range []string{SupportedKernelBTF, SupportedKubernetesKernelBTF} {
		if !supportedKernelBTF(digest) {
			t.Fatalf("known exact artifact rejected: %s", digest)
		}
		for _, unknown := range []string{"", digest[:63], digest + "0", "0" + digest[1:], strings.ToUpper(digest), digest + "\n", " " + digest} {
			if supportedKernelBTF(unknown) {
				t.Fatalf("nonexact artifact accepted: %q", unknown)
			}
		}
	}
	if supportedKernelBTF(strings.Repeat("0", 64)) {
		t.Fatal("unknown digest accepted")
	}
}

func TestOwnerBuilderKernelMatrixMatchesRuntime(t *testing.T) {
	builder, err := os.ReadFile("../full/owner/build-archive.sh")
	if err != nil {
		t.Fatal(err)
	}
	for name, digest := range map[string]string{"expected_btf": SupportedKernelBTF, "kubernetes_btf": SupportedKubernetesKernelBTF} {
		if !strings.Contains(string(builder), "\n"+name+"="+digest+"\n") {
			t.Fatalf("builder %s differs from runtime matrix", name)
		}
	}
}

// TestSharedCandidateKernelMatrixIsSeparate: the shared candidate matrix is
// exactly the two qualified AL2023 kernels and shares nothing with the
// persistent-owner matrix in either direction.
func TestSharedCandidateKernelMatrixIsSeparate(t *testing.T) {
	if len(sharedCandidateKernelBTF) != 2 {
		t.Fatalf("shared candidate matrix %v", sharedCandidateKernelBTF)
	}
	for digest, release := range sharedCandidateKernelBTF {
		if len(digest) != 64 || strings.ToLower(digest) != digest || !strings.HasSuffix(release, ".amzn2023.x86_64") {
			t.Errorf("malformed entry %q: %q", digest, release)
		}
		if supportedKernelBTF(digest) {
			t.Errorf("shared candidate kernel %s admitted by the persistent-owner matrix", release)
		}
	}
	for _, digest := range []string{SupportedKernelBTF, SupportedKubernetesKernelBTF} {
		if _, ok := sharedCandidateKernelBTF[digest]; ok {
			t.Errorf("persistent-owner kernel %s in the shared candidate matrix", digest)
		}
	}
}

// TestMain makes the node-level unit tests host-independent: the overlay
// layout read is faked (as on a matrix kernel with overlay loaded) unless a
// live VM test (IG_SHARED_OVL_BTF / IG_SHARED_OVL_AUTOLOAD) uses the real one,
// or the binary runs on an exact shared-candidate kernel: there every
// attached test loads real objects, whose classifier must get that kernel's
// own layout (a faked 6.18 OVL_FILE on 6.12 dereferenced the realfile as an
// ovl_file: every image fact READ_FAULT/UNKNOWN, G020 6.12 image failure).
func TestMain(m *testing.M) {
	if os.Getenv("IG_SHARED_OVL_BTF") != "1" && os.Getenv("IG_SHARED_OVL_AUTOLOAD") != "1" && !onSharedCandidateKernel() {
		overlayLayoutReader = func() (uint32, error) { return sharedImageOverlayLayoutOvlFile, nil }
		overlayModuleLoader = func() error { return nil }
	}
	os.Exit(m.Run())
}

// onSharedCandidateKernel: the running kernel's BTF is one of the exact
// shared-candidate matrix kernels.
func onSharedCandidateKernel() bool {
	digest, err := kernelBTFDigest()
	if err != nil {
		return false
	}
	_, ok := sharedCandidateKernelBTF[digest]
	return ok
}

// TestSharedImageOverlayLayoutExactMatrix: every shared candidate kernel has
// exactly its source-verified overlay layout, the values match the classifier
// header, and nothing outside the exact matrix selects a layout.
func TestSharedImageOverlayLayoutExactMatrix(t *testing.T) {
	want := map[string]uint32{
		"6.12.113-138.209.amzn2023.x86_64": 1,
		"6.18.56-125.164.amzn2023.x86_64":  2,
	}
	if len(sharedImageOverlayLayouts) != len(sharedCandidateKernelBTF) {
		t.Fatalf("layout matrix %v differs from kernel matrix %v", sharedImageOverlayLayouts, sharedCandidateKernelBTF)
	}
	for digest, release := range sharedCandidateKernelBTF {
		spec := overlaySpecForLayout(t, want[release])
		got, err := sharedImageOverlayLayout(digest, spec)
		if err != nil || got != want[release] || got == sharedImageOverlayLayoutUnset {
			t.Errorf("%s: layout %d err %v, want %d", release, got, err, want[release])
		}
		for _, unknown := range []string{"", digest[:63], digest + "0", strings.ToUpper(digest), release} {
			if got, err := sharedImageOverlayLayout(unknown, spec); err == nil || got != sharedImageOverlayLayoutUnset {
				t.Errorf("nonexact identity %q selected layout %d", unknown, got)
			}
		}
	}
	for _, digest := range []string{SupportedKernelBTF, SupportedKubernetesKernelBTF} {
		if _, err := sharedImageOverlayLayout(digest, overlaySpecForLayout(t, 2)); err == nil {
			t.Errorf("persistent-owner kernel %s selected an overlay layout", digest)
		}
	}
	header, err := os.ReadFile("../full/shared_image_classify.h")
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]uint32{
		"SE_IMAGE_OVL_LAYOUT_UNSET":    sharedImageOverlayLayoutUnset,
		"SE_IMAGE_OVL_LAYOUT_REALFILE": sharedImageOverlayLayoutRealFile,
		"SE_IMAGE_OVL_LAYOUT_OVL_FILE": sharedImageOverlayLayoutOvlFile,
	} {
		if !strings.Contains(string(header), fmt.Sprintf("#define %s %d", name, value)) {
			t.Errorf("header %s differs from Go value %d", name, value)
		}
	}
}

// overlaySpecForLayout builds a synthetic overlay module BTF: 6.18 shape
// (struct ovl_file {file *realfile; file *upperfile}) or, for the realfile
// layout, a spec without struct ovl_file.
func overlaySpecForLayout(t *testing.T, layout uint32) *btf.Spec {
	t.Helper()
	if layout == sharedImageOverlayLayoutRealFile {
		return ovlSpec(t, nil)
	}
	file := &btf.Struct{Name: "file", Size: 8}
	ptr := &btf.Pointer{Target: file}
	return ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 16, Members: []btf.Member{
		{Name: "realfile", Type: ptr, Offset: 0},
		{Name: "upperfile", Type: ptr, Offset: 64},
	}})
}

func ovlSpec(t *testing.T, ovl *btf.Struct) *btf.Spec {
	t.Helper()
	types := []btf.Type{&btf.Struct{Name: "unrelated", Size: 4}}
	if ovl != nil {
		types = append(types, ovl)
	}
	b, err := btf.NewBuilder(types, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := b.Spec()
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// TestSharedImageOverlayLayoutModuleBTFPin (review M6): the overlay module BTF
// shape must confirm the vmlinux-digest layout; every mismatch, a missing
// module BTF and a swapped-kernel combination select UNSET.
func TestSharedImageOverlayLayoutModuleBTFPin(t *testing.T) {
	var d612, d618 string
	for digest, release := range sharedCandidateKernelBTF {
		if strings.HasPrefix(release, "6.12.") {
			d612 = digest
		} else {
			d618 = digest
		}
	}
	file := &btf.Struct{Name: "file", Size: 8}
	ptr := &btf.Pointer{Target: file}
	member := func(name string, off uint32) btf.Member {
		return btf.Member{Name: name, Type: ptr, Offset: btf.Bits(off)}
	}
	cases := []struct {
		name   string
		digest string
		spec   *btf.Spec
	}{
		{"6.18 digest, module BTF missing", d618, nil},
		{"6.12 digest, module BTF missing", d612, nil},
		{"6.18 digest, 6.12 module shape (ovl_file absent)", d618, overlaySpecForLayout(t, 1)},
		{"6.12 digest, 6.18 module shape (ovl_file present)", d612, overlaySpecForLayout(t, 2)},
		{"6.18 wrong size", d618, ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 24, Members: []btf.Member{member("realfile", 0), member("upperfile", 64)}})},
		{"6.18 swapped members", d618, ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 16, Members: []btf.Member{member("upperfile", 0), member("realfile", 64)}})},
		{"6.18 wrong offset", d618, ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 16, Members: []btf.Member{member("realfile", 0), member("upperfile", 128)}})},
		{"6.18 extra member", d618, ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 16, Members: []btf.Member{member("realfile", 0), member("upperfile", 64), member("x", 128)}})},
		{"6.18 non-pointer member", d618, ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 16, Members: []btf.Member{member("realfile", 0), {Name: "upperfile", Type: &btf.Int{Name: "long", Size: 8}, Offset: 64}}})},
	}
	for _, tc := range cases {
		if got, err := sharedImageOverlayLayout(tc.digest, tc.spec); err == nil || got != sharedImageOverlayLayoutUnset {
			t.Errorf("%s: layout %d err %v, want UNSET and error", tc.name, got, err)
		}
	}
}

// TestResolveSharedImageOverlayLayoutAutoload: an absent overlay module BTF
// triggers one autoload then a re-read; a failed autoload or a non-ENOENT
// error does not; failures are recorded as the node's unavailable reason.
func TestResolveSharedImageOverlayLayoutAutoload(t *testing.T) {
	oldRead, oldLoad := overlayLayoutReader, overlayModuleLoader
	t.Cleanup(func() {
		overlayLayoutReader, overlayModuleLoader = oldRead, oldLoad
		sharedOverlayLayoutFailure.Store(nil)
	})
	loaded, loads := false, 0
	overlayLayoutReader = func() (uint32, error) {
		if !loaded {
			return 0, fmt.Errorf("overlay module BTF: %w", os.ErrNotExist)
		}
		return sharedImageOverlayLayoutOvlFile, nil
	}
	overlayModuleLoader = func() error { loads++; loaded = true; return nil }
	if got, err := resolveSharedImageOverlayLayout(); err != nil || got != sharedImageOverlayLayoutOvlFile || loads != 1 {
		t.Fatalf("autoload path: layout %d err %v loads %d", got, err, loads)
	}
	// Autoload fails: UNSET and a reason reaches the node.
	loaded, loads = false, 0
	overlayModuleLoader = func() error { loads++; return fmt.Errorf("EPERM") }
	if got, err := resolveSharedImageOverlayLayout(); err == nil || got != sharedImageOverlayLayoutUnset || loads != 1 {
		t.Fatalf("failed autoload: layout %d err %v loads %d", got, err, loads)
	}
	c, err := sharedImageOverlayConstants()
	if err != nil || c[sharedImageOverlayLayoutConstant] != sharedImageOverlayLayoutUnset {
		t.Fatalf("constants %v err %v", c, err)
	}
	if err := sharedImageOverlayUnavailable(); err == nil || !strings.Contains(err.Error(), "EPERM") {
		t.Fatalf("unavailable reason %v", err)
	}
	// Non-ENOENT errors (shape mismatch) never autoload.
	loads = 0
	overlayLayoutReader = func() (uint32, error) { return 0, fmt.Errorf("shape mismatch") }
	if _, err := resolveSharedImageOverlayLayout(); err == nil || loads != 0 {
		t.Fatalf("mismatch must not autoload: err %v loads %d", err, loads)
	}
	// Recovery clears the reason.
	overlayLayoutReader = func() (uint32, error) { return sharedImageOverlayLayoutRealFile, nil }
	if _, err := sharedImageOverlayConstants(); err != nil || sharedImageOverlayUnavailable() != nil {
		t.Fatalf("reason not cleared: %v", err)
	}
}

// TestSharedLiveHealthOverlayUnavailable: an unavailable overlay layout is
// Degraded, never a startup failure: the live health stays clean, the node's
// Ready reports it (FromImage refused), and the image build refuses.
func TestSharedLiveHealthOverlayUnavailable(t *testing.T) {
	boom := fmt.Errorf("overlay layout unavailable: boom")
	if e := (sharedLiveHealth{image: healthyImage{}}).check(); e != nil {
		t.Fatalf("startup health %v", e)
	}
	n := &NodeEnforcer{host: &sharedHostState{}}
	if e := n.overlayDegraded(); e != nil {
		t.Fatalf("Degraded without a reason: %v", e)
	}
	n.host.overlayFailure.Store(&boom)
	if e := n.overlayDegraded(); e == nil || !strings.Contains(e.Error(), "FromImage policies refused") || !errors.Is(e, boom) {
		t.Fatalf("Degraded %v", e)
	}
	x := &productImageIndex{resolver: noopImageResolver{}, overlayUnavailable: func() error { return boom }}
	_, _, e := x.build(t.Context(), 0, 0, SharedInitIdentity{ContainerID: "c"})
	if !errors.Is(e, ErrSharedImageIndexUnavailable) || !strings.Contains(e.Error(), "overlay layout unavailable") {
		t.Fatalf("build %v", e)
	}
}

type noopImageResolver struct{ sharedImageResolving }

type healthyImage struct{}

func (healthyImage) imageHealth() error { return nil }
