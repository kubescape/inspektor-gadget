// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification && s1_layout_builder

package fullruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"

	orasoci "oras.land/oras-go/v2/content/oci"
)

var s1ProductObjectName = regexp.MustCompile(`^g19pkg(64|128|256|512)\.bpf\.o$`)

// TestBuildS1ProductLayout (S1 review 4) writes one OCI layout per pinned
// kernel and product profile, each holding the product gadget image of the
// stage-1 object of that profile (BuildSharedCandidateImage: the packaged
// metadata, the object as the program layer). An object must be one this
// release QUALIFIES on that pin (sharedProductPin.ProductObjects); the
// builder refuses anything else and never skips. It is a build tool, absent
// from every test suite (its own build tag s1_layout_builder): build it with
// go test -c -tags 'enforce_exec_shared_qualification s1_layout_builder'
// and run it with -test.run '^TestBuildS1ProductLayout$'.
//
//	IG_ENFORCE_EXEC_PRODUCT_OBJECTS  the four g19pkg<profile>.bpf.o
//	IG_S1_PRODUCT_LAYOUT_OUT         a new or empty output directory
//
// Output: <out>/<kernel>-<profile>/ (an OCI layout) and <out>/images.tsv.
func TestBuildS1ProductLayout(t *testing.T) {
	out := os.Getenv("IG_S1_PRODUCT_LAYOUT_OUT")
	list := strings.FieldsFunc(os.Getenv("IG_ENFORCE_EXEC_PRODUCT_OBJECTS"), func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if out == "" || len(list) != 4 {
		t.Fatal("set IG_S1_PRODUCT_LAYOUT_OUT and IG_ENFORCE_EXEC_PRODUCT_OBJECTS (the four product objects)")
	}
	if entries, err := os.ReadDir(out); err == nil && len(entries) != 0 {
		t.Fatalf("%s is not empty", out)
	}
	profiles := map[string]SharedProfile{
		"64": sharedProductProfileFor(64, 8), "128": sharedProductProfileFor(128, 32),
		"256": sharedProductProfileFor(256, 32), "512": sharedProductProfileFor(512, 16),
	}
	rows := "# kernel\tprofile\tlayout\timage\tobject-sha256\n"
	for _, path := range list {
		m := s1ProductObjectName.FindStringSubmatch(filepath.Base(path))
		if m == nil {
			t.Fatalf("%s: want g19pkg<64|128|256|512>.bpf.o", path)
		}
		profile := profiles[m[1]]
		profile.ExitTombstones = sharedProductExitTombstones
		elf, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(elf)
		digest := hex.EncodeToString(sum[:])
		for _, d := range sharedProductPinDigests() {
			pin := sharedProductPins[d]
			if !pin.qualifiesProductObject(digest) {
				t.Fatalf("%s: sha256 %s is not qualified on %s", path, digest, pin.Release)
			}
			kernel := strings.Join(strings.SplitN(pin.Release, ".", 3)[:2], ".")
			dir := filepath.Join(out, fmt.Sprintf("%s-%s", kernel, m[1]))
			store, err := orasoci.New(dir)
			if err != nil {
				t.Fatal(err)
			}
			image, err := BuildSharedCandidateImage(t.Context(), store, elf, KernelMatrixEntry{Release: pin.Release, Profile: profile})
			if err != nil {
				t.Fatalf("%s on %s: %v", path, pin.Release, err)
			}
			rows += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", kernel, m[1], filepath.Base(dir), image, digest)
		}
	}
	if err := os.WriteFile(filepath.Join(out, "images.tsv"), []byte(rows), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("layouts in %s:\n%s", out, rows)
}
