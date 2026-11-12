// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"strings"
	"testing"
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
