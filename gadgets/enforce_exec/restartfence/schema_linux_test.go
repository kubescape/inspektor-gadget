// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package restartfence

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestV3SchemaRejectsSameSizeLegacyAndMalformedBTF(t *testing.T) {
	for name, mutate := range map[string]func(*btf.Struct){
		"v2 reserved header": func(s *btf.Struct) {
			s.Members[6] = btf.Member{Name: "reserved64", Offset: 256, Type: &btf.Array{Type: &btf.Int{Size: 8}, Nelems: 4}}
			s.Members = append(s.Members[:7], s.Members[8:]...)
		},
		"missing accounting name": func(s *btf.Struct) { s.Members[6].Name = "other" },
		"wrong header offset":     func(s *btf.Struct) { s.Members[6].Offset += 8 },
		"signed accounting":       func(s *btf.Struct) { s.Members[6].Type = &btf.Int{Size: 8, Encoding: btf.Signed} },
		"narrow accounting":       func(s *btf.Struct) { s.Members[6].Type = &btf.Int{Size: 4} },
		"bitfield accounting":     func(s *btf.Struct) { s.Members[6].BitfieldSize = 32 },
		"wrong reserved count":    func(s *btf.Struct) { s.Members[7].Type.(*btf.Array).Nelems = 4 },
		"wrong children count":    func(s *btf.Struct) { s.Members[8].Type.(*btf.Array).Nelems = 127 },
		"wrong child name":        func(s *btf.Struct) { s.Members[8].Type.(*btf.Array).Type.(*btf.Struct).Members[8].Name = "reserved64" },
		"wrong child offset":      func(s *btf.Struct) { s.Members[8].Type.(*btf.Array).Type.(*btf.Struct).Members[8].Offset = 392 },
		"extra field":             func(s *btf.Struct) { s.Members = append(s.Members, btf.Member{Name: "extra"}) },
	} {
		t.Run(name, func(t *testing.T) {
			schema := fencePodSchema()
			mutate(schema)
			if err := validateFencePodSchema(&btf.Int{Size: 8}, schema); err == nil {
				t.Fatal("non-v3 shape accepted")
			}
		})
	}
	for name, key := range map[string]btf.Type{
		"missing": nil,
		"signed":  &btf.Int{Size: 8, Encoding: btf.Signed},
		"small":   &btf.Int{Size: 4},
	} {
		t.Run("key-"+name, func(t *testing.T) {
			if err := validateFencePodSchema(key, fencePodSchema()); err == nil {
				t.Fatal("invalid key BTF accepted")
			}
		})
	}
	if err := validateFencePodSchema(&btf.Int{Size: 8}, nil); err == nil {
		t.Fatal("missing BTF accepted")
	}
	if err := validateFencePodSchema(&btf.Typedef{Name: "__u64", Type: &btf.Int{Size: 8}}, fencePodSchema()); err != nil {
		t.Fatal(err)
	}
}

func TestV3VersionInventoryRetainsForeignAndPendingEntries(t *testing.T) {
	for _, name := range []string{"fence-v1", "fence-v2", "fence-v2_tmp", "fence-v3_tmp", "fence-v4", "fence-unknown"} {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir()
			for _, entry := range []string{fenceDirectory, name} {
				if err := os.Mkdir(filepath.Join(path, entry), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			parent, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			if err := checkFenceSiblings(parent); err == nil {
				t.Fatal("foreign version ignored")
			}
			for _, entry := range []string{fenceDirectory, name} {
				if _, err := os.Stat(filepath.Join(path, entry)); err != nil {
					t.Fatal("evidence changed", err)
				}
			}
		})
	}
	path := t.TempDir()
	if err := os.Mkdir(filepath.Join(path, fenceDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := checkFenceSiblings(parent); err != nil {
		t.Fatal(err)
	}
}

func TestV3ManifestRefusesOldFormatWithIdenticalGeometry(t *testing.T) {
	spec := pinTestSpec()
	manifest := pinTestManifest(spec)
	for _, format := range []int{1, 2, 4} {
		manifest.Format = format
		if err := manifest.check(spec, manifest.BootID, manifest.ObjectSHA256); err == nil {
			t.Fatalf("accepted format %d", format)
		}
	}
	if fencePinFormat != 3 || fenceDirectory != "fence-v3" || InstallRoot != "/sys/fs/bpf/kubescape/fence-v3" {
		t.Fatal("version contract drift")
	}
}
