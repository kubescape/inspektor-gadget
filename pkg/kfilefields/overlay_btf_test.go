// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kfilefields

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestCheckOverlayModuleBTF(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modules string
		btf     bool
		wantErr bool
	}{
		{name: "no loaded modules"},
		{name: "unrelated module", modules: "overlay_extra 1 0 - Live 0\n"},
		{name: "available", modules: "overlay 1 0 - Live 0\n", btf: true},
		{name: "missing", modules: "other 1 0 - Live 0\noverlay 1 0 - Live 0\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fstest.MapFS{
				"proc/modules": {Data: []byte(tc.modules)},
			}
			if tc.btf {
				root["sys/kernel/btf/overlay"] = &fstest.MapFile{Data: []byte("btf")}
			}
			err := checkOverlayModuleBTF(root)
			if !tc.wantErr {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("expected missing BTF error, got %v", err)
			}
			for _, message := range []string{"overlay module BTF is unavailable", "real-inode resolution", "CONFIG_DEBUG_INFO_BTF_MODULES"} {
				if !strings.Contains(err.Error(), message) {
					t.Errorf("error %q does not contain %q", err, message)
				}
			}
		})
	}
}

func TestCheckOverlayModuleBTFWithoutModuleSupport(t *testing.T) {
	if err := checkOverlayModuleBTF(fstest.MapFS{}); err != nil {
		t.Fatal(err)
	}
}

type permissionDeniedFS struct {
	fs.FS
	path string
}

func (f permissionDeniedFS) Open(name string) (fs.File, error) {
	if name == f.path {
		return nil, fs.ErrPermission
	}
	return f.FS.Open(name)
}

func TestCheckOverlayModuleBTFUnreadable(t *testing.T) {
	for _, path := range []string{"proc/modules", "sys/kernel/btf/overlay"} {
		t.Run(path, func(t *testing.T) {
			root := permissionDeniedFS{
				FS:   fstest.MapFS{"proc/modules": {Data: []byte("overlay 1 0 - Live 0\n")}},
				path: path,
			}
			if err := checkOverlayModuleBTF(root); !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("expected permission error, got %v", err)
			}
		})
	}
}
