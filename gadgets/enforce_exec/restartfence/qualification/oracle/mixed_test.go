// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	fence "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
)

func TestFixtureModeTranslation(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input uint32
		want  fence.Mode
	}{
		{"audit", 1, fence.Audit}, {"strict", 2, fence.Strict}, {"off", 3, fence.Off},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fixtureMode(tt.input)
			if err != nil || got != tt.want {
				t.Fatalf("mode=%v error=%v want=%v", got, err, tt.want)
			}
		})
	}
	for _, mode := range []uint32{0, 4, ^uint32(0)} {
		if _, err := fixtureMode(mode); err == nil {
			t.Fatalf("accepted unknown fixture mode %d", mode)
		}
	}
}

func TestMixedCommandUsesExactChildIdentity(t *testing.T) {
	f := fixture{pods: []pod{{id: 17, childID: 23, mode: 2}, {id: 17, childID: 29, mode: 1}}}
	got := f.mixedCommand("refence", 1)
	if got.Pod != 17 || got.Child != 29 || got.Identity != 29 || got.Mode != 1 || got.Op != "refence" {
		t.Fatalf("wrong child command: %+v", got)
	}
}
