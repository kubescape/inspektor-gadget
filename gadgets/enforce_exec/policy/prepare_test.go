// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import (
	"strings"
	"testing"
)

func TestGadgetPreparation(t *testing.T) {
	for _, mode := range []string{"enforce", "audit", "off"} {
		t.Run(mode, func(t *testing.T) {
			p, err := Prepare(strings.Replace(fixture, "mode: enforce", "mode: "+mode, 1))
			if err != nil {
				t.Fatal(err)
			}
			if p.Hash() == "" || p.RuleCount() != 1 {
				t.Fatal("missing prepared configuration")
			}
		})
	}
	if _, err := Prepare("version: 100"); err == nil {
		t.Fatal("invalid policy prepared")
	}
}
