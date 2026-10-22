// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import (
	"strings"
	"testing"
)

func TestParseLaunch(t *testing.T) {
	const valid = "version: 1\npolicy:\n  mode: enforce\n  exec:\n    default: deny\n"
	process := Process{Node: "node", BootID: "boot", HostPID: 123, StartTimeTicks: 456}
	document, err := ParseLaunch(strings.NewReader(valid), DefaultLimits(), process)
	if err != nil {
		t.Fatal(err)
	}
	if document.Binding.Process == nil || *document.Binding.Process != process {
		t.Fatalf("wrong binding: %+v", document.Binding)
	}
	cases := map[string]string{
		"empty binding":      valid + "binding: {}\n",
		"null binding":       valid + "binding: null\n",
		"container binding":  valid + "binding:\n  container:\n    runtime: docker\n    id: other\n",
		"process binding":    valid + "binding:\n  process:\n    hostPID: 42\n",
		"unknown field":      valid + "unknown: true\n",
		"multiple documents": valid + "---\n" + valid,
		"invalid mode":       strings.Replace(valid, "enforce", "invalid", 1),
		"duplicate field":    valid + "version: 1\n",
		"invalid YAML":       "[",
		"oversized":          valid + strings.Repeat(" ", int(DefaultLimits().MaxBytes)),
		"kernel capacity":    valid + "    rules:\n      - name: too-many\n        action: allow\n        target:\n          path: [/a, /b, /c, /d, /e, /f, /g, /h, /i]\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLaunch(strings.NewReader(input), DefaultLimits(), process); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	if _, err := ParseLaunch(strings.NewReader(valid), DefaultLimits(), Process{}); err == nil {
		t.Fatal("invalid launcher identity accepted")
	}
}
