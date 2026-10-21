// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import (
	"fmt"
	"strings"
)

const (
	KernelMaxRules = 8
	KernelPathSize = 256
)

// KernelEntry is the map value shared with the execution BPF program. Entry zero
// holds the generation header; subsequent entries each describe one path.
type KernelEntry struct {
	Generation  uint64
	Mode        uint32
	DefaultDeny uint32
	Count       uint32
	Deny        uint32
	Prefix      uint32
	Length      uint32
	Path        [KernelPathSize]byte
}

// CompileKernel prepares a complete generation before any kernel map is changed.
// It preserves rule order; the BPF evaluator gives matching denies precedence.
// Unsupported configurations return an empty generation, never partial rules.
func CompileKernel(d Document, generation uint64) ([KernelMaxRules + 1]KernelEntry, error) {
	var entries [KernelMaxRules + 1]KernelEntry
	fail := func(err error) ([KernelMaxRules + 1]KernelEntry, error) {
		return [KernelMaxRules + 1]KernelEntry{}, err
	}
	if err := d.Validate(DefaultLimits()); err != nil {
		return fail(err)
	}
	if generation == 0 {
		return fail(fmt.Errorf("kernel generation must be nonzero"))
	}
	entries[0].Generation = generation
	switch d.Policy.Mode {
	case "audit":
		entries[0].Mode = 1
	case "enforce":
		entries[0].Mode = 2
	}
	if d.Policy.Exec.Default == "deny" {
		entries[0].DefaultDeny = 1
	}
	for _, rule := range d.Policy.Exec.Rules {
		if rule.Mode != "" && rule.Mode != d.Policy.Mode {
			return fail(fmt.Errorf("rule %q mode must match policy mode for the kernel backend", rule.Name))
		}
		for _, pattern := range rule.Target.Path {
			if entries[0].Count == KernelMaxRules {
				return fail(fmt.Errorf("kernel expanded path capacity exceeded (%d)", KernelMaxRules))
			}
			var entry KernelEntry
			if strings.HasSuffix(pattern, "/**") {
				pattern = strings.TrimSuffix(pattern, "**")
				entry.Prefix = 1
			}
			if len(pattern) >= KernelPathSize {
				return fail(fmt.Errorf("rule %q encoded path must be shorter than %d bytes", rule.Name, KernelPathSize))
			}
			entry.Length = uint32(len(pattern))
			copy(entry.Path[:], pattern)
			if rule.Action == "deny" {
				entry.Deny = 1
			}
			entries[0].Count++
			entries[entries[0].Count] = entry
		}
	}
	return entries, nil
}
