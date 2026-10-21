// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	policy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	raw, err := api.GetParamValue(policy.ParameterName, uint64(policy.DefaultLimits().MaxBytes+1))
	if err != nil {
		api.Errorf("enforce_exec: reading %s: %v", policy.ParameterName, err)
		return 1
	}
	prepared, err := policy.Prepare(raw)
	if err != nil {
		api.Errorf("enforce_exec: invalid policy: %v", err)
		return 1
	}
	api.Infof("enforce_exec: validated policy %s (%d rules); not attached", prepared.Hash(), prepared.RuleCount())
	if err := prepared.Start(); err != nil {
		api.Errorf("%v", err)
		return 1
	}
	return 0
}

func main() {}
