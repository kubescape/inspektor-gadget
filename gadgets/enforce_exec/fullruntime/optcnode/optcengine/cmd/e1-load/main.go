// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// e1-load loads (and attaches) each option C engine variant once and reports
// whether the verifier accepted it. TEST-ONLY.
package main

import (
	"fmt"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/optcengine"
)

func main() {
	rc := 0
	for _, product := range []bool{true, false} {
		v := map[bool]string{true: "product", false: "test"}[product]
		e, err := optcengine.Load(optcengine.Options{Product: product})
		if err != nil {
			fmt.Printf("VARIANT %s LOAD FAIL\n%v\n", v, err)
			rc = 1
			continue
		}
		fmt.Printf("VARIANT %s LOAD OK\n", v)
		e.Close()
	}
	os.Exit(rc)
}
