// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Command btfshape prints the BTF shape fingerprint (005 §8) of an engine
// object on a kernel, for recording in a family's qualification record.
//
//	btfshape -object optc_product_bpfel.o [-btf /sys/kernel/btf/vmlinux] [-v]
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/admission"
)

func main() {
	object := flag.String("object", "", "engine object")
	btfPath := flag.String("btf", "/sys/kernel/btf/vmlinux", "kernel BTF")
	verbose := flag.Bool("v", false, "list the dependencies")
	flag.Parse()
	if err := run(*object, *btfPath, *verbose); err != nil {
		fmt.Fprintln(os.Stderr, "btfshape:", err)
		os.Exit(1)
	}
}

func run(object, btfPath string, verbose bool) error {
	obj, err := os.ReadFile(object)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(btfPath)
	if err != nil {
		return err
	}
	kernel, err := btf.LoadSpec(btfPath)
	if err != nil {
		return err
	}
	fp, err := admission.Fingerprint(obj, kernel)
	if err != nil {
		return err
	}
	types, hooks, err := admission.Dependencies(obj)
	if err != nil {
		return err
	}
	osr := map[string]string{}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				osr[k] = strings.Trim(v, `"`)
			}
		}
	}
	release, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	os2 := sha256.Sum256(obj)
	bs := sha256.Sum256(raw)
	out := map[string]any{
		"release":       strings.TrimSpace(string(release)),
		"os_id":         osr["ID"],
		"os_version":    osr["VERSION_ID"],
		"btf_sha256":    hex.EncodeToString(bs[:]),
		"object_sha256": hex.EncodeToString(os2[:]),
		"fingerprint":   fp,
		"types":         len(types),
		"hooks":         hooks,
	}
	if verbose {
		out["type_names"] = types
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(out)
}
