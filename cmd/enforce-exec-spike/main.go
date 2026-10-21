// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// enforce-exec-spike exercises policy configuration without enforcing anything.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/enforcement/execpolicy"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("enforce-exec-spike", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	file := flags.String("policy-file", "", "standalone policy YAML (required)")
	replacement := flags.String("replace-policy-file", "", "optional replacement for the same binding")
	limits := execpolicy.DefaultLimits()
	flags.IntVar(&limits.MaxRules, "max-rules", limits.MaxRules, "simulation rule capacity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("--policy-file is required; this command only simulates enforcement")
	}
	fmt.Fprintln(diagnostics, "SIMULATION ONLY: no processes are inspected, no BPF is loaded, no execution is blocked.")
	backend := execpolicy.NewMemoryBackend(limits)
	encoder := json.NewEncoder(output)
	emit := func(kind string, value any) error {
		return encoder.Encode(struct {
			Type  string `json:"type"`
			Value any    `json:"value"`
		}{kind, value})
	}
	if err := emit("capabilities", backend.Capabilities()); err != nil {
		return err
	}
	prepare := func(filename string) (execpolicy.Handle, error) {
		f, err := os.Open(filename)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		d, err := execpolicy.Parse(f, limits)
		if err != nil {
			return 0, err
		}
		return backend.Prepare(d, backend.Inspect().Generation)
	}
	for _, filename := range []string{*file, *replacement} {
		if filename == "" {
			continue
		}
		h, err := prepare(filename)
		if err != nil {
			if outputErr := emit("retained-state", backend.Inspect()); outputErr != nil {
				return outputErr
			}
			return fmt.Errorf("prepare %q: %w", filename, err)
		}
		state, err := backend.Activate(h)
		if err != nil {
			return err
		}
		if err := emit("simulated-state", state); err != nil {
			return err
		}
		for _, executable := range flags.Args() {
			decision, err := backend.Evaluate(executable)
			if err != nil {
				return err
			}
			if err := emit("simulated-verdict", decision); err != nil {
				return err
			}
		}
	}
	if err := backend.Remove(backend.Inspect().Generation); err != nil {
		return err
	}
	return emit("removed-state", backend.Inspect())
}
