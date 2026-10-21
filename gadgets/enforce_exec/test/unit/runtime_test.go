// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package unit_test

import (
	"bytes"
	"context"
	"encoding/json"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"

	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// runThroughIG uses the real OCI handler, WASM operator and local runtime, with
// an in-memory image store so no privileged /var/lib/ig access is necessary.
func runThroughIG(t *testing.T, wasm, metadata, policy []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := memory.New()
	push := func(media string, data []byte) ocispec.Descriptor {
		d := content.NewDescriptorFromBytes(media, data)
		if err := store.Push(ctx, d, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		return d
	}
	cfg := push("application/vnd.gadget.config.v1+yaml", metadata)
	layer := push("application/vnd.gadget.wasm.program.v1+binary", wasm)
	manifest := ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: cfg, Layers: []ocispec.Descriptor{layer}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	desc := push(ocispec.MediaTypeImageManifest, data)
	desc.Platform = &ocispec.Platform{Architecture: goruntime.GOARCH, OS: "linux"}
	index := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}}
	data, err = json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	desc = push(ocispec.MediaTypeImageIndex, data)
	const image = "ghcr.io/inspektor-gadget/gadget/enforce_exec:spike"
	if err := store.Tag(ctx, desc, image); err != nil {
		t.Fatal(err)
	}
	gadgetCtx := gadgetcontext.New(ctx, image, gadgetcontext.WithDataOperators(ocihandler.OciHandler), gadgetcontext.WithOrasReadonlyTarget(store))
	runtime := local.New()
	// Skip local Runtime.Init: it requires root for BPF even for a WASM-only
	// image. Exercise the real RunGadget/OCI/WASM path without BPF setup.
	// Inspection must expose the real parameter without trying to start enforcement.
	_, err = runtime.GetGadgetInfo(gadgetCtx, nil, nil)
	if err != nil {
		t.Fatalf("gadget inspection: %v", err)
	}
	found := false
	for _, p := range gadgetCtx.Params() {
		if p.Key == "exec-policy" && p.IsMandatory {
			found = true
		}
	}
	if !found {
		t.Fatal("OCI metadata did not expose mandatory exec-policy")
	}
	// Use a fresh context for execution, as normal run does after inspection.
	gadgetCtx = gadgetcontext.New(ctx, image, gadgetcontext.WithDataOperators(ocihandler.OciHandler), gadgetcontext.WithOrasReadonlyTarget(store))
	err = runtime.RunGadget(gadgetCtx, nil, map[string]string{"operator.oci.wasm.exec-policy": string(policy)})
	if err == nil || !strings.Contains(err.Error(), "gadgetPreStart failed") {
		t.Fatalf("expected failure from actual guest pre-start hook, got %v", err)
	}
}
