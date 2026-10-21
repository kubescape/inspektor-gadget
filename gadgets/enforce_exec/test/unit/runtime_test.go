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
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"

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
	newContext := func(t *testing.T, allow bool) *gadgetcontext.GadgetContext {
		t.Helper()
		handler := ocihandler.New()
		params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
		if err := params.Set("verify-image", "false"); err != nil {
			t.Fatal(err)
		}
		if allow {
			if err := params.Set("allow-enforcement", "true"); err != nil {
				t.Fatal(err)
			}
		}
		if err := handler.Init(params); err != nil {
			t.Fatal(err)
		}
		return gadgetcontext.New(ctx, image, gadgetcontext.WithDataOperators(handler), gadgetcontext.WithOrasReadonlyTarget(store))
	}
	runtime := local.New()
	// Skip root-only Runtime.Init and use an image with just the actual WASM
	// layer. Admission and lifecycle execute normally; no BPF is installed.
	t.Run("admission-default-denied", func(t *testing.T) {
		err := runtime.RunGadget(newContext(t, false), nil, map[string]string{"operator.oci.wasm.exec-policy": string(policy)})
		if err == nil || !strings.Contains(err.Error(), "requires operator.oci.allow-enforcement=true") {
			t.Fatalf("expected enforcement admission denial, got %v", err)
		}
	})
	gadgetCtx := newContext(t, true)
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
	// A valid policy reaches gadgetStart, where the deliberately absent BPF
	// bindings map must fail startup instead of advertising enforcement.
	err = runtime.RunGadget(newContext(t, true), nil, map[string]string{"operator.oci.wasm.exec-policy": string(policy)})
	if err == nil || !strings.Contains(err.Error(), "gadgetStart failed") {
		t.Fatalf("expected failure from actual guest start hook without BPF maps, got %v", err)
	}
}
