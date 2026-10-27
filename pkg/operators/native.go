// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package operators

const (
	// NativeResourcesKey exposes a compact pre-load resource manifest, never BTF,
	// instructions or write authority. It is local-only, not the remote API.
	NativeResourcesKey     = "ebpf/native-resources"
	NativeAttachmentPrefix = "attachment/"
)

type NativeMapResource struct {
	Type, KeySize, ValueSize, MaxEntries, Flags uint32
}
type NativeProgramResource struct {
	Type   uint32
	Target string
	// Conservative encoded instruction count (LD_IMM64 occupies two words).
	Instructions uint64
}
type NativeResources struct {
	Maps     map[string]NativeMapResource
	Programs map[string]NativeProgramResource
}

// NativeAttachment is a borrowed, live receipt, not an owned link. Check fails
// when the linked program is gone/changed. Callers must join checks before Stop;
// they must not infer hook presence from image metadata or a loaded program FD.
type NativeAttachment struct {
	Type   uint32
	Target string
	Check  func() error
}
