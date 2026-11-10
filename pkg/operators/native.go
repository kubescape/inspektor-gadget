// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package operators

const (
	// NativeResourcesKey exposes a compact pre-load resource manifest, never BTF,
	// instructions or write authority. It is local-only, not the remote API.
	NativeResourcesKey = "ebpf/native-resources"
	// NativeOwnerRequiredKey marks local native-owner use before OCI layer
	// instantiation, including when the image omits its required ABI annotation.
	// Such images must contain exactly one eBPF layer and no executable guests.
	NativeOwnerRequiredKey = "ebpf/native-owner-required"
	// NativeResourceValidatorKey holds a local func(*NativeResources) error.
	// Native owners install it before Start; the eBPF operator invokes it on the
	// final transformed collection immediately before allocating kernel resources.
	NativeResourceValidatorKey = "ebpf/native-resource-validator"
	// NativeRecoveryTestRunKey is a trusted local opt-in for the two recovery
	// SchedCLS programs that must be loaded for TEST_RUN, never attached to TC.
	// The native resource validator must still admit the exact recovered image.
	NativeRecoveryTestRunKey = "ebpf/native-recovery-test-run"
	NativeAttachmentPrefix   = "attachment/"
	// NativeLoadedProgramPrefix borrows every program in the exact admitted
	// recovered collection for H's pin/FD ledger. It is not an invocation
	// permission and is absent for ordinary or protocol-only images.
	NativeLoadedProgramPrefix = "ebpf/native-loaded-program/"
)

type NativeMapResource struct {
	Type, KeySize, ValueSize, MaxEntries, Flags uint32
	// InnerMap describes the separately allocated map-of-maps template.
	InnerMap *NativeMapResource
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
// when the exact link identity, type or linked program changes. IDs are
// diagnostic evidence, not authority to reopen or pin a link. Callers must
// join checks before Stop; image metadata or a loaded program FD is not proof
// of hook presence.
type NativeAttachment struct {
	Type, LinkID, ProgramID uint32
	Target                  string
	Check                   func() error
	// PinAt is present only on admitted recovery task LSM links. dirFD must
	// reference a private, host-visible bpffs directory. A successful pin is
	// retained on later errors; the future S pin ledger owns unlinking.
	PinAt func(dirFD int) (NativePinnedLink, error)
}

// NativePinnedLink owns a reopened link FD, not the pin itself. Close releases
// that FD but leaves the bpffs pin intact. PinName is a fixed basename for S.
type NativePinnedLink interface {
	FD() int
	PinName() string
	Check() error
	Close() error
}
