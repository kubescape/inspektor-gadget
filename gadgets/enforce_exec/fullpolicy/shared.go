// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"crypto/sha256"
	"fmt"
	"slices"
)

// SharedCompilerABI identifies scope-neutral objects, not legacy KernelProgram
// images. Objects retain local Rule.PolicyIndex=0; the shared evaluator must map
// that index through the whole binding snapshot and evaluate one policy union.
const SharedCompilerABI uint32 = 1

// SharedPolicy is immutable compiler-owned content. It is NOT installable as a
// legacy KernelProgram: generation, observed container and root epoch live in
// the binding snapshot. Verdict provenance is separately retained by each caller;
// compiler-owned authored source is private whole-set admission evidence.
type SharedPolicy struct {
	entries []Blob
	digest  [32]byte
	uid     uint64
	// source is compiler-owned immutable admission provenance, not digest input.
	source *Policy
}

func (p *SharedPolicy) Entries() []Blob {
	if p == nil {
		return nil
	}
	return slices.Clone(p.entries)
}

func (p *SharedPolicy) UID() uint64 {
	if p == nil {
		return 0
	}
	return p.uid
}

func (p *SharedPolicy) Digest() [32]byte {
	if p == nil {
		return [32]byte{}
	}
	return p.digest
}

// Equal checks actual canonical content, not hash equality alone.
func (p *SharedPolicy) Equal(q *SharedPolicy) bool {
	return p != nil && q != nil && p.digest == q.digest && slices.Equal(p.entries, q.entries)
}

// CompileSharedPolicy reuses the complete native compiler/validator. Authored
// container predicates remain in the object; only the observed container is
// removed. No scope epoch or image-readiness authority enters this API.
func CompileSharedPolicy(policy Policy) (*SharedPolicy, error) {
	// Reuse Compile's complete deep-copy contract, including every nested rule
	// predicate. Never retain caller-owned slices/pointers for later admission.
	compiled, err := Compile([]Policy{policy})
	if err != nil {
		return nil, err
	}
	owned := compiled.policies[0]
	source := owned.source
	source.Rules = make([]Rule, len(owned.rules))
	for i, rule := range owned.rules {
		source.Rules[i] = rule.source
	}
	p, err := CompileKernel([]Policy{source}, 1, "shared-object")
	if err != nil {
		return nil, err
	}
	h, err := Decode[KernelHeader](p.Entries[0])
	if err != nil {
		return nil, err
	}
	k, err := Decode[KernelPolicy](p.Entries[KernelPolicyBase])
	if err != nil {
		return nil, err
	}
	// The compiler emits a dedicated observation cell. It remains zero
	// padding so absolute predicate/instruction references need no relocation.
	p.Entries[h.ContainerRef] = Blob{}
	h.Generation = 0
	h.ContainerRef = 0
	k.RootEpoch = 0
	p.Entries[0], err = encode(h)
	if err != nil {
		return nil, err
	}
	p.Entries[KernelPolicyBase], err = encode(k)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte{byte(SharedCompilerABI), 0, 0, 0})
	for i := range p.Entries {
		_, _ = hash.Write(p.Entries[i][:])
	}
	result := &SharedPolicy{entries: p.Entries, uid: k.UID, source: &source}
	copy(result.digest[:], hash.Sum(nil))
	return result, nil
}

type SharedPolicyRef struct {
	Object    *SharedPolicy
	RootEpoch uint64
}

// SharedSnapshot is a native preparation value, not an activation receipt.
// Accepted epochs must come from the exact scope's trusted retained catalogue.
type SharedSnapshot struct {
	ScopeCookie, Generation uint64
	Container               string
	Policies                []SharedPolicyRef
}

func NewSharedSnapshot(scope, generation uint64, container string, refs []SharedPolicyRef) (SharedSnapshot, error) {
	if scope == 0 || scope == UnknownRoleEpoch || generation == 0 || generation == UnknownRoleEpoch || len(refs) == 0 || len(refs) > MaxPolicies {
		return SharedSnapshot{}, fmt.Errorf("invalid shared snapshot identity/count")
	}
	if err := validateString(container); err != nil {
		return SharedSnapshot{}, err
	}
	policies := make([]Policy, len(refs))
	for i, r := range refs {
		if r.Object == nil || r.Object.uid == 0 || r.Object.source == nil || r.RootEpoch == 0 || r.RootEpoch > generation {
			return SharedSnapshot{}, fmt.Errorf("invalid scoped policy epoch")
		}
		for _, prior := range refs[:i] {
			if prior.Object.uid == r.Object.uid {
				return SharedSnapshot{}, fmt.Errorf("duplicate scoped policy UID")
			}
		}
		policies[i] = *r.Object.source
	}
	// Independently compiled objects are not an admission receipt for their
	// union. Run the SAME native compiler over its owned authored inputs so
	// patterns, matcher code, strings/values and all blob budgets remain global.
	// This also preserves whole-set UID/role validation without reconstructing IR.
	if _, err := CompileKernel(policies, generation, container); err != nil {
		return SharedSnapshot{}, fmt.Errorf("shared policy union: %w", err)
	}
	return SharedSnapshot{ScopeCookie: scope, Generation: generation, Container: container, Policies: slices.Clone(refs)}, nil
}
