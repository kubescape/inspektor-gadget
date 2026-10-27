// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// ValidateKernelProgram checks the public compiled-data boundary before any map
// write or binding. It does not attest kernel capabilities or original authoring
// provenance. All referenced objects, bytecode and metadata are validated; no
// partial program is usable on failure.
func ValidateKernelProgram(p *KernelProgram) error {
	if p == nil || len(p.Entries) < KernelRuleBase || len(p.Entries) > MaxKernelEntries {
		return fmt.Errorf("invalid full program entry budget")
	}
	h, err := Decode[KernelHeader](p.Entries[0])
	if err != nil {
		return err
	}
	if h.Generation == 0 || h.Generation == UnknownRoleEpoch || h.PolicyCount == 0 || h.PolicyCount > MaxPolicies || h.RuleBase != KernelRuleBase || h.RuleCount > MaxRules || uint64(h.RuleBase)+uint64(h.RuleCount) > uint64(len(p.Entries)) || !zero(h.Padding[:]) {
		return fmt.Errorf("invalid full header")
	}
	if len(p.Rules) != int(h.RuleCount) {
		return fmt.Errorf("rule metadata count mismatch")
	}
	if len(p.Identities) == 0 || len(p.Identities) > MaxKernelEntries+2*MaxPolicies {
		return fmt.Errorf("invalid identity registry budget")
	}
	for hash, name := range p.Identities {
		if err := validateString(name); err != nil {
			return err
		}
		if hash == 0 || stableHash(name) != hash {
			return fmt.Errorf("invalid stable identity hash")
		}
	}
	v := programValidator{p: p, code: map[uint32]bool{}, policy: make([]KernelPolicy, h.PolicyCount), names: map[string]bool{}, revisions: map[uint32]string{}}
	if err := v.stringAt(h.ContainerRef); err != nil {
		return fmt.Errorf("container: %w", err)
	}
	for i := uint32(0); i < MaxPolicies; i++ {
		b := p.Entries[KernelPolicyBase+i]
		if i >= h.PolicyCount {
			if !zero(b[:]) {
				return fmt.Errorf("unused policy slot is not zero")
			}
			continue
		}
		policy, err := Decode[KernelPolicy](b)
		if err != nil {
			return err
		}
		if policy.UID == 0 || policy.RootRole == 0 || policy.RootEpoch == 0 || policy.RootEpoch > h.Generation || policy.Default > 2 || policy.Mode < 1 || policy.Mode > 2 || !zero(policy.Padding[:]) {
			return fmt.Errorf("invalid policy entry")
		}
		if err = v.identity(policy.UID); err != nil {
			return err
		}
		if err = v.identity(policy.RootRole); err != nil {
			return err
		}
		for j := uint32(0); j < i; j++ {
			if v.policy[j].UID == policy.UID {
				return fmt.Errorf("duplicate policy UID")
			}
		}
		v.policy[i] = policy
	}
	for i := uint32(0); i < h.RuleCount; i++ {
		rule, err := Decode[KernelRule](p.Entries[h.RuleBase+i])
		if err != nil {
			return err
		}
		if rule.PolicyIndex >= h.PolicyCount || rule.Mode < 1 || rule.Mode > 2 || rule.Deny > 1 || !validTri(rule.ActorImage) || !validTri(rule.TargetImage) || !validTri(rule.Stdin) || rule.AncestorDepth > MaxAncestorDepth || rule.Reserved != 0 || !zero(rule.Padding[:]) {
			return fmt.Errorf("invalid rule %d scalars", i)
		}
		if (rule.AncestorDepth == 0) != (rule.AncestorPath.Count == 0) {
			return fmt.Errorf("ancestor depth/list mismatch")
		}
		if rule.SetRole != 0 {
			if rule.Deny != 0 {
				return fmt.Errorf("deny assigns role")
			}
			if err = v.identity(rule.SetRole); err != nil {
				return err
			}
		}
		for _, list := range []KernelList{rule.ActorPath, rule.TargetPath, rule.AncestorPath} {
			if err = v.list(list, "pattern"); err != nil {
				return fmt.Errorf("rule %d: %w", i, err)
			}
		}
		if err = v.list(rule.ActorRole, "identity"); err != nil {
			return err
		}
		if err = v.list(rule.UID, "uid"); err != nil {
			return err
		}
		for _, list := range []KernelList{rule.Container, rule.ArgContains, rule.ArgPrefix} {
			if err = v.list(list, "string"); err != nil {
				return err
			}
		}
		if err = v.list(rule.FSType, "filesystem"); err != nil {
			return err
		}
		meta := p.Rules[i]
		if meta.PolicyIndex != rule.PolicyIndex || stableHash(meta.PolicyID) != v.policy[rule.PolicyIndex].UID || p.Identities[v.policy[rule.PolicyIndex].UID] != meta.PolicyID {
			return fmt.Errorf("rule policy metadata mismatch")
		}
		for _, s := range []string{meta.PolicyID, meta.Revision, meta.Name} {
			if err = validateString(s); err != nil {
				return err
			}
		}
		if meta.Origin != "" {
			if err = validateString(meta.Origin); err != nil {
				return err
			}
		}
		key := fmt.Sprintf("%d/%s", rule.PolicyIndex, meta.Name)
		if v.names[key] {
			return fmt.Errorf("duplicate rule name")
		}
		v.names[key] = true
		if previous := v.revisions[rule.PolicyIndex]; previous != "" && previous != meta.Revision {
			return fmt.Errorf("inconsistent policy revisions")
		}
		v.revisions[rule.PolicyIndex] = meta.Revision
	}
	return nil
}

func zero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
func validTri(v int32) bool { return v >= -1 && v <= 1 }

type programValidator struct {
	p         *KernelProgram
	code      map[uint32]bool
	patterns  int
	policy    []KernelPolicy
	names     map[string]bool
	revisions map[uint32]string
}

func (v *programValidator) identity(id uint64) error {
	if _, ok := v.p.Identities[id]; !ok {
		return fmt.Errorf("unregistered identity")
	}
	return nil
}

func (v *programValidator) stringAt(key uint32) error {
	if uint64(key) >= uint64(len(v.p.Entries)) {
		return fmt.Errorf("string reference out of range")
	}
	s, err := Decode[KernelString](v.p.Entries[key])
	if err != nil {
		return err
	}
	if s.Length == 0 || s.Length > MaxStringBytes || !zero(s.Bytes[s.Length:]) || !zero(s.Padding[:]) {
		return fmt.Errorf("invalid string length/padding")
	}
	text := string(s.Bytes[:s.Length])
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return fmt.Errorf("invalid string encoding")
	}
	return nil
}

func (v *programValidator) list(l KernelList, kind string) error {
	if l.Count == 0 {
		if l.Base != 0 {
			return fmt.Errorf("empty list has nonzero reference")
		}
		return nil
	}
	if l.Count > MaxValues || l.Base == 0 || uint64(l.Base)+uint64(l.Count) > uint64(len(v.p.Entries)) {
		return fmt.Errorf("invalid list reference/budget")
	}
	for i := uint32(0); i < l.Count; i++ {
		key := l.Base + i
		switch kind {
		case "string", "filesystem":
			if err := v.stringAt(key); err != nil {
				return err
			}
			if kind == "filesystem" {
				s, _ := Decode[KernelString](v.p.Entries[key])
				if !fileType(string(s.Bytes[:s.Length])) {
					return fmt.Errorf("unknown filesystem class")
				}
			}
		case "identity", "uid":
			val, err := Decode[KernelValue](v.p.Entries[key])
			if err != nil {
				return err
			}
			if !zero(val.Padding[:]) {
				return fmt.Errorf("nonzero value padding")
			}
			if kind == "identity" {
				if err = v.identity(val.Value); err != nil {
					return err
				}
			} else if val.Value > math.MaxUint32 {
				return fmt.Errorf("UID out of range")
			}
		case "pattern":
			if err := v.patternAt(key); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown list kind")
		}
	}
	return nil
}
func fileType(s string) bool { return s == "tmpfs" || s == "memfd" || s == "deleted" || s == "overlay" }
func (v *programValidator) patternAt(key uint32) error {
	v.patterns++
	if v.patterns > MaxPatterns {
		return fmt.Errorf("pattern budget exceeded")
	}
	p, err := Decode[KernelPattern](v.p.Entries[key])
	if err != nil {
		return err
	}
	if p.Count == 0 || p.Count > MaxRegexStates || p.Start >= p.Count || p.CodeBase == 0 || uint64(p.CodeBase)+uint64(p.Count) > uint64(len(v.p.Entries)) || !zero(p.Padding[:]) {
		return fmt.Errorf("invalid pattern descriptor")
	}
	for pc := uint32(0); pc < p.Count; pc++ {
		key := p.CodeBase + pc
		v.code[key] = true
		if len(v.code) > MaxRegexInstructions {
			return fmt.Errorf("instruction budget exceeded")
		}
		inst, err := Decode[KernelInstruction](v.p.Entries[key])
		if err != nil {
			return err
		}
		if !zero(inst.Padding[:]) {
			return fmt.Errorf("instruction padding")
		}
		switch inst.Op {
		case KernelAlt:
			if inst.Out >= p.Count || inst.Arg >= p.Count || inst.Count != 0 {
				return fmt.Errorf("invalid alternate")
			}
		case KernelEmptyWidth:
			if inst.Out >= p.Count || inst.Arg == 0 || inst.Arg & ^uint32(KernelBeginText|KernelEndText) != 0 || inst.Count != 0 {
				return fmt.Errorf("invalid assertion")
			}
		case KernelNop:
			if inst.Out >= p.Count || inst.Arg != 0 || inst.Count != 0 {
				return fmt.Errorf("invalid jump")
			}
		case KernelMatch, KernelFail:
			if inst.Out != 0 || inst.Arg != 0 || inst.Count != 0 {
				return fmt.Errorf("invalid terminal")
			}
		case KernelRune:
			if inst.Out >= p.Count || inst.Arg != 0 || inst.Count == 0 || inst.Count > MaxRuneRanges {
				return fmt.Errorf("invalid rune instruction")
			}
			var end uint32
			for i := uint32(0); i < inst.Count; i++ {
				lo, hi := inst.Ranges[2*i], inst.Ranges[2*i+1]
				if lo > hi || hi > 0x10ffff || (i > 0 && lo <= end) {
					return fmt.Errorf("invalid rune ranges")
				}
				end = hi
			}
		default:
			return fmt.Errorf("invalid opcode")
		}
		used := inst.Count * 2
		if used > 16 {
			return fmt.Errorf("invalid range budget")
		}
		for _, value := range inst.Ranges[used:] {
			if value != 0 {
				return fmt.Errorf("unused range data")
			}
		}
	}
	return nil
}
