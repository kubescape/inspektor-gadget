// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Facts are authoritative inputs for the pure reference evaluator. Nil pointers
// mean unknown, not false. A kernel implementation must acquire the same facts at
// the pre-exec hook; syscall-entry userspace snapshots are not equivalent.
type Facts struct {
	ActorPath         string
	ActorFromImage    *bool
	Ancestors         []string          // immediate parent first; completeness checked against depth
	AncestorsComplete bool              // true when traversal reached its genuine root
	Roles             map[string]string // policy ID -> inherited role; absence means root bootstrap
	// RoleBootstrap is proof from the backend that this is the policy root task;
	// it must not be used to hide map loss or missing inherited state.
	RoleBootstrap   bool
	EffectiveUID    *uint32
	Container       string
	TargetPath      string
	TargetFromImage *bool
	FSType          string
	// FSType and FileKinds contain known-positive simultaneous classes.
	// Missing positives do not prove false. FileKindsKnown explicitly lists
	// classes with authoritative true/false observations. Positives are known.
	FileKinds      []string
	FileKindsKnown []string
	Argv           []string
	ArgvComplete   bool
	StdinIsPipe    *bool
}
type Match struct {
	PolicyID, Revision, Rule, Origin string
	Action                           Action
	Mode                             Mode
}
type Decision struct {
	Action  Action // semantic deny, including audit-only denies
	Mode    Mode   // strongest denying mode, or audit for an allowed decision
	Block   bool
	Matches []Match
	// Role updates are policy-local and must be committed only on successful exec.
	SetRoles map[string]string
}

// Evaluate is a reference oracle for kernel parity tests, not a userspace
// enforcement fallback. Unknown required facts fail evaluation, never match false.
func (p *Program) Evaluate(f Facts) (Decision, error) {
	for _, v := range append([]string{f.ActorPath, f.TargetPath}, f.Ancestors...) {
		if len(v) > MaxStringBytes || strings.ContainsRune(v, 0) || !utf8.ValidString(v) {
			return Decision{}, fmt.Errorf("path observation invalid or exceeds %d bytes", MaxStringBytes)
		}
	}
	d := Decision{Action: Allow, Mode: Audit, SetRoles: map[string]string{}}
	matched := false
	allowMode, denyMode := Audit, Audit
	for _, policy := range p.policies {
		ps := policy.source
		role := f.Roles[ps.ID]
		if role == "" && f.RoleBootstrap {
			role = ps.RootRole
		}
		roles := map[string]bool{}
		for _, rule := range policy.rules {
			ok, err := rule.matches(f, role)
			if err != nil {
				return Decision{}, fmt.Errorf("policy %s rule %s: %w", ps.ID, rule.source.Name, err)
			}
			if !ok {
				continue
			}
			matched = true
			r := rule.source
			mode := r.Mode
			if mode == "" {
				mode = ps.Mode
			}
			d.Matches = append(d.Matches, Match{PolicyID: ps.ID, Revision: ps.Revision, Rule: r.Name, Origin: r.Origin, Action: r.Action, Mode: mode})
			if r.Action == Deny {
				d.Action = Deny
				if mode == Enforce {
					denyMode = Enforce
					d.Block = true
				}
			} else {
				if mode == Enforce {
					allowMode = Enforce
				}
				if r.Target.SetRole != "" {
					roles[r.Target.SetRole] = true
				}
			}
		}
		if len(roles) > 1 {
			return Decision{}, fmt.Errorf("policy %s: overlapping allows assign conflicting roles", ps.ID)
		}
		for role := range roles {
			d.SetRoles[ps.ID] = role
		}
	}
	// Defaults merge strictly, but are consulted only when the entire merged rule
	// union has no match. A default deny in one policy cannot shadow another's allow.
	if !matched {
		for _, policy := range p.policies {
			ps := policy.source
			if ps.Default != Deny {
				if ps.Default == Allow && ps.Mode == Enforce {
					allowMode = Enforce
				}
				continue
			}
			d.Action = Deny
			if ps.Mode == Enforce {
				denyMode = Enforce
				d.Block = true
			}
			d.Matches = append(d.Matches, Match{PolicyID: ps.ID, Revision: ps.Revision, Action: Deny, Mode: ps.Mode})
		}
	}
	if d.Action == Deny {
		d.Mode = denyMode
		clear(d.SetRoles)
	} else {
		d.Mode = allowMode
	}
	slices.SortFunc(d.Matches, func(a, b Match) int {
		if n := strings.Compare(a.PolicyID, b.PolicyID); n != 0 {
			return n
		}
		return strings.Compare(a.Rule, b.Rule)
	})
	return d, nil
}
func (r compiledRule) matches(f Facts, role string) (bool, error) {
	a, t := r.source.Actor, r.source.Target
	if len(r.actor) > 0 {
		if f.ActorPath == "" {
			return false, fmt.Errorf("actor executable unavailable")
		}
		if !pathMatches(r.actor, f.ActorPath) {
			return false, nil
		}
	}
	if len(r.target) > 0 {
		if f.TargetPath == "" {
			return false, fmt.Errorf("target executable unavailable")
		}
		if !pathMatches(r.target, f.TargetPath) {
			return false, nil
		}
	}
	if len(a.Role) > 0 {
		if role == "" {
			return false, fmt.Errorf("inherited role unavailable")
		}
		if !slices.Contains(a.Role, role) {
			return false, nil
		}
	}
	if len(a.Container) > 0 {
		if f.Container == "" {
			return false, fmt.Errorf("container name unavailable")
		}
		if !slices.Contains(a.Container, f.Container) {
			return false, nil
		}
	}
	if len(a.UID) > 0 {
		if f.EffectiveUID == nil {
			return false, fmt.Errorf("effective UID unavailable")
		}
		if !slices.Contains(a.UID, int64(*f.EffectiveUID)) {
			return false, nil
		}
	}
	if a.FromImage != nil {
		if f.ActorFromImage == nil {
			return false, fmt.Errorf("actor image provenance unavailable")
		}
		if *a.FromImage != *f.ActorFromImage {
			return false, nil
		}
	}
	if t.FromImage != nil {
		if f.TargetFromImage == nil {
			return false, fmt.Errorf("target image provenance unavailable")
		}
		if *t.FromImage != *f.TargetFromImage {
			return false, nil
		}
	}
	if len(t.FSType) > 0 {
		found, unknown := false, false
		for _, kind := range t.FSType {
			positive := kind == f.FSType || slices.Contains(f.FileKinds, kind)
			found = found || positive
			unknown = unknown || (!positive && !slices.Contains(f.FileKindsKnown, kind))
		}
		// OR accepts a known positive even if another class is unknown.
		if !found {
			if unknown {
				return false, fmt.Errorf("target filesystem classification unavailable")
			}
			return false, nil
		}
	}
	if a.Ancestor != nil {
		depth := int(a.Ancestor.Depth)
		found := false
		for i, path := range f.Ancestors {
			if i >= depth {
				break
			}
			if path == "" {
				return false, fmt.Errorf("ancestor executable unavailable")
			}
			if pathMatches(r.ancestor, path) {
				found = true
				break
			}
		}
		if !found {
			if len(f.Ancestors) < depth && !f.AncestorsComplete {
				return false, fmt.Errorf("ancestor traversal incomplete")
			}
			return false, nil
		}
	}
	if a := t.Argv; a != nil {
		if len(a.Contains) > 0 || len(a.Prefix) > 0 {
			if !f.ArgvComplete || len(f.Argv) > MaxArgc {
				return false, fmt.Errorf("staged argv incomplete or oversized")
			}
			size := 0
			for _, arg := range f.Argv {
				if strings.ContainsRune(arg, 0) {
					return false, fmt.Errorf("invalid staged argument")
				}
				size += len(arg) + 1
			}
			if size > MaxArgBytes {
				return false, fmt.Errorf("staged argv exceeds %d bytes", MaxArgBytes)
			}
			// Lists are alternatives. Contains matches a complete argument, prefix matches
			// the beginning of an argument (not a lossy space-joined command line).
			if len(a.Contains) > 0 {
				found := false
				for _, v := range a.Contains {
					if slices.Contains(f.Argv, v) {
						found = true
						break
					}
				}
				if !found {
					return false, nil
				}
			}
			if len(a.Prefix) > 0 {
				found := false
				for _, v := range a.Prefix {
					for _, arg := range f.Argv {
						if strings.HasPrefix(arg, v) {
							found = true
							break
						}
					}
				}
				if !found {
					return false, nil
				}
			}
		}
		if a.StdinIsPipe != nil {
			if f.StdinIsPipe == nil {
				return false, fmt.Errorf("stdin identity unavailable")
			}
			if *a.StdinIsPipe != *f.StdinIsPipe {
				return false, nil
			}
		}
	}
	return true, nil
}
func pathMatches(patterns []*regexp.Regexp, s string) bool {
	for _, p := range patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}
