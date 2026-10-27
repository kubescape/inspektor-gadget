// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package fullpolicy defines the complete, runtime-independent exec contract.
// It is not a kernel capability declaration: a backend must validate all required
// capabilities before installing a compiled policy.
package fullpolicy

import (
	"fmt"
	"math"
	"path"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	MaxPolicies      = 8
	MaxRules         = 256
	MaxPatterns      = 1024
	MaxValues        = 256
	MaxStringBytes   = 255
	MaxAncestorDepth = 16
	MaxArgc          = 64
	MaxArgBytes      = 4096
)

type Mode string

const (
	Audit   Mode = "audit"
	Enforce Mode = "enforce"
)

type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

type Policy struct {
	ID       string
	Revision string
	Mode     Mode
	RootRole string
	Default  Action // Empty means that no exec section default was authored.
	Rules    []Rule
}
type Rule struct {
	Name   string
	Origin string
	Action Action
	Mode   Mode
	Actor  Actor
	Target Target
}
type Actor struct {
	Path      []string
	FromImage *bool
	Ancestor  *Ancestor
	Role      []string
	UID       []int64
	Container []string
}
type Ancestor struct {
	Path  []string
	Depth int32
}
type Target struct {
	Path      []string
	FromImage *bool
	FSType    []string
	Argv      *Argv
	SetRole   string
}
type Argv struct {
	Contains, Prefix []string
	StdinIsPipe      *bool
}

type compiledRule struct {
	source                  Rule
	actor, target, ancestor []*regexp.Regexp
}
type compiledPolicy struct {
	source Policy
	rules  []compiledRule
}
type Program struct{ policies []compiledPolicy }

// Compile validates the entire immutable candidate, without retaining caller-owned
// slices/pointers. List order has no effect on matching or verdict precedence.
func Compile(policies []Policy) (*Program, error) {
	if len(policies) == 0 || len(policies) > MaxPolicies {
		return nil, fmt.Errorf("require 1..%d policies", MaxPolicies)
	}
	p := &Program{}
	ids := map[string]bool{}
	rules, patterns := 0, 0
	for _, policy := range policies {
		if policy.ID == "" || policy.Revision == "" || ids[policy.ID] {
			return nil, fmt.Errorf("policy identity/revision must be nonempty and identity unique")
		}
		ids[policy.ID] = true
		if err := validateString(policy.ID); err != nil {
			return nil, err
		}
		if err := validateString(policy.Revision); err != nil {
			return nil, err
		}
		if policy.Mode != Audit && policy.Mode != Enforce {
			return nil, fmt.Errorf("policy %s: invalid mode", policy.ID)
		}
		if policy.Default != "" && policy.Default != Allow && policy.Default != Deny {
			return nil, fmt.Errorf("policy %s: invalid default", policy.ID)
		}
		if policy.RootRole == "" {
			policy.RootRole = "agent"
		}
		if err := validateString(policy.RootRole); err != nil {
			return nil, err
		}
		cp := compiledPolicy{source: policy}
		cp.source.Rules = nil
		names := map[string]bool{}
		for _, r := range policy.Rules {
			rules++
			if rules > MaxRules {
				return nil, fmt.Errorf("exec rule capacity exceeds %d", MaxRules)
			}
			if r.Name == "" || names[r.Name] {
				return nil, fmt.Errorf("rule name must be nonempty and unique")
			}
			names[r.Name] = true
			if err := validateString(r.Name); err != nil {
				return nil, err
			}
			if r.Origin != "" {
				if err := validateString(r.Origin); err != nil {
					return nil, err
				}
			}
			if r.Action != Allow && r.Action != Deny {
				return nil, fmt.Errorf("rule %s: invalid action", r.Name)
			}
			if r.Mode != "" && r.Mode != Audit && r.Mode != Enforce {
				return nil, fmt.Errorf("rule %s: invalid mode", r.Name)
			}
			if r.Target.SetRole != "" {
				if r.Action != Allow {
					return nil, fmt.Errorf("rule %s: setRole requires allow", r.Name)
				}
				if err := validateString(r.Target.SetRole); err != nil {
					return nil, err
				}
			}
			cr := compiledRule{source: r}
			var err error
			cr.source.Actor.FromImage = cloneBool(r.Actor.FromImage)
			cr.source.Target.FromImage = cloneBool(r.Target.FromImage)
			cr.actor, err = compilePaths(r.Actor.Path, &patterns)
			if err != nil {
				return nil, fmt.Errorf("rule %s actor: %w", r.Name, err)
			}
			cr.target, err = compilePaths(r.Target.Path, &patterns)
			if err != nil {
				return nil, fmt.Errorf("rule %s target: %w", r.Name, err)
			}
			cr.source.Actor.Path = append([]string(nil), r.Actor.Path...)
			cr.source.Target.Path = append([]string(nil), r.Target.Path...)
			cr.source.Actor.Role, err = cloneStrings(r.Actor.Role)
			if err != nil {
				return nil, err
			}
			cr.source.Actor.Container, err = cloneStrings(r.Actor.Container)
			if err != nil {
				return nil, err
			}
			cr.source.Target.FSType, err = cloneStrings(r.Target.FSType)
			if err != nil {
				return nil, err
			}
			for _, kind := range cr.source.Target.FSType {
				if !fileType(kind) {
					return nil, fmt.Errorf("unknown filesystem class %q", kind)
				}
			}
			if len(r.Actor.UID) > MaxValues {
				return nil, fmt.Errorf("UID list exceeds %d", MaxValues)
			}
			cr.source.Actor.UID = append([]int64(nil), r.Actor.UID...)
			for _, uid := range r.Actor.UID {
				if uid < 0 || uid > math.MaxUint32 {
					return nil, fmt.Errorf("effective UID is out of range")
				}
			}
			if a := r.Actor.Ancestor; a != nil {
				if a.Depth < 1 || a.Depth > MaxAncestorDepth || len(a.Path) == 0 {
					return nil, fmt.Errorf("ancestor requires paths and depth 1..%d", MaxAncestorDepth)
				}
				cr.ancestor, err = compilePaths(a.Path, &patterns)
				if err != nil {
					return nil, err
				}
				cr.source.Actor.Ancestor = &Ancestor{Depth: a.Depth, Path: append([]string(nil), a.Path...)}
			}
			if a := r.Target.Argv; a != nil {
				contains, e := cloneStrings(a.Contains)
				if e != nil {
					return nil, e
				}
				prefix, e := cloneStrings(a.Prefix)
				if e != nil {
					return nil, e
				}
				if len(contains) == 0 && len(prefix) == 0 && a.StdinIsPipe == nil {
					return nil, fmt.Errorf("empty argv predicate")
				}
				cr.source.Target.Argv = &Argv{Contains: contains, Prefix: prefix, StdinIsPipe: cloneBool(a.StdinIsPipe)}
			}
			cp.rules = append(cp.rules, cr)
		}
		p.policies = append(p.policies, cp)
	}
	sort.Slice(p.policies, func(i, j int) bool { return p.policies[i].source.ID < p.policies[j].source.ID })
	return p, nil
}
func cloneBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	c := *b
	return &c
}
func validateString(s string) error {
	if s == "" || len(s) > MaxStringBytes || strings.ContainsRune(s, 0) || !utf8.ValidString(s) {
		return fmt.Errorf("string must contain 1..%d non-NUL bytes", MaxStringBytes)
	}
	return nil
}
func cloneStrings(in []string) ([]string, error) {
	if len(in) > MaxValues {
		return nil, fmt.Errorf("list capacity exceeds %d", MaxValues)
	}
	for _, s := range in {
		if err := validateString(s); err != nil {
			return nil, err
		}
	}
	return append([]string(nil), in...), nil
}
func compilePaths(in []string, total *int) ([]*regexp.Regexp, error) {
	if len(in) > MaxValues {
		return nil, fmt.Errorf("path list exceeds %d", MaxValues)
	}
	result := make([]*regexp.Regexp, 0, len(in))
	for _, s := range in {
		*total++
		if *total > MaxPatterns {
			return nil, fmt.Errorf("pattern capacity exceeds %d", MaxPatterns)
		}
		if err := validateString(s); err != nil {
			return nil, err
		}
		if !path.IsAbs(s) {
			return nil, fmt.Errorf("path must be absolute")
		}
		re, err := glob(s)
		if err != nil {
			return nil, err
		}
		result = append(result, re)
	}
	return result, nil
}

// glob uses pathname semantics: '*' and '?' do not cross '/', '**' does.
// Character classes follow path.Match, including negation and ranges. Rejecting
// malformed patterns is mandatory; they cannot become unconstrained predicates.
func glob(pattern string) (*regexp.Regexp, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, fmt.Errorf("malformed glob %q: %w", pattern, err)
	}
	chars := []rune(pattern)
	var b strings.Builder
	b.WriteString("\\A(?s:")
	for i := 0; i < len(chars); i++ {
		switch c := chars[i]; c {
		case '*':
			if i+1 < len(chars) && chars[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			var classPattern strings.Builder
			classPattern.WriteByte('[')
			i++
			if chars[i] == '^' {
				classPattern.WriteByte('^')
				i++
			}
			for chars[i] != ']' {
				if chars[i] == '\\' {
					i++
					fmt.Fprintf(&classPattern, "\\x{%x}", chars[i])
				} else if chars[i] == '-' {
					classPattern.WriteByte('-')
				} else {
					fmt.Fprintf(&classPattern, "\\x{%x}", chars[i])
				}
				i++
			}
			classPattern.WriteByte(']')
			// Expand classes once using path.Match class semantics.
			// Canonicalize path.Match escapes before parsing:
			// [\\d] contains literal d, not a regexp digit shorthand.
			class, err := syntax.Parse(classPattern.String(), syntax.Perl)
			if err != nil {
				return nil, fmt.Errorf("malformed glob %q: %w", pattern, err)
			}
			var ranges []rune
			if class.Op == syntax.OpLiteral {
				for _, r := range class.Rune {
					ranges = append(ranges, r, r)
				}
			} else if class.Op == syntax.OpCharClass {
				ranges = class.Rune
			} else {
				return nil, fmt.Errorf("unsupported character class")
			}
			b.WriteByte('[')
			written := false
			for j := 0; j < len(ranges); j += 2 {
				lo, hi := ranges[j], ranges[j+1]
				emit := func(a, z rune) {
					if a > z {
						return
					}
					fmt.Fprintf(&b, "\\x{%x}-\\x{%x}", a, z)
					written = true
				}
				emit(lo, hi)
			}
			// Defensive representation for an empty class.
			if !written {
				b.WriteString("^\\x{0}-\\x{10ffff}")
			}
			b.WriteByte(']')
		case '\\':
			i++
			b.WriteString(regexp.QuoteMeta(string(chars[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(")\\z")
	r, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("malformed glob %q: %w", pattern, err)
	}
	return r, nil
}
