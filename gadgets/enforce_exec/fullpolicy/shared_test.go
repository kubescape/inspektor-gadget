// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullpolicy

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSharedPolicyScopeNeutral(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "container", Action: Allow, Actor: Actor{Container: []string{"app"}}}}
	a, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("identical content differs")
	}
	legacyBefore, err := CompileKernelWithRoleEpochs([]Policy{p}, 9, "scope-observation", map[string]uint64{p.ID: 3})
	if err != nil {
		t.Fatal(err)
	}
	entries := a.Entries()
	rule, _ := Decode[KernelRule](entries[KernelRuleBase])
	authored, _ := Decode[KernelString](entries[rule.Container.Base])
	if rule.PolicyIndex != 0 || string(authored.Bytes[:authored.Length]) != "app" {
		t.Fatal("authored predicate/index changed")
	}
	legacyAfter, err := CompileKernelWithRoleEpochs([]Policy{p}, 9, "scope-observation", map[string]uint64{p.ID: 3})
	if err != nil || !reflect.DeepEqual(legacyBefore, legacyAfter) {
		t.Fatal("legacy compiler changed", err)
	}
	h, _ := Decode[KernelHeader](entries[0])
	k, _ := Decode[KernelPolicy](entries[1])
	if h.Generation != 0 || h.ContainerRef != 0 || k.RootEpoch != 0 {
		t.Fatal("scope facts embedded")
	}
	entries[1][0] ^= 1
	if !a.Equal(b) {
		t.Fatal("caller mutated immutable object")
	}
	sa, err := NewSharedSnapshot(11, 7, "app", []SharedPolicyRef{{Object: a, RootEpoch: 2}})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := NewSharedSnapshot(12, 9, "sidecar", []SharedPolicyRef{{Object: b, RootEpoch: 8}})
	if err != nil {
		t.Fatal(err)
	}
	if sa.ScopeCookie == sb.ScopeCookie || sa.Policies[0].RootEpoch == sb.Policies[0].RootEpoch || !sa.Policies[0].Object.Equal(sb.Policies[0].Object) {
		t.Fatal("scope/compiled ownership conflated")
	}
	for _, epoch := range []uint64{0, 10, UnknownRoleEpoch} {
		if _, err := NewSharedSnapshot(12, 9, "app", []SharedPolicyRef{{Object: a, RootEpoch: epoch}}); err == nil {
			t.Fatal("invalid epoch admitted")
		}
	}
	p.Rules[0].Action = Deny
	c, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(c) {
		t.Fatal("semantic change deduplicated")
	}
}

func TestSharedPolicyIdentityModeAndUnionCaps(t *testing.T) {
	p := base()
	a, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Policy){func(p *Policy) { p.ID = "other" }, func(p *Policy) { p.Mode = Audit }, func(p *Policy) { p.Default = Deny }, func(p *Policy) { p.RootRole = "other-role" }} {
		q := p
		change(&q)
		b, e := CompileSharedPolicy(q)
		if e != nil {
			t.Fatal(e)
		}
		if a.Equal(b) {
			t.Fatal("distinct identity/semantics deduplicated")
		}
	}
	q := p
	q.Revision = "next-provenance"
	b, err := CompileSharedPolicy(q)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("revision provenance entered object")
	}
	if _, err := NewSharedSnapshot(1, 1, "app", []SharedPolicyRef{{a, 1}, {a, 1}}); err == nil {
		t.Fatal("duplicate UID")
	}
	p.Rules = make([]Rule, 129)
	for i := range p.Rules {
		p.Rules[i] = Rule{Name: fmt.Sprint(i), Action: Allow}
	}
	a, err = CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = "other"
	b, err = CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSharedSnapshot(1, 1, "app", []SharedPolicyRef{{a, 1}, {b, 1}}); err == nil {
		t.Fatal("union exceeded 256 rules")
	}
}
