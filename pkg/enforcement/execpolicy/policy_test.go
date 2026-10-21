// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

const fixture = `version: 1
binding:
  container:
    runtime: containerd
    id: container-123
policy:
  mode: enforce
  exec:
    default: deny
    rules:
      - name: approved
        target:
          path: ["/usr/bin/**"]
        action: allow
`

func document(t *testing.T) Document {
	t.Helper()
	d, err := Parse(strings.NewReader(fixture), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestStrictParsing(t *testing.T) {
	cases := map[string]string{
		"unknown predicate":  strings.Replace(fixture, "path: [", "fromImage: true\n          path: [", 1),
		"unknown top-level":  fixture + "sources: []\n",
		"multiple documents": fixture + "---\n" + fixture,
		"duplicate YAML key": fixture + "version: 1\n",
		"missing binding":    strings.Replace(fixture, "container:\n    runtime: containerd\n    id: container-123", "{}", 1),
		"bad mode":           strings.Replace(fixture, "mode: enforce", "mode: tripwire", 1),
		"bad glob":           strings.Replace(fixture, "/usr/bin/**", "/usr/*/bin", 1),
		"relative path":      strings.Replace(fixture, "/usr/bin/**", "usr/bin/**", 1),
		"unclean path":       strings.Replace(fixture, "/usr/bin/**", "/usr/../bin/**", 1),
		"unknown version":    strings.Replace(fixture, "version: 1", "version: 2", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(input), DefaultLimits()); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func TestLimitsAndDuplicateRules(t *testing.T) {
	d := document(t)
	d.Policy.Exec.Rules = append(d.Policy.Exec.Rules, d.Policy.Exec.Rules[0])
	if err := d.Validate(DefaultLimits()); err == nil {
		t.Fatal("duplicate names accepted")
	}
	d.Policy.Exec.Rules[1].Name = "second"
	limits := DefaultLimits()
	limits.MaxRules = 1
	if err := d.Validate(limits); err == nil {
		t.Fatal("rule capacity ignored")
	}
	limits = DefaultLimits()
	limits.MaxPaths = 1
	if err := d.Validate(limits); err == nil {
		t.Fatal("path capacity ignored")
	}
	limits = DefaultLimits()
	limits.MaxBytes = 16
	if _, err := Parse(strings.NewReader(fixture), limits); err == nil {
		t.Fatal("input capacity ignored")
	}
	if err := d.Validate(limits); err == nil {
		t.Fatal("programmatic input capacity ignored")
	}
}

func TestDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, path, mode string
		deny, block      bool
	}{
		{"allowed", "/usr/bin/tool", "enforce", false, false},
		{"recursive", "/usr/bin/sub/tool", "enforce", false, false},
		{"boundary", "/usr/bin-other/tool", "enforce", true, true},
		{"default", "/tmp/tool", "enforce", true, true},
		{"audit", "/tmp/tool", "audit", true, false},
		{"off", "/tmp/tool", "off", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := document(t)
			d.Policy.Mode = tc.mode
			result, err := d.Evaluate(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if (result.Verdict == "deny") != tc.deny || result.WouldBlock != tc.block || result.Enforced || !result.Simulated {
				t.Fatalf("unexpected result: %+v", result)
			}
			if result.WouldDeny != (tc.deny && tc.mode == "audit") {
				t.Fatalf("wrong audit flag: %+v", result)
			}
		})
	}
}

func TestDenyPrecedenceAndModes(t *testing.T) {
	d := document(t)
	deny := Rule{Name: "no-shell", Action: "deny", Mode: "audit", Origin: "test", Target: Target{Path: []string{"/usr/bin/sh"}}}
	d.Policy.Exec.Rules = append(d.Policy.Exec.Rules, deny)
	for range 2 {
		result, err := d.Evaluate("/usr/bin/sh")
		if err != nil {
			t.Fatal(err)
		}
		if !result.WouldDeny || result.WouldBlock || result.Matches[0].Origin != "test" {
			t.Fatalf("audit deny must win over allow: %+v", result)
		}
		d.Policy.Exec.Rules[0], d.Policy.Exec.Rules[1] = d.Policy.Exec.Rules[1], d.Policy.Exec.Rules[0]
	}
	deny.Name = "hard-deny"
	deny.Mode = "enforce"
	d.Policy.Exec.Rules = append(d.Policy.Exec.Rules, deny)
	result, _ := d.Evaluate("/usr/bin/sh")
	if !result.WouldBlock || result.WouldDeny {
		t.Fatalf("enforce deny must win: %+v", result)
	}
	d.Policy.Mode = "off"
	result, _ = d.Evaluate("/usr/bin/sh")
	if result.WouldBlock {
		t.Fatal("rule override bypassed off")
	}
}

func TestProcessIdentity(t *testing.T) {
	d := document(t)
	d.Binding = Binding{Process: &Process{Node: "node-a", BootID: "boot-a", HostPID: 42, StartTimeTicks: 100}}
	if err := d.Validate(DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	d.Binding.Process.StartTimeTicks = 0
	if err := d.Validate(DefaultLimits()); err == nil {
		t.Fatal("incomplete identity accepted")
	}
}

func TestLifecycle(t *testing.T) {
	b := NewMemoryBackend(DefaultLimits())
	d := document(t)
	h, err := b.Prepare(d, 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Inspect().Active {
		t.Fatal("prepare activated policy")
	}
	// Mutations after preparation must not change the candidate.
	d.Policy.Exec.Rules[0].Target.Path[0] = "/tmp/**"
	state, err := b.Activate(h)
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != 1 || state.Enforcement {
		t.Fatalf("bad state %+v", state)
	}
	result, _ := b.Evaluate("/usr/bin/tool")
	if result.Verdict != "allow" {
		t.Fatal("candidate was not immutable")
	}
	state.Binding.Container.ID = "tampered"
	if b.Inspect().Binding.Container.ID == "tampered" {
		t.Fatal("inspection exposed mutable binding")
	}
	if _, err := b.Activate(h); err == nil {
		t.Fatal("handle replay accepted")
	}
	bad := document(t)
	bad.Policy.Mode = "invalid"
	if _, err := b.Prepare(bad, 1); err == nil {
		t.Fatal("bad replacement accepted")
	}
	if b.Inspect().Hash != state.Hash {
		t.Fatal("bad replacement changed active generation")
	}
	different := document(t)
	different.Binding.Container.ID = "different"
	if _, err := b.Prepare(different, 1); err == nil {
		t.Fatal("retargeting accepted")
	}
	d = document(t)
	d.Policy.Mode = "audit"
	h, err = b.Prepare(d, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Prepare(d, 1); err == nil {
		t.Fatal("unbounded pending storage")
	}
	b.Cancel(h)
	b.Cancel(h)
	h, err = b.Prepare(d, 1)
	if err != nil {
		t.Fatal(err)
	}
	state, err = b.Activate(h)
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != 2 {
		t.Fatal("replacement did not advance generation")
	}
	if err = b.Remove(1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale remove: %v", err)
	}
	if err = b.Remove(2); err != nil {
		t.Fatal(err)
	}
	if b.Inspect().Active || b.Inspect().Generation != 3 {
		t.Fatal("removal lost tombstone")
	}
	if err = b.Remove(3); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Prepare(d, 2); !errors.Is(err, ErrConflict) {
		t.Fatal("stale writer resurrected binding")
	}
	if _, err = b.Evaluate("/tmp/tool"); err == nil {
		t.Fatal("removed policy evaluated")
	}
}

func TestConcurrentPreparations(t *testing.T) {
	b := NewMemoryBackend(DefaultLimits())
	d := document(t)
	var wg sync.WaitGroup
	handles := make(chan Handle, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h, err := b.Prepare(d, 0); err == nil {
				handles <- h
			}
		}()
	}
	wg.Wait()
	close(handles)
	if len(handles) != 1 {
		t.Fatalf("expected one prepared candidate, got %d", len(handles))
	}
	for h := range handles {
		if _, err := b.Activate(h); err != nil {
			t.Fatal(err)
		}
	}
}
