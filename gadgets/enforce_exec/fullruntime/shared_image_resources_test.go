// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func sharedImageFixture(t *testing.T) (SharedProfile, *operators.NativeResources) {
	t.Helper()
	p, r := sharedResourcesFixture()
	p.Images = 65536
	p.TelemetryBytes = 262144
	extra, programs := sharedImageGeometry(p)
	for n, v := range extra {
		r.Maps[n] = v
	}
	r.Programs = programs
	for n, v := range r.Programs {
		v.Instructions = 17
		r.Programs[n] = v
	}
	return p, r
}

func TestSharedImageInventory(t *testing.T) {
	p, r := sharedImageFixture(t)
	u, err := validateSharedImageResources(p, r)
	if err != nil {
		t.Fatal(err)
	}
	if !u.PendingEnforcementQualification || u.MapPayloadBytes == 0 || u.ProgramInstructions != 8*17 {
		t.Fatalf("incomplete accounting: %+v", u)
	}
	for name := range r.Maps {
		t.Run(name, func(t *testing.T) {
			p, r := sharedImageFixture(t)
			delete(r.Maps, name)
			if _, err := validateSharedImageResources(p, r); err == nil {
				t.Fatal("missing map accepted")
			}
		})
	}
	for name := range r.Programs {
		t.Run(name, func(t *testing.T) {
			p, r := sharedImageFixture(t)
			v := r.Programs[name]
			v.Target = "foreign"
			r.Programs[name] = v
			if _, err := validateSharedImageResources(p, r); err == nil {
				t.Fatal("foreign hook accepted")
			}
		})
	}
}

func TestSharedImageCannotAdmitUnqualifiedFacts(t *testing.T) {
	p, r := sharedImageFixture(t)
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: p, ABI3Development: true, Image: "test:shared"})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.admitSharedResources(r); err == nil {
		t.Fatal("unqualified inode facts silently admitted")
	}
	if n.host.admitted != nil {
		t.Fatal("refused image retained as admitted")
	}
}
