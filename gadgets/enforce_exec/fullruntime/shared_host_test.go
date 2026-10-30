// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type sharedHostContext struct {
	operators.GadgetContext
	vars  map[string]any
	image string
}

func (c *sharedHostContext) GetVar(k string) (any, bool) { v, ok := c.vars[k]; return v, ok }

func (c *sharedHostContext) SetVar(k string, v any) { c.vars[k] = v }

func (c *sharedHostContext) Context() context.Context { return context.Background() }

func (c *sharedHostContext) ImageName() string { return c.image }

func TestSharedHostTwoPhaseAdmission(t *testing.T) {
	cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
	bad := cfg
	bad.ABI3Development = false
	if _, err := NewNodeEnforcer(bad); err == nil {
		t.Fatal("default enabled shared host")
	}
	n, err := NewNodeEnforcer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	acquired := false
	if _, err = n.Bind(t.Context(), SharedBindingConfig{CgroupID: 1, Acquire: func(context.Context) (BindingLease, error) { acquired = true; return &sharedTestLease{}, nil }}); err == nil || acquired {
		t.Fatal("binding without trusted init identity")
	}
	gc := &sharedHostContext{vars: map[string]any{sharedNodeKey: n}, image: cfg.Image}
	gc.vars["config"] = viper.New()
	if _, err = New().InstantiateDataOperator(gc, nil); err == nil {
		t.Fatal("unmarked image admitted through real operator")
	}
	metadata := viper.New()
	metadata.Set("annotations.enforce-exec-owner-abi", "3")
	metadata.Set("annotations.enforce-exec-owner-development", true)
	metadata.Set("annotations.enforce-exec-shared-profile", "1")
	gc.vars["config"] = metadata
	if _, err = New().InstantiateDataOperator(gc, nil); err == nil {
		t.Fatal("missing image geometry/maps admitted")
	}
	if err = n.Ready(gc); err == nil {
		t.Fatal("protocol foundation advertised protection")
	}
	if err = n.ReleaseAfterDetach(); err != nil {
		t.Fatal("never-claimed native handle release", err)
	}
}

func TestSharedHostStopDoesNotPretendManagerDetached(t *testing.T) {
	cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
	n, err := NewNodeEnforcer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.host.claimed = true // simulate host ownership without allocating BPF
	if err = n.StopNode(t.Context()); err == nil {
		t.Fatal("host manager detach falsely inferred")
	}
	if n.host.released {
		t.Fatal("released while operator remains claimed")
	}
	if err = n.Start(nil); err == nil {
		t.Fatal("nil context")
	}
	if err = n.Stop(nil); err == nil {
		t.Fatal("nil stop context")
	}
	if err = n.Close(nil); err == nil {
		t.Fatal("nil close context")
	}
}

func TestSharedHostJoinedPanicCleanup(t *testing.T) {
	cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
	n, err := NewNodeEnforcer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gc := &sharedHostContext{vars: map[string]any{}, image: cfg.Image}
	n.host.claimed = true
	n.host.context = gc
	thread, err := startControlThread(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	n.host.control = &sharedControl{thread: thread}
	if err = thread.do(t.Context(), func() error { panic("command panic") }); err == nil {
		t.Fatal("panic diagnostic lost")
	}
	if err = n.Close(gc); err == nil {
		t.Fatal("sticky panic diagnostic lost")
	}
	select {
	case <-thread.done:
	default:
		t.Fatal("command thread not joined")
	}
	// No BPF resources are allocated in this unit fixture. Manager teardown has
	// no borrowed FDs to close; joined diagnostics must not retain the handle.
	if !n.host.operatorClosed {
		t.Fatal("joined cleanup reported permanently incomplete")
	}
	if err = n.ReleaseAfterDetach(); err != nil {
		t.Fatal("joined failed command prevented release", err)
	}
}

func TestSharedHostBindingRefusalIsNotJoinedCleanup(t *testing.T) {
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "development"})
	if err != nil {
		t.Fatal(err)
	}
	gc := &sharedHostContext{vars: map[string]any{}, image: "development"}
	n.host.context = gc
	n.host.claimed = true
	n.bindings[1] = &BindingSession{node: n, prepared: 1, cgroup: 1}
	if err = n.Close(gc); err == nil || n.host.operatorClosed {
		t.Fatal("active binding drain refusal marked closed")
	}
	if err = n.ReleaseAfterDetach(); err == nil {
		t.Fatal("unjoined cleanup released")
	}
}

func TestSharedHostRejectsImageKeyGeometry(t *testing.T) {
	for _, key := range []string{"images", "image-quota"} {
		for _, value := range []string{"", "0", "3", "4294967296"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
				n, err := NewNodeEnforcer(cfg)
				if err != nil {
					t.Fatal(err)
				}
				gc := &sharedHostContext{vars: map[string]any{}, image: cfg.Image}
				metadata := viper.New()
				metadata.Set("annotations.enforce-exec-owner-abi", "3")
				metadata.Set("annotations.enforce-exec-owner-development", true)
				metadata.Set("annotations.enforce-exec-shared-profile", "1")
				p := cfg.Profile
				for name, count := range map[string]uint64{"inode-facts": p.InodeFacts, "inode-quota": p.PerBinding.InodeFacts, "tasks": p.Tasks, "scratch": p.Scratch, "accepted-uids": p.AcceptedUIDs, "task-quota": p.PerBinding.Tasks, "scratch-quota": p.PerBinding.Scratch, "bindings": p.Bindings, "slots-256": p.PolicySlots[0], "slots-1024": p.PolicySlots[1], "slots-4096": p.PolicySlots[2], "slots-16384": p.PolicySlots[3], "images": p.Images, "image-quota": p.PerBinding.Images} {
					metadata.Set("annotations.enforce-exec-shared-"+name, strconv.FormatUint(count, 10))
				}
				metadata.Set("annotations.enforce-exec-shared-"+key, value)
				_, err = instantiateSharedNode(gc, metadata, n)
				if err == nil || !strings.Contains(err.Error(), "shared image geometry mismatch: "+key) {
					t.Fatalf("wrong geometry admission: %v", err)
				}
				if n.host.claimed || n.host.admitted != nil || n.host.ready {
					t.Fatal("invalid image geometry acquired host authority")
				}
			})
		}
	}
}
