// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

type fakeMap struct {
	values map[uint64]uint64
	err    error
}

func (m *fakeMap) Put(k, v interface{}) error {
	if m.err != nil {
		return m.err
	}
	m.values[k.(uint64)] = v.(uint64)
	return nil
}

func (m *fakeMap) Delete(k interface{}) error {
	if m.err != nil {
		return m.err
	}
	delete(m.values, k.(uint64))
	return nil
}

func controller() (*Bindings, *fakeMap) {
	m := &fakeMap{values: map[uint64]uint64{}}
	return &Bindings{config: Config{Entries: [9]execpolicy.KernelEntry{{Generation: 7}}}, ready: true, members: m, active: map[uint64]ContainerIdentity{}, desired: map[execpolicy.Container]ContainerIdentity{}}, m
}

func identity(id uint64) ContainerIdentity {
	return ContainerIdentity{Runtime: "containerd", ID: fmt.Sprint(id), CgroupID: id, CgroupPath: fmt.Sprintf("/test/%d", id)}
}

func TestMembershipIdentityAndFailure(t *testing.T) {
	b, m := controller()
	c := identity(1)
	require.NoError(t, b.Bind(c))
	require.NoError(t, b.Bind(c))
	require.Len(t, m.values, 1)
	stale := c
	stale.ID = "old"
	require.NoError(t, b.Unbind(stale))
	require.Len(t, m.values, 1)
	require.Error(t, b.Bind(stale))
	moved := c
	moved.CgroupID = 2
	require.Error(t, b.Bind(moved))
	m.err = errors.New("map failure")
	require.Error(t, b.Unbind(c))
	require.Equal(t, 1, b.Status().Bound)
	require.Error(t, b.Bind(identity(3)))
	require.Equal(t, 1, b.Status().Bound)
	require.Error(t, b.Status().Error)
	m.err = nil
	require.NoError(t, b.Unbind(c))
	require.Zero(t, b.Status().Bound)
	for _, invalid := range []ContainerIdentity{{}, {Runtime: "r", ID: "i", CgroupID: 1, CgroupPath: "/"}, {Runtime: "r", ID: "i", CgroupID: 1, CgroupPath: "/a/../b"}} {
		require.Error(t, b.Bind(invalid))
	}
	require.NoError(t, b.Stop(nil))
	require.Error(t, b.Bind(c))
	require.Error(t, b.Unbind(c))
	require.False(t, b.Status().Ready)
}

func TestMembershipCapacityAndConcurrentChurn(t *testing.T) {
	b, _ := controller()
	for i := uint64(1); i <= execpolicy.KernelMaxBindings; i++ {
		require.NoError(t, b.Bind(identity(i)))
	}
	require.Error(t, b.Bind(identity(execpolicy.KernelMaxBindings+1)))
	require.NoError(t, b.Unbind(identity(1)))
	require.NoError(t, b.Bind(identity(execpolicy.KernelMaxBindings+1)))
	var wg sync.WaitGroup
	for i := uint64(2); i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if err := b.Unbind(identity(i)); err != nil {
					t.Error(err)
				}
				if err := b.Bind(identity(i)); err != nil {
					t.Error(err)
				}
				b.Status()
			}
		}()
	}
	wg.Wait()
	require.Equal(t, execpolicy.KernelMaxBindings, b.Status().Bound)
}

func TestStartupSnapshotCoalescing(t *testing.T) {
	b, _ := controller()
	b.ready = false
	c := identity(1)
	b.config.Targets = []execpolicy.Container{c.selector()}
	require.NoError(t, b.container("CREATED", identity(2)))
	require.Empty(t, b.desired)
	require.NoError(t, b.container("CREATED", c))
	require.Len(t, b.desired, 1)
	stale := c
	stale.CgroupID = 8
	require.NoError(t, b.container("DELETED", stale))
	require.Len(t, b.desired, 1)
	require.NoError(t, b.container("DELETED", c))
	require.Empty(t, b.desired)
	require.NoError(t, b.container("CREATED", c))
	require.Equal(t, c, b.desired[c.selector()])
	require.Error(t, b.Bind(c), "startup cannot be bypassed")
	invalid := c
	invalid.CgroupPath = "/"
	require.Error(t, b.container("CREATED", invalid))
	require.Error(t, b.lastError)
	require.Error(t, b.Start(nil), "bad replay must fail startup before accessing maps")
}

func TestNativeConfigurationGuard(t *testing.T) {
	gc := gadgetcontext.New(context.Background(), "test")
	instance, err := New().InstantiateDataOperator(gc, nil)
	require.NoError(t, err)
	require.Nil(t, instance)
	require.NoError(t, gc.SetMetadata([]byte("annotations:\n  enforce-exec: true\n")))
	_, err = New().InstantiateDataOperator(gc, nil)
	require.ErrorContains(t, err, "native policy configuration")
	config := Config{Entries: [9]execpolicy.KernelEntry{{Generation: 1, Mode: 2, DefaultDeny: 1}}, InitialBindings: []ContainerIdentity{identity(1)}}
	option := WithConfig(config)
	config.InitialBindings[0].ID = "mutated"
	option(gc)
	instance, err = New().InstantiateDataOperator(gc, nil)
	require.NoError(t, err)
	b := instance.(*Bindings)
	require.Equal(t, identity(1), b.desired[identity(1).selector()])
	require.Error(t, b.Start(gc), "missing kernel maps cannot claim readiness")
	require.False(t, b.Status().Ready)
	config.Targets = []execpolicy.Container{{Runtime: "r", ID: "id"}}
	WithConfig(config)(gc)
	_, err = New().InstantiateDataOperator(gc, nil)
	require.ErrorContains(t, err, "containers datasource")
}

func TestFinalReadinessRetainsLateBindingFailures(t *testing.T) {
	for _, source := range []string{"discovery", "native-bind", "native-unbind"} {
		t.Run(source, func(t *testing.T) {
			b, m := controller() // map installation completed; later operators may still start
			first, second := identity(1), identity(2)
			b.config.Targets = []execpolicy.Container{first.selector(), second.selector()}
			require.NoError(t, b.Bind(first))
			require.False(t, b.Status().Ready, "map availability alone is not instance readiness")
			fault := errors.New("binding map exhausted")
			m.err = fault
			switch source {
			case "discovery":
				require.ErrorIs(t, b.container("CREATED", second), fault)
			case "native-bind":
				require.ErrorIs(t, b.Bind(second), fault)
			case "native-unbind":
				require.ErrorIs(t, b.Unbind(first), fault)
			}
			m.err = nil
			require.NoError(t, b.Bind(identity(3)), "unrelated success must not erase failed coverage")
			require.ErrorIs(t, b.Ready(nil), fault)
			require.False(t, b.Status().Ready)
		})
	}
}

func TestReadinessSeparatesStartupFromRuntimeErrors(t *testing.T) {
	b, m := controller()
	require.NoError(t, b.Bind(identity(1)))
	require.NoError(t, b.Ready(nil))
	require.True(t, b.Status().Ready)
	m.err = errors.New("live write failure")
	require.Error(t, b.Bind(identity(2)))
	require.Error(t, b.Status().Error)
	require.Nil(t, b.startupError, "post-readiness failures are reported to the active owner")
	require.NoError(t, b.Stop(nil))
	require.Error(t, b.Ready(nil))
}
