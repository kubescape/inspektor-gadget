// Copyright 2024-2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package instancemanager

import (
	"context"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type fakeUpdateContext struct {
	supported bool
	readyErr  error
	updateErr error
	calls     int
	values    api.ParamValues
	active    api.ParamValues
	acks      int
}

func (f *fakeUpdateContext) ParameterUpdatesSupported() (bool, error) { return f.supported, f.readyErr }

func (f *fakeUpdateContext) UpdateParameters(_ context.Context, values api.ParamValues) error {
	f.calls++
	f.values = values
	if f.updateErr != nil {
		return f.updateErr
	}
	f.active = maps.Clone(values)
	f.acks++
	return nil
}

func TestReconcileLiveParameters(t *testing.T) {
	for _, tc := range []struct {
		name      string
		updateErr error
		readyErr  error
		image     string
		rename    bool
		unchanged bool
		wantErr   bool
		calls     int
	}{
		{name: "acknowledged", calls: 1},
		{name: "rejected", updateErr: errors.New("invalid policy"), wantErr: true, calls: 1},
		{name: "starting", readyErr: gadgetcontext.ErrNotRunning, wantErr: true},
		{name: "image change", image: "other-image", wantErr: true},
		{name: "duplicate notification", unchanged: true, calls: 1},
		{name: "duplicate while starting", unchanged: true, readyErr: gadgetcontext.ErrNotRunning, wantErr: true},
		{name: "name change", rename: true, unchanged: true, wantErr: true},
		{name: "name and policy change", rename: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			updater := &fakeUpdateContext{supported: true, updateErr: tc.updateErr, readyErr: tc.readyErr}
			cancelled := false
			current := &api.GadgetRunRequest{ImageName: "enforce", ParamValues: map[string]string{"operator.oci.wasm.exec-policy": "old"}}
			gi := &GadgetInstance{id: "instance", name: "original", request: current, updateContext: updater, state: stateRunning, cancel: func() { cancelled = true }}
			mgr := &Manager{gadgetInstances: map[string]*GadgetInstance{"instance": gi}}
			desired := &api.GadgetInstance{Id: "instance", Name: "original", GadgetConfig: proto.Clone(current).(*api.GadgetRunRequest)}
			if !tc.unchanged {
				desired.GadgetConfig.ParamValues["operator.oci.wasm.exec-policy"] = "new"
			}
			if tc.rename {
				desired.Name = "renamed"
			}
			if tc.image != "" {
				desired.GadgetConfig.ImageName = tc.image
			}
			err := mgr.ReconcileGadget(context.Background(), desired)
			if tc.wantErr {
				require.Error(t, err)
				require.Same(t, current, gi.request)
			} else {
				require.NoError(t, err)
				require.True(t, proto.Equal(desired.GadgetConfig, gi.request))
			}
			require.Equal(t, tc.calls, updater.calls)
			require.False(t, cancelled)
			require.Same(t, gi, mgr.LookupInstance("original"))
			require.Nil(t, mgr.LookupInstance("renamed"))
			require.Same(t, gi, mgr.LookupInstance("instance"))
			status, err := mgr.InstanceState("instance")
			require.NoError(t, err)
			require.Equal(t, api.GadgetInstanceStatus_StatusRunning, status.Status)
			require.Equal(t, tc.wantErr, status.Message != "")
			// A failed desired configuration can subsequently be corrected.
			if tc.updateErr != nil {
				updater.updateErr = nil
				require.NoError(t, mgr.ReconcileGadget(context.Background(), desired))
				require.Nil(t, gi.updateError)
			}
		})
	}
}

func TestLegacyConfigurationRestarts(t *testing.T) {
	for _, tc := range []struct {
		name         string
		desiredName  string
		desiredImage string
	}{
		{name: "configuration change", desiredName: "original", desiredImage: "new"},
		{name: "name change", desiredName: "renamed", desiredImage: "old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cancelled := false
			gi := &GadgetInstance{id: "instance", name: "original", request: &api.GadgetRunRequest{ImageName: "old"}, updateContext: &fakeUpdateContext{}, cancel: func() { cancelled = true }}
			mgr := &Manager{gadgetInstances: map[string]*GadgetInstance{"instance": gi}}
			// The deliberately invalid protocol version makes the replacement exit before
			// runtime initialization; this test concerns the restart decision only.
			require.NoError(t, mgr.ReconcileGadget(context.Background(), &api.GadgetInstance{Id: "instance", Name: tc.desiredName, GadgetConfig: &api.GadgetRunRequest{ImageName: tc.desiredImage}}))
			require.True(t, cancelled)
			replacement := mgr.LookupInstance("instance")
			require.NotSame(t, gi, replacement)
			require.Same(t, replacement, mgr.LookupInstance(tc.desiredName))
			if tc.desiredName != "original" {
				require.Nil(t, mgr.LookupInstance("original"))
			}
		})
	}
}

func TestFailedStartupAcceptsCorrectedConfiguration(t *testing.T) {
	cancelled := false
	current := &api.GadgetRunRequest{ImageName: "failed"}
	gi := &GadgetInstance{id: "instance", request: current, state: stateError, runCompleted: true, error: errors.New("initial validation failed"), cancel: func() { cancelled = true }}
	mgr := &Manager{gadgetInstances: map[string]*GadgetInstance{"instance": gi}}
	// Duplicate notifications do not retry a failed configuration indefinitely.
	require.NoError(t, mgr.ReconcileGadget(context.Background(), &api.GadgetInstance{Id: "instance", GadgetConfig: current}))
	require.Same(t, gi, mgr.LookupInstance("instance"))
	require.False(t, cancelled)
	// Invalid protocol makes the replacement exit before requiring a real runtime.
	require.NoError(t, mgr.ReconcileGadget(context.Background(), &api.GadgetInstance{Id: "instance", GadgetConfig: &api.GadgetRunRequest{ImageName: "corrected"}}))
	require.True(t, cancelled)
	require.NotSame(t, gi, mgr.LookupInstance("instance"))
}

func TestRestoreLastGoodRequiresFreshAcknowledgement(t *testing.T) {
	updater := &fakeUpdateContext{supported: true}
	cancelled := false
	current := &api.GadgetRunRequest{ImageName: "enforce", ParamValues: map[string]string{"operator.oci.wasm.exec-policy": "old"}}
	gi := &GadgetInstance{id: "instance", request: current, updateContext: updater, state: stateRunning, cancel: func() { cancelled = true }}
	mgr := &Manager{gadgetInstances: map[string]*GadgetInstance{"instance": gi}}
	desired := &api.GadgetInstance{Id: "instance", GadgetConfig: proto.Clone(current).(*api.GadgetRunRequest)}
	// A direct input publication changes the active policy without updating the
	// manager's cached request. Restoring the cached request must undo this.
	require.NoError(t, updater.UpdateParameters(context.Background(), api.ParamValues{"operator.oci.wasm.exec-policy": "direct"}))
	updater.updateErr = errors.New("invalid policy")
	desired.GadgetConfig.ParamValues["operator.oci.wasm.exec-policy"] = "invalid"
	require.Error(t, mgr.ReconcileGadget(context.Background(), desired))
	require.Error(t, gi.updateError)
	desired.GadgetConfig = proto.Clone(current).(*api.GadgetRunRequest)
	// A failed restoration must not clear the error or claim the old policy.
	require.Error(t, mgr.ReconcileGadget(context.Background(), desired))
	require.Error(t, gi.updateError)
	require.Equal(t, "direct", updater.active["operator.oci.wasm.exec-policy"])
	require.Equal(t, 1, updater.acks)
	updater.updateErr = nil
	require.NoError(t, mgr.ReconcileGadget(context.Background(), desired))
	require.Nil(t, gi.updateError)
	require.Equal(t, 4, updater.calls)
	require.Equal(t, 2, updater.acks)
	require.Equal(t, api.ParamValues(current.ParamValues), updater.active, "restoration republishes the desired policy")
	require.Same(t, gi, mgr.LookupInstance("instance"))
	require.True(t, proto.Equal(current, gi.request))
	require.False(t, cancelled)
	status, err := mgr.InstanceState("instance")
	require.NoError(t, err)
	require.Empty(t, status.Message)
	require.Equal(t, api.GadgetInstanceStatus_StatusRunning, status.Status)
}

// completingRuntime uses the real gadget context lifecycle and a timeout, then
// holds the return to model runtime cleanup that must finish before replacement.
type completingRuntime struct {
	runtime.Runtime
	cleaned chan error
	release chan struct{}
}

func (r *completingRuntime) ParamDescs() params.ParamDescs { return nil }
func (r *completingRuntime) RunGadget(ctx runtime.GadgetContext, _ *params.Params, values api.ParamValues) error {
	gadgetcontext.WithTimeout(time.Millisecond)(ctx.(*gadgetcontext.GadgetContext))
	err := ctx.Run(values)
	r.cleaned <- err
	<-r.release
	return err
}

type emptyService struct{}

func (emptyService) GetOperatorMap() map[operators.DataOperator]*params.Params { return nil }

func TestCompletedRunAcceptsChangedConfiguration(t *testing.T) {
	rt := &completingRuntime{cleaned: make(chan error, 1), release: make(chan struct{})}
	defer close(rt.release)
	mgr, err := New(rt)
	require.NoError(t, err)
	mgr.Service = emptyService{}
	desired := &api.GadgetInstance{Id: "instance", Name: "original", GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: "old"}}
	mgr.RunGadget(desired)
	gi := mgr.LookupInstance("instance")
	t.Cleanup(func() { _ = mgr.RemoveGadget("instance") })
	select {
	case err := <-rt.cleaned:
		require.NoError(t, err, "real gadget context timeout and cleanup succeed")
	case <-time.After(5 * time.Second):
		t.Fatal("gadget did not finish")
	}
	// A stopped context alone is insufficient: runtime cleanup is still pending.
	changed := proto.Clone(desired).(*api.GadgetInstance)
	changed.GadgetConfig.ImageName = "new"
	require.Error(t, mgr.ReconcileGadget(context.Background(), changed))
	require.Same(t, gi, mgr.LookupInstance("instance"))
	gi.mu.Lock()
	completed := gi.runCompleted
	gi.mu.Unlock()
	require.False(t, completed)
	rt.release <- struct{}{}
	require.Eventually(t, func() bool {
		gi.mu.Lock()
		defer gi.mu.Unlock()
		return gi.runCompleted
	}, 5*time.Second, time.Millisecond)
	gi.mu.Lock()
	runErr := gi.error
	gi.mu.Unlock()
	require.NoError(t, runErr)
	// Duplicate notifications do not rerun a successfully completed gadget.
	require.NoError(t, mgr.ReconcileGadget(context.Background(), desired))
	require.Same(t, gi, mgr.LookupInstance("instance"))
	require.NoError(t, mgr.ReconcileGadget(context.Background(), changed))
	replacement := mgr.LookupInstance("instance")
	require.NotSame(t, gi, replacement)
	replacement.mu.Lock()
	require.True(t, proto.Equal(changed.GadgetConfig, replacement.request))
	replacement.mu.Unlock()
}

func TestUnchangedLegacyConfigurationDoesNotRestart(t *testing.T) {
	updater := &fakeUpdateContext{}
	current := &api.GadgetRunRequest{ImageName: "legacy"}
	gi := &GadgetInstance{id: "instance", request: current, updateContext: updater, cancel: func() { t.Error("unchanged legacy gadget was cancelled") }}
	mgr := &Manager{gadgetInstances: map[string]*GadgetInstance{"instance": gi}}
	require.NoError(t, mgr.ReconcileGadget(context.Background(), &api.GadgetInstance{Id: "instance", GadgetConfig: proto.Clone(current).(*api.GadgetRunRequest)}))
	require.Same(t, gi, mgr.LookupInstance("instance"))
	require.Zero(t, updater.calls)
}
