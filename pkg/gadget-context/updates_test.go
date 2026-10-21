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

package gadgetcontext

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type updatingOperator struct {
	*fakeOperator
	err      error
	calls    int
	received api.ParamValues
}

func (o *updatingOperator) SupportsParameterUpdates() bool { return true }
func (o *updatingOperator) UpdateParameters(_ context.Context, values api.ParamValues) error {
	o.calls++
	o.received = values
	return o.err
}

func TestParameterUpdateLifecycle(t *testing.T) {
	ctx := New(context.Background(), "image")
	op := &updatingOperator{fakeOperator: &fakeOperator{name: "oci"}}
	ctx.localOperators = []operators.DataOperatorInstance{op}
	ctx.paramValues = api.ParamValues{"operator.oci.wasm.policy": "old", "runtime.other": "keep"}
	desired := api.ParamValues{"operator.oci.wasm.policy": "new", "runtime.other": "keep"}
	require.ErrorIs(t, ctx.UpdateParameters(context.Background(), desired), ErrNotRunning)
	ctx.updatesReady = true
	op.err = errors.New("rejected")
	require.ErrorContains(t, ctx.UpdateParameters(context.Background(), desired), "rejected")
	require.Equal(t, "old", ctx.paramValues["operator.oci.wasm.policy"])
	op.err = nil
	require.NoError(t, ctx.UpdateParameters(context.Background(), desired))
	require.Equal(t, api.ParamValues{"wasm.policy": "new"}, op.received)
	desired["runtime.other"] = "changed"
	require.ErrorContains(t, ctx.UpdateParameters(context.Background(), desired), "outside")
	require.Equal(t, 2, op.calls)
	require.Equal(t, "keep", ctx.paramValues["runtime.other"])
	ctx.Cancel()
	require.ErrorIs(t, ctx.UpdateParameters(context.Background(), desired), context.Canceled)
}

func TestParameterUpdateSupport(t *testing.T) {
	ctx := New(context.Background(), "image")
	_, err := ctx.ParameterUpdatesSupported()
	require.ErrorIs(t, err, ErrNotRunning)
	ctx.updatesReady = true
	supported, err := ctx.ParameterUpdatesSupported()
	require.NoError(t, err)
	require.False(t, supported)
	require.ErrorIs(t, ctx.UpdateParameters(context.Background(), nil), ErrParameterUpdatesUnsupported)
	ctx.localOperators = []operators.DataOperatorInstance{
		&updatingOperator{fakeOperator: &fakeOperator{name: "one"}},
		&updatingOperator{fakeOperator: &fakeOperator{name: "two"}},
	}
	require.ErrorContains(t, ctx.UpdateParameters(context.Background(), nil), "multiple")
}
