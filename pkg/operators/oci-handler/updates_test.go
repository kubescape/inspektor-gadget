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

package ocihandler

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type updateImageOperator struct {
	err      error
	received api.ParamValues
}

func (*updateImageOperator) Name() string                        { return "wasm" }
func (*updateImageOperator) Start(operators.GadgetContext) error { return nil }
func (*updateImageOperator) Stop(operators.GadgetContext) error  { return nil }
func (*updateImageOperator) Close(operators.GadgetContext) error { return nil }
func (*updateImageOperator) SupportsParameterUpdates() bool      { return true }
func (o *updateImageOperator) UpdateParameters(_ context.Context, values api.ParamValues) error {
	o.received = values
	return o.err
}

func TestImageParameterUpdateForwarding(t *testing.T) {
	op := &updateImageOperator{}
	handler := &OciHandlerInstance{imageOperatorInstances: []operators.ImageOperatorInstance{op}, paramValues: api.ParamValues{"wasm.policy": "old", "pull": "missing"}}
	require.True(t, handler.SupportsParameterUpdates())
	require.NoError(t, handler.UpdateParameters(context.Background(), api.ParamValues{"wasm.policy": "new", "pull": "missing"}))
	require.Equal(t, api.ParamValues{"policy": "new"}, op.received)
	op.err = errors.New("rejected")
	require.Error(t, handler.UpdateParameters(context.Background(), api.ParamValues{"wasm.policy": "bad", "pull": "missing"}))
	require.Equal(t, "new", handler.paramValues["wasm.policy"])
	require.ErrorContains(t, handler.UpdateParameters(context.Background(), api.ParamValues{"wasm.policy": "new", "pull": "always"}), "outside")
	require.Equal(t, "missing", handler.paramValues["pull"])
}
