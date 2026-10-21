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
	"fmt"
	"maps"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

var (
	ErrParameterUpdatesUnsupported = errors.New("gadget does not support live parameter updates")
	ErrNotRunning                  = errors.New("gadget is not ready for live parameter updates")
)

// UpdateParameters submits the complete desired parameter set. Success means the
// owning operator acknowledged publication; errors preserve the running policy.
// Unsupported is returned only after startup, so reconciliation cannot mistake
// an initializing enforcement gadget for a legacy gadget and restart it.
func (c *GadgetContext) UpdateParameters(ctx context.Context, values api.ParamValues) error {
	c.updateMu.Lock()
	defer c.updateMu.Unlock()
	if err := c.ctx.Err(); err != nil {
		return fmt.Errorf("gadget stopped: %w", err)
	}
	if !c.updatesReady {
		return ErrNotRunning
	}
	updater, err := c.parameterUpdater()
	if err != nil {
		return err
	}
	prefix := "operator." + updater.(operators.DataOperatorInstance).Name() + "."
	before, after := maps.Clone(c.paramValues), maps.Clone(values)
	for k := range before {
		if strings.HasPrefix(k, prefix) {
			delete(before, k)
		}
	}
	for k := range after {
		if strings.HasPrefix(k, prefix) {
			delete(after, k)
		}
	}
	if !maps.Equal(before, after) {
		return fmt.Errorf("parameters outside %s cannot be updated on this running gadget", prefix)
	}
	operatorPrefix := strings.TrimSuffix(prefix, ".")
	updated := values.ExtractPrefixedValues(operatorPrefix)
	// Apply the same operator defaults as initial instantiation, so omitted
	// defaults do not appear to be changes to unrelated OCI parameters.
	for _, op := range c.dataOperators {
		if "operator."+op.Name() != operatorPrefix {
			continue
		}
		descriptors := op.InstanceParams().AddPrefix(operatorPrefix)
		apihelpers.MergeWithAlternativeKeys(descriptors, updated)
		if err := apihelpers.NormalizeWithDefaults(descriptors, updated); err != nil {
			return err
		}
		if err := apihelpers.Validate(descriptors, updated); err != nil {
			return err
		}
	}
	if err := updater.UpdateParameters(ctx, updated); err != nil {
		return err
	}
	c.paramValues = maps.Clone(values)
	return nil
}

func (c *GadgetContext) ParameterUpdatesSupported() (bool, error) {
	c.updateMu.Lock()
	defer c.updateMu.Unlock()
	if err := c.ctx.Err(); err != nil {
		return false, fmt.Errorf("gadget stopped: %w", err)
	}
	if !c.updatesReady {
		return false, ErrNotRunning
	}
	_, err := c.parameterUpdater()
	if errors.Is(err, ErrParameterUpdatesUnsupported) {
		return false, nil
	}
	return err == nil, err
}

func (c *GadgetContext) parameterUpdater() (operators.ParameterUpdater, error) {
	var updater operators.ParameterUpdater
	for _, op := range c.localOperators {
		u, ok := op.(operators.ParameterUpdater)
		if !ok || !u.SupportsParameterUpdates() {
			continue
		}
		if updater != nil {
			return nil, fmt.Errorf("multiple operators advertise parameter updates")
		}
		updater = u
	}
	if updater == nil {
		return nil, ErrParameterUpdatesUnsupported
	}
	return updater, nil
}
