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
	"fmt"
	"maps"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (o *OciHandlerInstance) SupportsParameterUpdates() bool {
	for _, op := range o.imageOperatorInstances {
		if u, ok := op.(operators.ParameterUpdater); ok && u.SupportsParameterUpdates() {
			return true
		}
	}
	return false
}

func (o *OciHandlerInstance) UpdateParameters(ctx context.Context, values api.ParamValues) error {
	var updater operators.ParameterUpdater
	for _, op := range o.imageOperatorInstances {
		u, ok := op.(operators.ParameterUpdater)
		if !ok || !u.SupportsParameterUpdates() {
			continue
		}
		if updater != nil {
			return fmt.Errorf("multiple image operators advertise parameter updates")
		}
		updater = u
	}
	if updater == nil {
		return fmt.Errorf("no image operator supports parameter updates")
	}
	prefix := updater.(operators.ImageOperatorInstance).Name() + "."
	before, after := maps.Clone(o.paramValues), maps.Clone(values)
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
	if err := updater.UpdateParameters(ctx, values.ExtractPrefixedValues(strings.TrimSuffix(prefix, "."))); err != nil {
		return err
	}
	o.paramValues = maps.Clone(values)
	return nil
}
