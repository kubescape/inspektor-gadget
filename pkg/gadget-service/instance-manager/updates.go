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
	"fmt"
	"maps"

	"google.golang.org/protobuf/proto"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type parameterUpdateContext interface {
	ParameterUpdatesSupported() (bool, error)
	UpdateParameters(context.Context, api.ParamValues) error
}

// ReconcileGadget keeps a live-update-capable gadget running on rejected updates.
// Legacy gadgets still restart when their configuration changes.
func (m *Manager) ReconcileGadget(ctx context.Context, desired *api.GadgetInstance) error {
	if desired == nil || desired.GadgetConfig == nil {
		return fmt.Errorf("missing gadget configuration")
	}
	m.mu.Lock()
	gi := m.gadgetInstances[desired.Id]
	m.mu.Unlock()
	if gi == nil {
		m.RunGadget(desired)
		return nil
	}
	gi.updateMu.Lock()
	defer gi.updateMu.Unlock()
	gi.mu.Lock()
	current := gi.request
	currentName := gi.name
	updater := gi.updateContext
	runCompleted := gi.runCompleted
	gi.mu.Unlock()
	unchanged := currentName == desired.Name && proto.Equal(current, desired.GadgetConfig)
	if runCompleted {
		if unchanged {
			return gi.setUpdateError(nil)
		}
		// Run has returned and completed operator cleanup, whether it failed
		// or finished normally. A changed configuration may start a fresh instance.
		if err := m.RemoveGadget(desired.Id); err != nil {
			return err
		}
		m.RunGadget(desired)
		return nil
	}
	if updater == nil {
		return gi.setUpdateError(gadgetcontext.ErrNotRunning)
	}
	supported, err := updater.ParameterUpdatesSupported()
	if err != nil {
		return gi.setUpdateError(err)
	}
	if !supported {
		if unchanged {
			return gi.setUpdateError(nil)
		}
		if err := m.RemoveGadget(desired.Id); err != nil {
			return err
		}
		m.RunGadget(desired)
		return nil
	}
	// Structural changes require an explicit removal. Never introduce a gap by
	// silently restarting a gadget that promised live policy updates.
	desiredStructure := proto.Clone(desired.GadgetConfig).(*api.GadgetRunRequest)
	currentStructure := proto.Clone(current).(*api.GadgetRunRequest)
	desiredStructure.ParamValues, currentStructure.ParamValues = nil, nil
	if currentName != desired.Name || !proto.Equal(desiredStructure, currentStructure) {
		return gi.setUpdateError(fmt.Errorf("running gadget only supports parameter updates; remove the instance explicitly to change its name or execution configuration"))
	}
	// Cached requests do not prove the active policy: direct datasource updates
	// can change it independently. Even an unchanged request needs a fresh ack.
	if err := updater.UpdateParameters(ctx, maps.Clone(desired.GadgetConfig.ParamValues)); err != nil {
		return gi.setUpdateError(fmt.Errorf("live parameter update not acknowledged; instance remains running: %w", err))
	}
	gi.mu.Lock()
	gi.request = proto.Clone(desired.GadgetConfig).(*api.GadgetRunRequest)
	gi.updateError = nil
	gi.mu.Unlock()
	return nil
}

func (p *GadgetInstance) setUpdateError(err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updateError = err
	return err
}
