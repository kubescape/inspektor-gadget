// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package wasm

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"

	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// A declared datasource protocol keeps gadget-specific configuration out of the
// instance manager. Publication is acknowledged synchronously by a correlated
// status event from the guest, not merely by accepting an input packet.
type parameterUpdates struct {
	updateMu                                    sync.Mutex
	mu                                          sync.Mutex
	parameter, inputName, statusName, fieldName string
	input                                       datasource.DataSource
	generation, nextID, pendingID               uint64
	ack                                         *updateAck
}
type updateAck struct {
	generation     uint64
	state, message string
}

func readUpdateProtocol(config *viper.Viper) (*parameterUpdates, error) {
	if config == nil {
		return nil, nil
	}
	p := &parameterUpdates{parameter: config.GetString("annotations.live-update-parameter"), inputName: config.GetString("annotations.live-update-datasource"), statusName: config.GetString("annotations.live-update-status"), fieldName: config.GetString("annotations.live-update-field")}
	if p.parameter == "" && p.inputName == "" && p.statusName == "" && p.fieldName == "" {
		return nil, nil
	}
	if p.parameter == "" || p.inputName == "" || p.statusName == "" || p.fieldName == "" {
		return nil, fmt.Errorf("incomplete live-update datasource protocol")
	}
	return p, nil
}

func (i *wasmOperatorInstance) initParameterUpdates() error {
	p := i.parameterUpdates
	if p == nil {
		return nil
	}
	sources := i.gadgetCtx.GetDataSources()
	p.input = sources[p.inputName]
	status := sources[p.statusName]
	if p.input == nil || status == nil {
		return fmt.Errorf("live-update input/status datasource missing")
	}
	check := func(ds datasource.DataSource, name string, kind api.Kind) error {
		f := ds.GetField(name)
		if f == nil || f.Type() != kind {
			return fmt.Errorf("live-update field %q missing or wrong kind", name)
		}
		return nil
	}
	for name, kind := range map[string]api.Kind{p.fieldName: api.Kind_String, "expected_generation": api.Kind_Uint64, "request_id": api.Kind_Uint64} {
		if err := check(p.input, name, kind); err != nil {
			return err
		}
	}
	for name, kind := range map[string]api.Kind{"state": api.Kind_String, "message": api.Kind_String, "generation": api.Kind_Uint64, "request_id": api.Kind_Uint64} {
		if err := check(status, name, kind); err != nil {
			return err
		}
	}
	return status.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
		gen, err := status.GetField("generation").Uint64(data)
		if err != nil {
			return err
		}
		id, err := status.GetField("request_id").Uint64(data)
		if err != nil {
			return err
		}
		state, err := status.GetField("state").String(data)
		if err != nil {
			return err
		}
		message, err := status.GetField("message").String(data)
		if err != nil {
			return err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		p.generation = gen
		if id != 0 && id == p.pendingID {
			p.ack = &updateAck{gen, state, message}
		}
		return nil
	}, 0)
}

func (i *wasmOperatorInstance) SupportsParameterUpdates() bool { return i.parameterUpdates != nil }

func (i *wasmOperatorInstance) UpdateParameters(ctx context.Context, values api.ParamValues) error {
	p := i.parameterUpdates
	if p == nil {
		return fmt.Errorf("guest does not advertise live updates")
	}
	p.updateMu.Lock()
	defer p.updateMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if i.guestStopped.Load() {
		return fmt.Errorf("guest stopped")
	}
	before, after := maps.Clone(i.paramValues), maps.Clone(values)
	delete(before, p.parameter)
	delete(after, p.parameter)
	if !maps.Equal(before, after) {
		return fmt.Errorf("only parameter %q supports live updates", p.parameter)
	}
	raw, ok := values[p.parameter]
	if !ok {
		return fmt.Errorf("missing live parameter %q", p.parameter)
	}
	if raw == i.paramValues[p.parameter] {
		return nil
	}
	p.mu.Lock()
	gen := p.generation
	if gen == 0 || gen == ^uint64(0) || p.nextID == ^uint64(0) {
		p.mu.Unlock()
		return fmt.Errorf("guest has no usable active generation")
	}
	p.nextID++
	id := p.nextID
	p.pendingID = id
	p.ack = nil
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.pendingID = 0; p.ack = nil; p.mu.Unlock() }()
	packet, err := p.input.NewPacketSingle()
	if err != nil {
		return err
	}
	if err = p.input.GetField(p.fieldName).PutString(packet, raw); err == nil {
		err = p.input.GetField("expected_generation").PutUint64(packet, gen)
	}
	if err == nil {
		err = p.input.GetField("request_id").PutUint64(packet, id)
	}
	if err != nil {
		p.input.Release(packet)
		return err
	}
	emitErr := p.input.EmitAndRelease(packet)
	p.mu.Lock()
	ack := p.ack
	p.mu.Unlock()
	if ack == nil {
		return errors.Join(fmt.Errorf("guest did not acknowledge update request %d", id), emitErr)
	}
	if ack.state == "update-rejected" || ack.state == "error" {
		return fmt.Errorf("guest rejected policy update: %s", ack.message)
	}
	switch ack.state {
	case "enforcing", "auditing", "off", "waiting-for-target":
	default:
		return fmt.Errorf("guest returned ambiguous update state %q", ack.state)
	}
	if ack.generation != gen+1 {
		return fmt.Errorf("guest acknowledged unexpected generation %d (wanted %d)", ack.generation, gen+1)
	}
	// Guest callbacks read parameters under the same execution lock.
	i.dataSourceCallbackLock.Lock()
	i.paramValues = maps.Clone(values)
	i.dataSourceCallbackLock.Unlock()
	return nil
}
