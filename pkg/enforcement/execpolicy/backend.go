// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

var ErrConflict = errors.New("active generation changed")

type Capabilities struct {
	ContractVersion int      `json:"contractVersion"`
	Backend         string   `json:"backend"`
	Enforcement     bool     `json:"enforcement"`
	Predicates      []string `json:"predicates"`
	Limits          Limits   `json:"limits"`
}
type Handle uint64

type State struct {
	Backend     string  `json:"backend"`
	Enforcement bool    `json:"enforcement"`
	Active      bool    `json:"active"`
	Generation  uint64  `json:"generation"`
	Hash        string  `json:"hash,omitempty"`
	Binding     Binding `json:"binding"`
	Mode        string  `json:"mode,omitempty"`
	Rules       int     `json:"rules"`
	Pending     int     `json:"pending"`
}

// Backend is an experimental single-binding generation lifecycle contract.
// Implementations must not treat successful preparation as attached readiness.
type Backend interface {
	Capabilities() Capabilities
	Prepare(Document, uint64) (Handle, error)
	Activate(Handle) (State, error)
	Cancel(Handle)
	Inspect() State
	Remove(uint64) error
}

type candidate struct {
	document Document
	expected uint64
}

// MemoryBackend simulates a single binding. It never attaches enforcement.
// At most one candidate can be prepared, bounding temporary storage.
type MemoryBackend struct {
	mu         sync.Mutex
	limits     Limits
	generation uint64
	next       Handle
	active     *Document
	pending    map[Handle]candidate
}

func NewMemoryBackend(limits Limits) *MemoryBackend {
	return &MemoryBackend{limits: limits, pending: make(map[Handle]candidate)}
}

func (m *MemoryBackend) Capabilities() Capabilities {
	return Capabilities{ContractVersion: 1, Backend: "memory-simulation", Enforcement: false, Predicates: []string{"target.path:exact", "target.path:directory/**"}, Limits: m.limits}
}

func (m *MemoryBackend) Prepare(d Document, expected uint64) (Handle, error) {
	if err := d.Validate(m.limits); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if expected != m.generation {
		return 0, ErrConflict
	}
	if len(m.pending) != 0 {
		return 0, fmt.Errorf("prepared-generation capacity exceeded; cancel or activate the pending handle")
	}
	if m.active != nil && bindingKey(m.active.Binding) != bindingKey(d.Binding) {
		return 0, fmt.Errorf("replacement cannot change binding identity; remove the old binding first")
	}
	m.next++
	m.pending[m.next] = candidate{document: clone(d), expected: expected}
	return m.next, nil
}

func (m *MemoryBackend) Activate(h Handle) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.pending[h]
	if !ok {
		return m.inspect(), fmt.Errorf("unknown prepared handle")
	}
	delete(m.pending, h)
	if c.expected != m.generation {
		return m.inspect(), ErrConflict
	}
	d := c.document
	m.active = &d
	m.generation++
	return m.inspect(), nil
}

func (m *MemoryBackend) Cancel(h Handle) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pending, h)
}

func (m *MemoryBackend) Inspect() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inspect()
}

func (m *MemoryBackend) inspect() State {
	s := State{Backend: "memory-simulation", Generation: m.generation, Pending: len(m.pending)}
	if m.active != nil {
		d := clone(*m.active)
		s.Active, s.Hash, s.Binding, s.Mode, s.Rules = true, d.Hash(), d.Binding, d.Policy.Mode, len(d.Policy.Exec.Rules)
	}
	return s
}

func (m *MemoryBackend) Remove(expected uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if expected != m.generation {
		return ErrConflict
	}
	if m.active == nil && len(m.pending) == 0 {
		return nil
	}
	m.active = nil
	clear(m.pending)
	m.generation++ // Retain the tombstone generation to reject stale writers.
	return nil
}

func (m *MemoryBackend) Evaluate(executable string) (Decision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return Decision{}, fmt.Errorf("no active simulated policy")
	}
	return m.active.Evaluate(executable)
}

func clone(d Document) Document {
	data, _ := json.Marshal(d)
	var out Document
	_ = json.Unmarshal(data, &out)
	return out
}
func bindingKey(b Binding) string { data, _ := json.Marshal(b); return string(data) }

var _ Backend = (*MemoryBackend)(nil)
