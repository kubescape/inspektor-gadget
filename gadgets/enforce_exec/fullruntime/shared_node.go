// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
)

var ErrSharedNativeUnavailable = errors.New("shared native collection/publication is not implemented")

type SharedNodeConfig struct {
	Profile         SharedProfile
	ABI3Development bool
	Image           string
}
type SharedBindingConfig struct {
	CgroupID uint64
	Acquire  func(context.Context) (BindingLease, error)
}
type SharedBindingStatus struct {
	ScopeCookie, CgroupID, Generation uint64
	Ready                             bool
	Removed                           bool
	Fault                             error
}

// sharedCollection is private: injected ownership tests do not attest hooks,
// immutable arena installation, routing or native publication.
type (
	sharedCollection interface{ Close() error }
	NodeEnforcer     struct {
		mu              sync.Mutex
		stopMu          sync.Mutex
		config          SharedNodeConfig
		collection      sharedCollection
		bindings        map[uint64]*BindingSession
		nextCookie      uint64
		closing, closed bool
	}
)

type BindingSession struct {
	mu            sync.Mutex
	node          *NodeEnforcer
	scope, cgroup uint64
	lease         BindingLease
	removed       bool
}

// StartNode refuses until the real shared collection adapter validates metadata,
// referenced maps and commands. A development image name is not capability proof.
func StartNode(ctx context.Context, config SharedNodeConfig) (*NodeEnforcer, error) {
	return startSharedNode(ctx, config, func(context.Context, SharedNodeConfig, SharedAdmission) (sharedCollection, error) {
		return nil, ErrSharedNativeUnavailable
	})
}

func startSharedNode(ctx context.Context, config SharedNodeConfig, start func(context.Context, SharedNodeConfig, SharedAdmission) (sharedCollection, error)) (*NodeEnforcer, error) {
	admission, err := config.Profile.Validate()
	if err != nil {
		return nil, err
	}
	if !config.ABI3Development || config.Image == "" {
		return nil, fmt.Errorf("explicit shared development image and trusted opt-in required")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	collection, err := start(ctx, config, admission)
	if collection == nil {
		return nil, errors.Join(err, fmt.Errorf("missing shared collection"))
	}
	// Retain partial-start ownership for StopNode; startup errors cannot prove
	// that the collection has already detached and released every resource.
	n := &NodeEnforcer{config: config, collection: collection, bindings: make(map[uint64]*BindingSession)}
	if err = errors.Join(err, ctx.Err()); err != nil {
		n.closing = true
	}
	return n, err
}

// Bind reserves a unique cgroup and its quotas before acquiring a trusted lease.
// It creates no routing authority and never reports Ready by itself.
func (n *NodeEnforcer) Bind(ctx context.Context, c SharedBindingConfig) (*BindingSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.CgroupID == 0 || c.Acquire == nil {
		return nil, fmt.Errorf("trusted exact binding required")
	}
	n.mu.Lock()
	if n.closing || n.closed || n.bindings[c.CgroupID] != nil || uint64(len(n.bindings)) >= n.config.Profile.Bindings || n.nextCookie >= math.MaxUint64-1 {
		n.mu.Unlock()
		return nil, fmt.Errorf("shared binding unavailable")
	}
	n.nextCookie++
	s := &BindingSession{node: n, scope: n.nextCookie, cgroup: c.CgroupID}
	// Serialize cleanup with acquisition, without holding the node lock over IO.
	s.mu.Lock()
	n.bindings[c.CgroupID] = s
	n.mu.Unlock()
	lease, err := c.Acquire(ctx)
	if err == nil && lease == nil {
		err = fmt.Errorf("missing binding lease")
	}
	if err == nil {
		err = lease.Check(ctx)
	}
	s.lease = lease
	if err == nil {
		err = ctx.Err()
	}
	n.mu.Lock()
	stopping := n.closing
	n.mu.Unlock()
	if err == nil && stopping {
		err = fmt.Errorf("node stopping")
	}
	s.mu.Unlock()
	if err != nil {
		// Retain the handle on failed cleanup so callers can retry, not lose pins.
		cleanup := s.Remove(context.WithoutCancel(ctx), 0)
		if cleanup != nil {
			return s, errors.Join(err, cleanup)
		}
		return nil, err
	}
	return s, nil
}
func (s *BindingSession) ScopeCookie() uint64 { return s.scope }
func (s *BindingSession) Inspect() SharedBindingStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SharedBindingStatus{ScopeCookie: s.scope, CgroupID: s.cgroup, Removed: s.removed, Fault: ErrSharedNativeUnavailable}
}

// Remove currently cleans only never-activated reservations. The real shared
// driver must reconcile an authoritative WITHDRAWN receipt before lease release.
func (s *BindingSession) Remove(ctx context.Context, expectedGeneration uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expectedGeneration != 0 {
		return ErrSharedNativeUnavailable
	}
	if s.removed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.lease != nil {
		if err := s.lease.Close(); err != nil {
			return err
		}
		s.lease = nil
	}
	s.node.mu.Lock()
	defer s.node.mu.Unlock()
	if s.node.bindings[s.cgroup] != s {
		return fmt.Errorf("binding ownership mismatch")
	}
	delete(s.node.bindings, s.cgroup)
	s.removed = true
	return nil
}

func (n *NodeEnforcer) StopNode(ctx context.Context) error {
	n.stopMu.Lock()
	defer n.stopMu.Unlock()
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closing = true
	bindings := make([]*BindingSession, 0, len(n.bindings))
	for _, s := range n.bindings {
		bindings = append(bindings, s)
	}
	n.mu.Unlock()
	var result error
	for _, s := range bindings {
		result = errors.Join(result, s.Remove(ctx, 0))
	}
	if result != nil {
		return result
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := n.collection.Close(); err != nil {
		return err
	}
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
	return nil
}
