// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
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
	// InitHostPID is supplied by the trusted runtime, never policy metadata.
	InitHostPID uint32
	Acquire     func(context.Context) (BindingLease, error)
}
type SharedBindingStatus struct {
	ScopeCookie, CgroupID, Generation uint64
	PreparedID                        uint64
	Ready                             bool
	RootAuthorized                    bool
	Removed                           bool
	Fault                             error
}

// sharedCollection is private: injected ownership tests do not attest hooks,
// immutable arena installation, routing or native publication.
type (
	sharedCollection interface{ Close() error }
	NodeEnforcer     struct {
		mu               sync.Mutex
		stopMu           sync.Mutex
		config           SharedNodeConfig
		collection       sharedCollection
		host             *sharedHostState
		objects          *sharedObjectRegistry
		bindings         map[uint64]*BindingSession
		scopes           map[uint64]*sharedPhysicalScope
		preparations     map[*BindingSession]struct{}
		prepareBinding   func(context.Context, SharedBindingConfig, BindingLease) (*sharedPhysicalPins, error)
		collectionClosed bool
		nextPreparedID   uint64
		closing, closed  bool
	}
)

type BindingSession struct {
	mu               sync.Mutex
	node             *NodeEnforcer
	prepared, cgroup uint64
	account          *sharedPhysicalScope
	pending          *sharedPhysicalPins
	removed          bool
	prepareCancel    context.CancelFunc
	prepareDone      chan struct{}
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

// Bind prepares trusted physical inputs only. Kernel root authorization and
// publication are separate unavailable operations; this cannot report Ready.
func (n *NodeEnforcer) Bind(ctx context.Context, c SharedBindingConfig) (*BindingSession, error) {
	return n.bindPhysicalScope(ctx, c)
}

// PreparedID is a native reservation identity, never a kernel scope cookie.
func (s *BindingSession) PreparedID() uint64 { return s.prepared }

// ScopeCookie remains zero until real authenticated kernel registration. The
// command sequence, not a competing Go allocator, creates that authority.
func (s *BindingSession) ScopeCookie() uint64 {
	s.account.mu.Lock()
	defer s.account.mu.Unlock()
	if s.account.registration.Operation != sharedBindingOpen || s.account.registration.Status != 0 {
		return 0
	}
	return s.account.registration.Sequence
}

func (s *BindingSession) Inspect() SharedBindingStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SharedBindingStatus{PreparedID: s.prepared, ScopeCookie: s.ScopeCookie(), CgroupID: s.cgroup, Removed: s.removed, Fault: ErrSharedNativeUnavailable}
}

// Remove retires the logical session, not its retained physical history account.
// Nonzero generations still require the unavailable authenticated withdrawal.
func (s *BindingSession) Remove(ctx context.Context, expectedGeneration uint64) error {
	return s.removePhysicalSession(ctx, expectedGeneration)
}

func (n *NodeEnforcer) StopNode(ctx context.Context) error {
	if n.host != nil {
		if err := n.BeforeStop(ctx); err != nil {
			return err
		}
		return n.ReleaseAfterDetach()
	}
	n.stopMu.Lock()
	defer n.stopMu.Unlock()
	if err := n.cancelAndJoinPreparations(ctx); err != nil {
		return err
	}
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
	if !n.collectionClosed {
		if err := n.collection.Close(); err != nil {
			return err
		}
		n.mu.Lock()
		n.collectionClosed = true
		n.mu.Unlock()
	}
	if err := n.releasePhysicalScopes(); err != nil {
		return err
	}
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
	return nil
}
