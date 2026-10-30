// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

const sharedNodeKey = "enforce-exec/native-shared-node"

type sharedBorrowedFD interface{ FD() int }

type sharedHostState struct {
	sharedProtocolHostOwnership
	borrowed                                 []sharedBorrowedFD
	context                                  operators.GadgetContext
	admitted                                 *operators.NativeResources
	resources                                sharedControlResources
	control                                  *sharedControl
	claimed, operatorClosed, released, ready bool
	commandsJoined                           bool
	startAttempted                           bool
}

// NewNodeEnforcer constructs a host-owned node handle without starting a gadget
// or allocating kernel resources. The HOST must pass WithNodeEnforcer to its
// existing manager's one StartGadget call, and retain this handle on any error.
func NewNodeEnforcer(config SharedNodeConfig) (*NodeEnforcer, error) {
	if _, err := config.Profile.Validate(); err != nil {
		return nil, err
	}
	if !config.ABI3Development || config.Image == "" {
		return nil, fmt.Errorf("explicit shared development image and trusted opt-in required")
	}
	return &NodeEnforcer{config: config, bindings: map[uint64]*BindingSession{}, host: &sharedHostState{}}, nil
}

// WithNodeEnforcer adds native ownership to the existing host gadget context.
// It does not construct an instance manager or a second runtime.
func WithNodeEnforcer(node *NodeEnforcer) gadgetcontext.Option {
	return func(gc *gadgetcontext.GadgetContext) {
		gc.SetVar(sharedNodeKey, node)
		gc.SetVar(operators.NativeOwnerRequiredKey, true)
		gc.SetVar(operators.NativeResourceValidatorKey, func(resources *operators.NativeResources) error {
			if node == nil || node.host == nil {
				return fmt.Errorf("missing host-owned shared node")
			}
			return node.admitSharedResources(resources)
		})
	}
}

func (n *NodeEnforcer) admitSharedResources(resources *operators.NativeResources) error {
	if resources != nil {
		if _, fullImage := resources.Maps["se_tasks"]; fullImage {
			usage, err := validateSharedImageResources(n.config.Profile, resources)
			if err != nil {
				return err
			}
			if usage.PendingEnforcementQualification {
				return fmt.Errorf("shared image lifetime/qualification proofs remain unavailable: %w", ErrSharedNativeUnavailable)
			}
			return ErrSharedNativeUnavailable // qualification/publication remains unavailable
		}
	}
	if _, err := validateSharedProtocolResources(n.config.Profile, resources); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host == nil || n.closing || n.closed || n.host.released {
		return fmt.Errorf("shared native admission closed")
	}
	// Accepted manifests have no nested map templates; shallow value copies are
	// complete independent snapshots. Never retain caller-mutable map registries.
	n.host.admitted = &operators.NativeResources{Maps: maps.Clone(resources.Maps), Programs: maps.Clone(resources.Programs)}
	return nil
}

func instantiateSharedNode(gc operators.GadgetContext, metadata *viper.Viper, node *NodeEnforcer) (operators.DataOperatorInstance, error) {
	if node == nil || node.host == nil || metadata == nil {
		return nil, fmt.Errorf("shared image requires its host-owned native node")
	}
	if owner, _ := gc.GetVar(ownerKey); owner != nil {
		return nil, fmt.Errorf("shared and per-binding owner options are mutually exclusive")
	}
	if !node.config.ABI3Development || gc.ImageName() != node.config.Image || metadata.GetString("annotations.enforce-exec-owner-abi") != "3" || !metadata.GetBool("annotations.enforce-exec-owner-development") || metadata.GetString("annotations.enforce-exec-shared-profile") != "1" || metadata.GetBool("annotations.enforce-exec") || metadata.GetBool("annotations.enforce-exec-full") {
		return nil, fmt.Errorf("shared image/native capability mismatch")
	}
	values := map[string]uint64{"images": node.config.Profile.Images, "image-quota": node.config.Profile.PerBinding.Images, "inode-facts": node.config.Profile.InodeFacts, "inode-quota": node.config.Profile.PerBinding.InodeFacts, "tasks": node.config.Profile.Tasks, "scratch": node.config.Profile.Scratch, "accepted-uids": node.config.Profile.AcceptedUIDs, "task-quota": node.config.Profile.PerBinding.Tasks, "scratch-quota": node.config.Profile.PerBinding.Scratch, "bindings": node.config.Profile.Bindings, "slots-256": node.config.Profile.PolicySlots[0], "slots-1024": node.config.Profile.PolicySlots[1], "slots-4096": node.config.Profile.PolicySlots[2], "slots-16384": node.config.Profile.PolicySlots[3]}
	for key, want := range values {
		if metadata.GetString("annotations.enforce-exec-shared-"+key) != strconv.FormatUint(want, 10) {
			return nil, fmt.Errorf("shared image geometry mismatch: %s", key)
		}
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	if cpus < 1 || cpus > 64 || uint32(cpus) > node.config.Profile.PossibleCPUs {
		return nil, fmt.Errorf("actual possible CPUs exceed shared profile")
	}
	value, _ := gc.GetVar(operators.NativeResourcesKey)
	resources, _ := value.(*operators.NativeResources)
	if err = node.admitSharedResources(resources); err != nil {
		return nil, err
	}
	if err = verifySupportedKernel(); err != nil {
		return nil, err
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.host.claimed || node.host.released || node.closing || node.closed {
		return nil, fmt.Errorf("shared native node already claimed")
	}
	node.host.claimed = true
	node.host.context = gc
	return node, nil
}
func (*NodeEnforcer) Name() string { return "enforce-exec-shared-node" }

// Start borrows and verifies the actual host-loaded program/map identities,
// then sets up the frozen, physical-thread-qualified command capability.
// Successful protocol startup is NOT complete shared enforcement readiness.
func (n *NodeEnforcer) Start(gc operators.GadgetContext) error {
	n.mu.Lock()
	if gc == nil || n.host == nil || !n.host.claimed || n.host.context != gc || n.host.control != nil || n.host.startAttempted || n.closing || n.closed {
		n.mu.Unlock()
		return fmt.Errorf("invalid shared host startup")
	}
	n.host.startAttempted = true
	ctx, cancel := context.WithCancel(gc.Context())
	done := make(chan struct{})
	n.host.startup = sharedStartupOperation{cancel: cancel, done: done}
	admitted := n.host.admitted
	n.mu.Unlock()
	defer func() { cancel(); n.mu.Lock(); n.host.startup = sharedStartupOperation{}; close(done); n.mu.Unlock() }()
	r, err := sharedControlResourcesFromContext(gc)
	n.mu.Lock()
	n.host.resources = r
	n.host.borrowed = r.borrowedHandles()
	n.mu.Unlock()
	if err != nil {
		return err
	}
	r.manifest = admitted
	n.mu.Lock()
	n.host.resources = r
	n.mu.Unlock()
	// Exact protocol-only capability, not an absence-of-se_tasks heuristic.
	if _, err = validateSharedProtocolResources(n.config.Profile, r.manifest); err != nil {
		return err
	}
	control, err := newSharedControl(ctx, n.config.Profile, r)
	n.mu.Lock()
	n.host.control = control
	n.mu.Unlock()
	if err != nil {
		return err
	}
	// newSharedControl validated actual loaded identities before this allocation.
	// Fixed slots are allocated only after explicit native resource admission.
	slots := make([]*sharedPhysicalScope, n.config.Profile.Bindings)
	objects := newSharedObjectRegistry(n.config.Profile)
	n.mu.Lock()
	n.host.protocol = &sharedProtocolCapability{}
	n.host.scopeSlots = slots
	n.objects = objects
	n.mu.Unlock()
	receipt, err := control.call(ctx, sharedCommandWire{Operation: sharedNodeInspect})
	if err == nil && (receipt.Value != SharedProfileVersion || receipt.Serial != 0 || receipt.Generation != 0) {
		err = fmt.Errorf("shared protocol handshake receipt mismatch")
	}
	n.mu.Lock()
	n.host.handshakeComplete = err == nil
	n.mu.Unlock()
	return err
}

func (n *NodeEnforcer) Ready(gc operators.GadgetContext) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host == nil || n.host.context != gc || n.host.control == nil || n.closing || n.closed {
		return fmt.Errorf("shared host startup incomplete")
	}
	// Routing, union evaluator adaptation, qualified history publication and
	// required attachment receipts are not integrated. Never advertise protection.
	return ErrSharedNativeUnavailable
}

// BeforeStop must precede host StopGadget. It joins native commands; it neither
// closes borrowed maps nor claims that manager attachment teardown happened.
func (n *NodeEnforcer) BeforeStop(ctx context.Context) error {
	return n.beforeStopProtocolUsing(ctx, nil)
}

func (n *NodeEnforcer) beforeStopProtocolUsing(ctx context.Context, transport sharedCommandTransport) error {
	n.stopMu.Lock()
	defer n.stopMu.Unlock()
	n.mu.Lock()
	if n.host == nil {
		n.mu.Unlock()
		return fmt.Errorf("not a host-owned shared node")
	}
	if n.host.commandsJoined {
		err := n.host.cleanupErr
		n.mu.Unlock()
		return err
	}
	n.mu.Unlock()
	if err := n.cancelAndJoinPreparations(ctx); err != nil {
		return err
	}
	n.mu.Lock()
	sessions := make([]*BindingSession, 0, len(n.bindings))
	for _, s := range n.bindings {
		sessions = append(sessions, s)
	}
	control := n.host.control
	protocol := n.host.protocol != nil
	n.mu.Unlock()
	for _, s := range sessions {
		if s.account == nil {
			return ErrSharedNativeUnavailable
		}
		s.account.mu.Lock()
		registered := s.account.registration.Sequence != 0 || s.account.native.attempted
		s.account.mu.Unlock()
		if registered && protocol {
			continue
		} // retain until real whole-node destruction
		// Ordinary Remove remains strict for all registered/ambiguous accounts.
		if err := s.Remove(ctx, 0); err != nil {
			return err
		}
	}
	var cleanup error
	if protocol {
		cleanup = errors.Join(n.settleProtocolScopes(ctx, control, transport), n.settleSharedObjects(ctx, transport))
	}
	// Unknown outcome is not an unjoined invocation: protocol-only jobs have
	// synchronously returned, and this sole program has no attached consumers.
	// Keep every unresolved record/pin through actual collection destruction.
	err := errors.Join(cleanup, control.close())
	n.mu.Lock()
	n.host.cleanupErr = err
	n.host.commandsJoined = true // close joins even when it returns a sticky thread failure
	n.mu.Unlock()
	return err
}

func (n *NodeEnforcer) Stop(gc operators.GadgetContext) error {
	if gc == nil {
		return fmt.Errorf("missing shared host context")
	}
	return n.BeforeStop(gc.Context())
}

func (n *NodeEnforcer) Close(gc operators.GadgetContext) error {
	n.mu.Lock()
	valid := gc != nil && n.host != nil && n.host.context == gc
	n.mu.Unlock()
	if !valid {
		return fmt.Errorf("foreign shared host close")
	}
	err := n.BeforeStop(context.WithoutCancel(gc.Context()))
	n.mu.Lock()
	if !n.host.commandsJoined || (len(n.bindings) != 0 && n.host.protocol == nil) {
		n.mu.Unlock()
		if err != nil {
			return err
		}
		return fmt.Errorf("shared cleanup has not joined")
	}
	n.host.operatorClosed = true
	n.closed = true
	n.mu.Unlock()
	return err
}

// ReleaseAfterDetach is called only after HOST manager teardown has joined.
// Known borrowed handles must be closed too. No map-ID absence/RSS proof is
// inferred, and this method never closes a collection owned by that manager.
func (n *NodeEnforcer) ReleaseAfterDetach() error {
	n.mu.Lock()
	if n.host == nil {
		n.mu.Unlock()
		return fmt.Errorf("not a host-owned shared node")
	}
	if n.host.claimed && !n.host.operatorClosed {
		n.mu.Unlock()
		return fmt.Errorf("host shared operator teardown not joined")
	}
	if len(n.preparations) != 0 || n.host.startup.done != nil || (n.objects != nil && n.objects.operation.done != nil) || (len(n.bindings) != 0 && (n.host.protocol == nil || !n.host.commandsJoined || !n.host.operatorClosed)) {
		n.mu.Unlock()
		return fmt.Errorf("shared preparations/sessions have not joined")
	}
	for _, a := range n.scopes {
		if a.native.done != nil {
			n.mu.Unlock()
			return fmt.Errorf("native scope operation not joined")
		}
	}
	// Inspect both the retained partial-start ledger and current resource set.
	// No passing check is inferred from a map/manifest name or collection Close.
	for _, h := range append(n.host.resources.borrowedHandles(), n.host.borrowed...) {
		if h.FD() >= 0 {
			n.mu.Unlock()
			return fmt.Errorf("borrowed shared handles remain live")
		}
	}
	if n.objects != nil {
		// Unresolved records are destroyed with the actual protocol collection,
		// not converted into acknowledged native cleanup receipts.
		clear(n.objects.slots)
		clear(n.objects.records)
		clear(n.objects.scopes)
		n.objects.retainedBytes = 0
		n.objects.destroyed = true
	}
	n.host.released = true
	n.closed = true
	protocol := n.host.protocol != nil
	n.mu.Unlock()
	if protocol {
		n.retireProtocolSessionsAfterDetach()
	}
	// A failed trusted lease Close retains the account for this same retry path.
	return n.releasePhysicalScopes()
}
