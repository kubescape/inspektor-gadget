// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime owns immutable execution rules and mutable container membership.
package runtime

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	configKey   = "enforce-exec/config"
	bindingsKey = "enforce-exec/bindings"
)

// Config contains compiled immutable rules and initial container discovery selectors.
// Empty Targets protects no discovered containers. Bind can explicitly add targets.
type Config struct {
	Entries         [execpolicy.KernelMaxRules + 1]execpolicy.KernelEntry
	Targets         []execpolicy.Container
	InitialBindings []ContainerIdentity
}

func WithConfig(config Config) gadgetcontext.Option {
	config.Targets = append([]execpolicy.Container(nil), config.Targets...)
	config.InitialBindings = append([]ContainerIdentity(nil), config.InitialBindings...)
	return func(gc *gadgetcontext.GadgetContext) { gc.SetVar(configKey, config) }
}

type ContainerIdentity struct {
	Runtime, ID string
	CgroupID    uint64
	CgroupPath  string
}

func (c ContainerIdentity) validate() error {
	if strings.TrimSpace(c.Runtime) == "" || strings.TrimSpace(c.ID) == "" || c.CgroupID == 0 || c.CgroupPath == "/" || !path.IsAbs(c.CgroupPath) || path.Clean(c.CgroupPath) != c.CgroupPath {
		return fmt.Errorf("binding requires runtime, full container ID and non-root cgroup v2 identity")
	}
	return nil
}

func (c ContainerIdentity) selector() execpolicy.Container {
	return execpolicy.Container{Runtime: c.Runtime, ID: c.ID}
}

type Status struct {
	Revision uint64
	Bound    int
	Ready    bool
	Error    error
}
type bindingMap interface {
	Put(interface{}, interface{}) error
	Delete(interface{}) error
}

// Bindings serializes all writes. Map handles are borrowed from the eBPF operator.
type Bindings struct {
	mu              sync.Mutex
	config          Config
	desired         map[execpolicy.Container]ContainerIdentity
	active          map[uint64]ContainerIdentity
	members         bindingMap
	ready, stopped  bool
	startupComplete bool
	startupError    error
	lastError       error
}

// GetBindings is called from an operator lifecycle hook or after instance
// startup completes. Retain the returned controller for concurrent live writes.
func GetBindings(gc operators.GadgetContext) (*Bindings, error) {
	value, _ := gc.GetVar(bindingsKey)
	b, ok := value.(*Bindings)
	if !ok {
		return nil, fmt.Errorf("execution binding controller is unavailable")
	}
	return b, nil
}

func (b *Bindings) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	err := b.lastError
	if !b.startupComplete && b.startupError != nil {
		err = b.startupError
	}
	return Status{Revision: b.config.Entries[0].Generation, Bound: len(b.active), Ready: b.ready && b.startupComplete && !b.stopped, Error: err}
}

// Bind synchronously authorizes one exact container after this operator starts.
// A later operator may populate bindings before the final readiness check.
func (b *Bindings) Bind(c ContainerIdentity) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped {
		return b.recordError(fmt.Errorf("binding controller is not running"))
	}
	err := b.bind(c)
	b.recordError(err)
	return err
}

// recordError is called with mu held. Startup errors remain sticky even if a
// later unrelated binding succeeds; the entire candidate must then be replaced.
func (b *Bindings) recordError(err error) error {
	b.lastError = err
	if err != nil && !b.startupComplete && b.startupError == nil {
		b.startupError = err
	}
	return err
}

// Ready is the final startup boundary. Errors after this check are active-runtime
// failures returned to the owner and exposed through Status.
func (b *Bindings) Ready(operators.GadgetContext) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped {
		return fmt.Errorf("binding controller is not running")
	}
	if b.startupError != nil {
		return b.startupError
	}
	b.startupComplete = true
	return nil
}

func (b *Bindings) bind(c ContainerIdentity) error {
	if err := c.validate(); err != nil {
		return err
	}
	if previous, ok := b.active[c.CgroupID]; ok {
		if previous != c {
			return fmt.Errorf("cgroup identity conflicts with active binding")
		}
		return nil
	}
	for _, previous := range b.active {
		if previous.selector() == c.selector() {
			return fmt.Errorf("container identity already bound to a different cgroup")
		}
	}
	if len(b.active) >= execpolicy.KernelMaxBindings {
		return fmt.Errorf("container binding capacity exceeded")
	}
	if err := b.members.Put(c.CgroupID, uint64(1)); err != nil {
		return fmt.Errorf("writing container binding: %w", err)
	}
	b.active[c.CgroupID] = c
	return nil
}

// Unbind ignores stale removal notifications, which cannot remove a newer identity.
func (b *Bindings) Unbind(c ContainerIdentity) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped {
		return b.recordError(fmt.Errorf("binding controller is not running"))
	}
	err := b.unbind(c)
	b.recordError(err)
	return err
}

func (b *Bindings) unbind(c ContainerIdentity) error {
	if previous, ok := b.active[c.CgroupID]; !ok || previous != c {
		return nil
	}
	if err := b.members.Delete(c.CgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("removing container binding: %w", err)
	}
	delete(b.active, c.CgroupID)
	return nil
}

func (b *Bindings) container(kind string, c ContainerIdentity) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return nil
	}
	selected := false
	for _, target := range b.config.Targets {
		if target == c.selector() {
			selected = true
			break
		}
	}
	if !selected {
		return nil
	}
	if kind != "CREATED" && kind != "DELETED" {
		return nil
	}
	if err := c.validate(); err != nil {
		b.recordError(err)
		return err
	}
	if !b.ready {
		if kind == "CREATED" {
			b.desired[c.selector()] = c
		} else if b.desired[c.selector()] == c {
			delete(b.desired, c.selector())
		}
		return nil
	}
	var err error
	if kind == "CREATED" {
		err = b.bind(c)
	} else {
		err = b.unbind(c)
	}
	b.recordError(err)
	return err
}

type operator struct{}

func New() operators.DataOperator            { return &operator{} }
func init()                                  { operators.RegisterDataOperator(New()) }
func (*operator) Name() string               { return "enforce-exec" }
func (*operator) Priority() int              { return 1 }
func (*operator) Init(*params.Params) error  { return nil }
func (*operator) GlobalParams() api.Params   { return nil }
func (*operator) InstanceParams() api.Params { return nil }
func (*operator) InstantiateDataOperator(gc operators.GadgetContext, _ api.ParamValues) (operators.DataOperatorInstance, error) {
	value, _ := gc.GetVar("config")
	metadata, ok := value.(*viper.Viper)
	if !ok || !metadata.GetBool("annotations.enforce-exec") {
		return nil, nil
	}
	value, ok = gc.GetVar(configKey)
	config, valid := value.(Config)
	if !ok || !valid {
		return nil, fmt.Errorf("enforce_exec requires native policy configuration; use ig enforce-exec or runtime.WithConfig")
	}
	if err := execpolicy.ValidateKernel(config.Entries); err != nil {
		return nil, err
	}
	if len(config.Targets) > execpolicy.KernelMaxBindings {
		return nil, fmt.Errorf("too many container selectors")
	}
	seen := map[execpolicy.Container]bool{}
	for _, target := range config.Targets {
		if strings.TrimSpace(target.Runtime) == "" || strings.TrimSpace(target.ID) == "" || seen[target] {
			return nil, fmt.Errorf("invalid or duplicate container selector")
		}
		seen[target] = true
	}
	b := &Bindings{config: config, desired: map[execpolicy.Container]ContainerIdentity{}, active: map[uint64]ContainerIdentity{}}
	if len(config.InitialBindings) > execpolicy.KernelMaxBindings {
		return nil, fmt.Errorf("too many initial bindings")
	}
	for _, c := range config.InitialBindings {
		if err := c.validate(); err != nil {
			return nil, err
		}
		if _, exists := b.desired[c.selector()]; exists {
			return nil, fmt.Errorf("duplicate initial container identity")
		}
		b.desired[c.selector()] = c
	}
	ds := gc.GetDataSources()["containers"]
	if ds == nil {
		if len(config.Targets) > 0 {
			return nil, fmt.Errorf("enforce_exec discovery targets require the containers datasource")
		}
		gc.SetVar(bindingsKey, b)
		return b, nil
	}
	for _, field := range []string{"event_type", "runtime", "container_id", "cgroup_id", "cgroup_v2_path"} {
		if ds.GetField(field) == nil {
			return nil, fmt.Errorf("missing container field %s", field)
		}
	}
	if err := ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
		kind, e1 := ds.GetField("event_type").String(data)
		runtime, e2 := ds.GetField("runtime").String(data)
		id, e3 := ds.GetField("container_id").String(data)
		cg, e4 := ds.GetField("cgroup_id").Uint64(data)
		cgpath, e5 := ds.GetField("cgroup_v2_path").String(data)
		if err := errors.Join(e1, e2, e3, e4, e5); err != nil {
			b.mu.Lock()
			defer b.mu.Unlock()
			return b.recordError(err)
		}
		return b.container(kind, ContainerIdentity{Runtime: runtime, ID: id, CgroupID: cg, CgroupPath: cgpath})
	}, 0); err != nil {
		return nil, err
	}
	gc.SetVar(bindingsKey, b)
	return b, nil
}
func (*Bindings) Name() string { return "enforce-exec" }
func (b *Bindings) Start(gc operators.GadgetContext) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return fmt.Errorf("binding controller already stopped")
	}
	if b.startupError != nil {
		return b.startupError
	}
	getMap := func(name string) (*ebpf.Map, error) {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, ok := value.(*ebpf.Map)
		if !ok {
			return nil, fmt.Errorf("missing BPF map %s", name)
		}
		return m, nil
	}
	policy, err := getMap("policy")
	if err != nil {
		return err
	}
	members, err := getMap("bindings")
	if err != nil {
		return err
	}
	if policy.Type() != ebpf.Array || policy.KeySize() != 4 || policy.ValueSize() != 288 || policy.MaxEntries() != 9 || policy.Flags()&unix.BPF_F_RDONLY_PROG == 0 {
		return fmt.Errorf("invalid immutable policy map layout")
	}
	if members.Type() != ebpf.Hash || members.KeySize() != 8 || members.ValueSize() != 8 || members.MaxEntries() != execpolicy.KernelMaxBindings {
		return fmt.Errorf("invalid binding map layout")
	}
	for i, entry := range b.config.Entries {
		if err := policy.Put(uint32(i), entry); err != nil {
			return fmt.Errorf("writing policy: %w", err)
		}
	}
	if err := policy.Freeze(); err != nil {
		return fmt.Errorf("freezing policy: %w", err)
	}
	b.members = members
	for _, c := range b.desired {
		if err := b.bind(c); err != nil {
			b.recordError(err)
			return err
		}
	}
	b.desired = nil
	b.ready = true
	return nil
}

func (b *Bindings) Stop(operators.GadgetContext) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	b.ready = false
	return nil
}
func (b *Bindings) Close(gc operators.GadgetContext) error { return b.Stop(gc) }
