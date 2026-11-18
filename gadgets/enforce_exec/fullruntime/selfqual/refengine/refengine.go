// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package refengine is the reference exec-enforcement engine of the D4
// self-qualification prototype (bpf/refengine.bpf.c): BPF LSM hooks, BTF
// tracepoints and CO-RE only. It is NOT the shared product engine; it exists
// so the qualification runner has an engine that loads on stock kernels.
package refengine

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/selfqual"
)

//go:embed refengine_bpfel.o
var object []byte

// Mutant selects a deliberately broken engine. Negative controls only.
type Mutant uint32

const (
	MutantNone Mutant = iota
	MutantAuditBlocks
	MutantFaultAllows
	MutantUnknownAllowed
	MutantSkipInterpPass
	MutantNoFreeze
	MutantCgroupEscape
	MutantFdpathBypass
	MutantThreadBypass
	MutantNoFailReconcile
	MutantDenyNoEvent
	MutantVforkUntrackedAllowed
	MutantRareBypass
	MutantNoAbortReconcile
)

// Mutants names every deterministic mutant (MutantRareBypass is statistical
// and is reported separately).
var Mutants = map[string]Mutant{
	"audit-blocks":            MutantAuditBlocks,
	"fault-allows":            MutantFaultAllows,
	"unknown-allowed":         MutantUnknownAllowed,
	"skip-interp-pass":        MutantSkipInterpPass,
	"no-freeze":               MutantNoFreeze,
	"cgroup-escape":           MutantCgroupEscape,
	"fdpath-bypass":           MutantFdpathBypass,
	"thread-bypass":           MutantThreadBypass,
	"no-fail-reconcile":       MutantNoFailReconcile,
	"deny-no-event":           MutantDenyNoEvent,
	"vfork-untracked-allowed": MutantVforkUntrackedAllowed,
	"no-abort-reconcile":      MutantNoAbortReconcile,
	"rare-bypass":             MutantRareBypass,
}

// Programs lists the engine's programs; a negative control may detach one.
var Programs = []string{"rq_task_alloc", "rq_bprm_check", "rq_sched_fork", "rq_sched_exec", "rq_sys_exit", "rq_sched_exit"}

// Options configures Load.
type Options struct {
	Mutant Mutant
	RareN  uint32 // MutantRareBypass: one bypass in RareN denies (0: 1024)
	// Detach names programs that are loaded but NOT attached (an injected
	// missing hook). Negative controls only.
	Detach []string
	// NonAtomicPublish makes Publish switch the generation BEFORE its rules
	// are in place. Negative controls only.
	NonAtomicPublish bool
}

// Engine implements selfqual.Engine.
type Engine struct {
	opts  Options
	coll  *ebpf.Collection
	links map[string]link.Link
	rd    *ringbuf.Reader

	mu      sync.Mutex
	nextGen uint64
	current map[uint64]uint64               // cgroup -> current generation
	rules   map[[2]uint64][]selfqual.FileID // (cgroup, gen) -> rule keys
}

type binding struct {
	Gen         uint64
	FaultInject uint32
	_           uint32
}

type genKey struct{ Cgroup, Gen uint64 }

type genMeta struct{ Mode, DefaultDeny uint32 }

type ruleKey struct{ Cgroup, Gen, Dev, Ino uint64 }

type rawEvent struct {
	Kind, Fault                              uint32
	Cgroup, Gen, ExecID, Dev, Ino            uint64
	PID, TID, Mode, Deny, Blocked, Pass, Out uint32
	Ret                                      int32
}

// Load loads and attaches the engine. Nothing is bound yet, so it decides
// nothing until Bind.
func Load(opts Options) (*Engine, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("reference engine spec: %w", err)
	}
	rare := opts.RareN
	if rare == 0 {
		rare = 1024
	}
	for name, v := range map[string]uint32{"rq_mutant": uint32(opts.Mutant), "rq_rare_n": rare} {
		variable, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("reference engine: no variable %s", name)
		}
		if err := variable.Set(v); err != nil {
			return nil, fmt.Errorf("reference engine: set %s: %w", name, err)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("reference engine load: %+v", ve)
		}
		return nil, fmt.Errorf("reference engine load: %w", err)
	}
	e := &Engine{opts: opts, coll: coll, links: map[string]link.Link{}, nextGen: 1, current: map[uint64]uint64{}, rules: map[[2]uint64][]selfqual.FileID{}}
	skip := map[string]bool{}
	for _, name := range opts.Detach {
		skip[name] = true
	}
	for _, name := range Programs {
		prog := coll.Programs[name]
		if prog == nil {
			e.Close()
			return nil, fmt.Errorf("reference engine: no program %s", name)
		}
		if skip[name] {
			continue
		}
		var l link.Link
		if prog.Type() == ebpf.LSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: prog})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: prog})
		}
		if err != nil {
			e.Close()
			return nil, fmt.Errorf("reference engine attach %s: %w", name, err)
		}
		e.links[name] = l
	}
	e.rd, err = ringbuf.NewReader(coll.Maps["rq_events"])
	if err != nil {
		e.Close()
		return nil, fmt.Errorf("reference engine events: %w", err)
	}
	return e, nil
}

// Identity is the loaded engine: the embedded object's sha256 and the kernel
// IDs of its attached links and programs.
func (e *Engine) Identity() selfqual.EngineIdentity {
	sum := sha256.Sum256(object)
	id := selfqual.EngineIdentity{ObjectSHA256: hex.EncodeToString(sum[:])}
	for _, name := range Programs {
		l, ok := e.links[name]
		if !ok {
			continue
		}
		info, err := l.Info()
		if err != nil {
			continue
		}
		id.Links = append(id.Links, selfqual.EngineLink{Name: name, LinkID: uint32(info.ID), ProgramID: uint32(info.Program)})
	}
	return id
}

func (e *Engine) Name() string {
	return fmt.Sprintf("refengine(mutant=%d,detach=%v,nonatomic=%v)", e.opts.Mutant, e.opts.Detach, e.opts.NonAtomicPublish)
}

// DetachProgram detaches one attached program (an injected missing hook after
// admission). Negative controls only.
func (e *Engine) DetachProgram(name string) error {
	l, ok := e.links[name]
	if !ok {
		return fmt.Errorf("program %s is not attached", name)
	}
	delete(e.links, name)
	return l.Close()
}

func (e *Engine) stage(cgroup, gen uint64, p selfqual.Policy) error {
	for _, id := range p.Allow {
		if err := e.coll.Maps["rq_rules"].Put(ruleKey{cgroup, gen, id.Dev, id.Ino}, uint32(1)); err != nil {
			return fmt.Errorf("stage rule: %w", err)
		}
	}
	e.rules[[2]uint64{cgroup, gen}] = append([]selfqual.FileID(nil), p.Allow...)
	if err := e.coll.Maps["rq_gens"].Put(genKey{cgroup, gen}, genMeta{Mode: uint32(p.Mode), DefaultDeny: 1}); err != nil {
		return fmt.Errorf("stage generation: %w", err)
	}
	return nil
}

func (e *Engine) publish(cgroup uint64, p selfqual.Policy, first bool) (uint64, error) {
	if p.Mode != selfqual.ModeAudit && p.Mode != selfqual.ModeStrict {
		return 0, fmt.Errorf("policy mode %d", p.Mode)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, bound := e.current[cgroup]; bound == first {
		return 0, fmt.Errorf("cgroup %d bound=%v", cgroup, bound)
	}
	gen := e.nextGen
	e.nextGen++
	flip := func() error {
		// One map-element replace: a reader sees the old generation or the
		// new one, never a mix.
		return e.coll.Maps["rq_bindings"].Put(cgroup, binding{Gen: gen})
	}
	if e.opts.NonAtomicPublish && !first {
		// The mutant: expose the generation, with its allow rules already in
		// place but its meta swapped in from the PREVIOUS generation's rules
		// only later. Readers in the window see the new number with a
		// permissive, empty-deny view.
		if err := e.coll.Maps["rq_gens"].Put(genKey{cgroup, gen}, genMeta{Mode: uint32(p.Mode), DefaultDeny: 0}); err != nil {
			return 0, err
		}
		if err := flip(); err != nil {
			return 0, err
		}
		time.Sleep(20 * time.Millisecond)
		if err := e.stage(cgroup, gen, p); err != nil {
			return 0, err
		}
		e.current[cgroup] = gen
		return gen, nil
	}
	if err := e.stage(cgroup, gen, p); err != nil {
		return 0, err
	}
	if err := flip(); err != nil {
		return 0, fmt.Errorf("publish generation: %w", err)
	}
	e.current[cgroup] = gen
	return gen, nil
}

func (e *Engine) Bind(cgroup uint64, p selfqual.Policy) (uint64, error) {
	return e.publish(cgroup, p, true)
}

func (e *Engine) Publish(cgroup uint64, p selfqual.Policy) (uint64, error) {
	return e.publish(cgroup, p, false)
}

func (e *Engine) retireLocked(cgroup, gen uint64) error {
	var errs []error
	if err := e.coll.Maps["rq_gens"].Delete(genKey{cgroup, gen}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, err)
	}
	for _, id := range e.rules[[2]uint64{cgroup, gen}] {
		if err := e.coll.Maps["rq_rules"].Delete(ruleKey{cgroup, gen, id.Dev, id.Ino}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	delete(e.rules, [2]uint64{cgroup, gen})
	return errors.Join(errs...)
}

func (e *Engine) Retire(cgroup, gen uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.current[cgroup] == gen {
		return fmt.Errorf("generation %d is current", gen)
	}
	return e.retireLocked(cgroup, gen)
}

func (e *Engine) InjectFault(cgroup uint64, on bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	gen, ok := e.current[cgroup]
	if !ok {
		return fmt.Errorf("cgroup %d is not bound", cgroup)
	}
	b := binding{Gen: gen}
	if on {
		b.FaultInject = 1
	}
	return e.coll.Maps["rq_bindings"].Put(cgroup, b)
}

func (e *Engine) Adopt(cgroup uint64, tid uint32) error {
	return e.coll.Maps["rq_adopt"].Put(tid, cgroup)
}

func (e *Engine) Unbind(cgroup uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.current[cgroup]; !ok {
		return nil
	}
	errs := []error{e.coll.Maps["rq_bindings"].Delete(cgroup)}
	for key := range e.rules {
		if key[0] == cgroup {
			errs = append(errs, e.retireLocked(cgroup, key[1]))
		}
	}
	delete(e.current, cgroup)
	return errors.Join(errs...)
}

func (e *Engine) Counters() (selfqual.Counters, error) {
	var c [17]uint64
	for i := range c {
		if err := e.coll.Maps["rq_counters"].Lookup(uint32(i), &c[i]); err != nil {
			return selfqual.Counters{}, fmt.Errorf("counter %d: %w", i, err)
		}
	}
	var g [2]int64
	for i := range g {
		if err := e.coll.Maps["rq_gauges"].Lookup(uint32(i), &g[i]); err != nil {
			return selfqual.Counters{}, fmt.Errorf("gauge %d: %w", i, err)
		}
	}
	return selfqual.Counters{
		Execs: c[0], Decisions: c[1], Allow: c[2], Deny: c[3], WouldDeny: c[4], FaultDeny: c[5],
		UnknownExec: c[6], UnknownFork: c[7], Births: c[8], Adopted: c[9], Exits: c[10],
		ExecOK: c[11], ExecFail: c[12], ExecAbort: c[13], StalePending: c[14], EventLost: c[15],
		StorageFail: c[16], Pending: g[0], Live: g[1],
	}, nil
}

func (e *Engine) ReadEvent(deadline time.Time) (selfqual.Event, error) {
	e.rd.SetDeadline(deadline)
	rec, err := e.rd.Read()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return selfqual.Event{}, os.ErrDeadlineExceeded
		}
		return selfqual.Event{}, err
	}
	var raw rawEvent
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
		return selfqual.Event{}, fmt.Errorf("decode event: %w", err)
	}
	return selfqual.Event{
		Kind: raw.Kind, Fault: raw.Fault, Cgroup: raw.Cgroup, Gen: raw.Gen, ExecID: raw.ExecID,
		File: selfqual.FileID{Dev: raw.Dev, Ino: raw.Ino}, PID: raw.PID, TID: raw.TID,
		Mode: selfqual.Mode(raw.Mode), Deny: raw.Deny != 0, Blocked: raw.Blocked != 0, Pass: raw.Pass,
		Outcome: raw.Out, Ret: raw.Ret,
	}, nil
}

func (e *Engine) Close() error {
	var errs []error
	if e.rd != nil {
		errs = append(errs, e.rd.Close())
	}
	for _, l := range e.links {
		errs = append(errs, l.Close())
	}
	e.links = map[string]link.Link{}
	if e.coll != nil {
		e.coll.Close()
		e.coll = nil
	}
	return errors.Join(errs...)
}
