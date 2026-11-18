// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package selfqual is the D4 research prototype of behavioural kernel
// self-qualification for enforce_exec: instead of admitting a kernel by its
// exact BTF digest, build-id and release, the engine is loaded, driven through
// synthetic exec probes in throwaway cgroups, and admitted only if every probe
// shows the contract's syscall outcome AND the engine's own bookkeeping.
//
// It is TEST-ONLY. It is not a product admission path, and a pass is not
// proof of the contract on paths no probe exercises (see REPORT.md).
package selfqual

import "time"

// Mode is a policy's enforcement class.
type Mode uint32

const (
	ModeAudit  Mode = 1
	ModeStrict Mode = 2
)

func (m Mode) String() string {
	switch m {
	case ModeAudit:
		return "Audit"
	case ModeStrict:
		return "Strict"
	}
	return "Mode?"
}

// FileID identifies an executable file the way the kernel sees it: the
// superblock device (kernel encoding, major<<20|minor) and the inode number.
type FileID struct {
	Dev, Ino uint64
}

// Policy is the minimal policy the probes need: an allow-list with a default
// deny. Everything not listed is denied (Strict) or would-be denied (Audit).
type Policy struct {
	Mode  Mode
	Allow []FileID
	// Paths are the allowed fixtures' absolute paths in the stage's mount
	// namespace (E1: path-based engines).
	Paths []string
	// Spec, when set, is an engine-specific policy set that replaces the
	// allow-list (E1: fullpolicy policies with roles).
	Spec any
}

// Counters is the engine's kernel-side bookkeeping in contract terms. An
// engine adapter maps its own counters onto these. The first group only
// grows; Pending and Live are gauges and must return to their baseline.
type Counters struct {
	Execs        uint64 // execs that reached the decision hook
	Decisions    uint64 // classified decisions, one per binfmt pass
	Allow        uint64
	Deny         uint64 // Strict deny, blocked
	WouldDeny    uint64 // Audit deny, not blocked
	FaultDeny    uint64 // fault before classification, blocked in every mode
	UnknownExec  uint64 // exec by an untracked task in a bound cgroup, blocked
	UnknownFork  uint64 // fork by an untracked task in a bound cgroup, blocked
	Births       uint64 // tracked tasks that started running
	Adopted      uint64
	Exits        uint64
	ExecOK       uint64 // pending record settled by a completed exec
	ExecFail     uint64 // pending record settled by a failed exec
	ExecAbort    uint64 // pending record settled by task exit mid-exec
	StalePending uint64 // a pending record was found leaked
	EventLost    uint64
	StorageFail  uint64

	Pending int64 // execs between decision and outcome
	Live    int64 // tracked live tasks
}

// Sub returns c-o for the monotonic counters and c's gauges unchanged.
func (c Counters) Sub(o Counters) Counters {
	return Counters{
		Execs: c.Execs - o.Execs, Decisions: c.Decisions - o.Decisions, Allow: c.Allow - o.Allow,
		Deny: c.Deny - o.Deny, WouldDeny: c.WouldDeny - o.WouldDeny, FaultDeny: c.FaultDeny - o.FaultDeny,
		UnknownExec: c.UnknownExec - o.UnknownExec, UnknownFork: c.UnknownFork - o.UnknownFork,
		Births: c.Births - o.Births, Adopted: c.Adopted - o.Adopted, Exits: c.Exits - o.Exits,
		ExecOK: c.ExecOK - o.ExecOK, ExecFail: c.ExecFail - o.ExecFail, ExecAbort: c.ExecAbort - o.ExecAbort,
		StalePending: c.StalePending - o.StalePending, EventLost: c.EventLost - o.EventLost,
		StorageFail: c.StorageFail - o.StorageFail,
		Pending:     c.Pending, Live: c.Live,
	}
}

// Event kinds, faults and outcomes.
const (
	EventDecision = 1
	EventFault    = 2
	EventOutcome  = 3

	FaultUnknownTask  = 1
	FaultInjected     = 2
	FaultNoBinding    = 3
	FaultNoGeneration = 4
	FaultStorage      = 5

	OutcomeOK    = 1
	OutcomeFail  = 2
	OutcomeAbort = 3
)

// Event is one kernel-side record.
type Event struct {
	Kind    uint32
	Fault   uint32
	Cgroup  uint64
	Gen     uint64
	ExecID  uint64
	File    FileID
	PID     uint32
	TID     uint32
	Mode    Mode
	Deny    bool
	Blocked bool
	Pass    uint32
	Outcome uint32
	Ret     int32
}

// Engine is what the qualification runner drives. All of it is kernel state:
// the runner never asks the engine what it would do.
type Engine interface {
	Name() string
	// Bind binds a cgroup (by cgroup v2 id) to a first generation.
	Bind(cgroup uint64, p Policy) (gen uint64, err error)
	// Publish switches the cgroup to a new generation atomically.
	Publish(cgroup uint64, p Policy) (gen uint64, err error)
	// Retire removes a generation that is no longer current.
	Retire(cgroup, gen uint64) error
	// InjectFault makes every decision in the cgroup fault before
	// classification.
	InjectFault(cgroup uint64, on bool) error
	// Adopt tracks an existing task of a bound cgroup.
	Adopt(cgroup uint64, tid uint32) error
	Unbind(cgroup uint64) error
	Counters() (Counters, error)
	// ReadEvent returns the next event, or os.ErrDeadlineExceeded.
	ReadEvent(deadline time.Time) (Event, error)
	Close() error
}

// InitAdopter is implemented by engines that distinguish the binding's seeded
// init from other adopted tasks (E1: the root anchor is captured from it).
type InitAdopter interface {
	AdoptInit(cgroup uint64, tid uint32) error
}
