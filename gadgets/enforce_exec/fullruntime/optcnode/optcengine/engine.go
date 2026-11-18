// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package optcengine is the E1 prototype of the enforce_exec option C state
// model (design 005 §7, §9.2): the D4 reference engine's hook skeleton with
// commit at lsm/bprm_committed_creds, inheritance at lsm/task_alloc, no
// failure tracking, a pending record with uncertain bits, commit-time
// generation revalidation, the R31 root anchor captured in BPF, path facts
// through bpf_d_path, and the real fullpolicy evaluator (or its bounded-loop
// compat variant where bpf_loop is missing). TEST-ONLY.
package optcengine

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/selfqual"
)

// The product object carries no test switches (review R6). The test object
// (-DOC_TEST_BUILD) adds the mutants and test knobs the oracle uses. Both are
// the staged, bounded-loop build of the real fullpolicy evaluator: the only
// one the verifier accepts on every qualified kernel (E1).
//
//go:embed optc_product_bpfel.o
var objectProduct []byte

//go:embed optc_test_bpfel.o
var objectTest []byte

// ProductObject is the embedded product object (no test switches): the
// object admission pins and fingerprints.
func ProductObject() []byte { return objectProduct }

// ErrUnsupportedPolicy: the policy needs more than the loaded build can
// evaluate; the binding keeps its previous generation (NotReady upstream).
var ErrUnsupportedPolicy = errors.New("policy exceeds the engine's limits")

// Variant is the object that loaded.
type Variant string

const (
	VariantProduct Variant = "product" // no test switches
	VariantTest    Variant = "test"    // mutants and test knobs (-DOC_TEST_BUILD)
)

type Mutant uint32

const (
	MutantNone Mutant = iota
	MutantAuditBlocks
	MutantFaultAllows
	MutantNoAnchorCheck
	MutantNoRevalidate
	MutantNoReset
	MutantNoUncertain
	MutantNoInherit
	MutantSkipInterpPass
	MutantAnchorRecapture
	MutantWalkExhaustAllows
	MutantNoBracket
	MutantStageFaultAllows
	MutantReevalNoKill
	MutantOnlyProposedUnknown
	MutantR11Allows
	MutantNoRootCheck
	MutantNoReachCheck
	MutantNoDeletedCheck
	MutantActorFirstPass
	MutantAncestorSkipUnknown
	MutantAncestorOff
	MutantNoFreeze
	MutantRetiredAllows
	MutantWitnessOff
	MutantGuardOff
	MutantGuardAuditKills
	MutantGuardAnyReceipt
	MutantReevalNoRoles
	MutantKeepBlockedWork
	MutantEvalErrorAllows
	MutantReceiptUndecided
	MutantAnchorTidOnly
	MutantNoCeiling
	MutantSeedAllPolicies
	MutantReevalKillUnchecked // review C5: a refused re-evaluation kill counts as KILLED, no latch
	MutantLateAnchor          // review C4: the anchor is captured whatever the init did since Bind
	MutantLeafCgroupOnly      // R11: only the task's own cgroup is looked up
	MutantExeAnyMount         // review N1: the init's pre-exec image may be on its own mount namespace
)

var Programs = []string{"oc_task_alloc", "oc_sched_fork", "oc_sched_exit", "oc_sched_exec", "oc_bprm_creds", "oc_bprm_check", "oc_bprm_committed"}

// Options configures one engine instance.
type Options struct {
	Mutant Mutant
	// Product loads the product object (no test switches).
	Product bool
	// NoReevaluate turns the compromise-8 alternative off (baseline: a
	// commit under a superseded generation only makes the roles UNKNOWN).
	NoReevaluate bool
	// StageCap lowers the rule-window invocations per pass (0: 16).
	// Negative controls only: it shows a pass the windows cannot finish
	// is denied, not decided on a prefix of the rules.
	StageCap uint32
	// MaxTasks is the R12 ceiling of tracked tasks per binding (0: none).
	MaxTasks uint32
	// WrongInitStart records a wrong start time for the seeded init.
	// Negative controls only: no anchor may be captured then (review R6).
	WrongInitStart bool
	// UnsafeNoPublishLimit skips the publication limit check. Negative
	// controls only: it shows the in-kernel window cap is a backstop.
	UnsafeNoPublishLimit bool
	// StaleInitAdopt makes AdoptInit leave an init adopt entry without
	// naming the task as the binding's init (a stale or reused entry).
	// Negative controls only: no anchor may be captured from it.
	StaleInitAdopt bool
}

// RulesPerWindow is the rules one window invocation walks (staged builds).
const RulesPerWindow = 16

// DefaultStageCap is the window invocations per pass: 16 x 16 = 256 rules,
// the compiler's maximum, in 17 of the kernel's 33 tail calls.
const DefaultStageCap = 16

// Limits is what the loaded build can walk. Publication refuses a program
// with more rules (never a silent truncation).
type Limits struct {
	MaxRules       int
	WindowRules    int
	WindowCap      int
	Staged         bool
	TailCallsPerOp int
}

// Counter indexes of oc_counters (bpf/optc.bpf.c enum oc_counter).
const (
	CExecs = iota
	CDecisions
	CAllow
	CDeny
	CWouldDeny
	CFaultDeny
	CUnknownExec
	CUnknownFork
	CBirths
	CAdopted
	CExits
	CCommits
	CReservedFail
	CReservedAbort
	CStalePending
	CEventLost
	CStorageFail
	CFaultAllow
	CGenMismatch
	CKilled
	CReevalDenyReported
	CAnchorCaptured
	CPathUnknown
	CRootMismatch
	CUnreachable
	CDeleted
	CNoAnchor
	CInternalMount
	CUncertainCommit
	CCeiling
	CAnchorRefused  // review C4: an init exec after Bind, or a closed capture
	CNestedUnknown  // untracked tasks in a cgroup below a bound one
	CInitInWorkload // review N1: anchor refused, the init already ran a file of its own mount namespace
	CMax
)

// Event kinds and commit flags beyond selfqual's.
const (
	EventCommit = selfqual.EventOutcome

	FaultNoPending = 6
	FaultStage     = 8

	CommitGenMismatch = 1
	CommitKilled      = 2
	CommitReevalDeny  = 4
	CommitKnownDeny   = 8
	CommitFault       = 16
	CommitUncertain   = 32

	PathKnown        = 0
	PathNoAnchor     = 1
	PathRootMismatch = 2
	PathUnreachable  = 3
	PathInternal     = 4
	PathDeleted      = 5
	PathWalkUnknown  = 8
)

// Detail is an event with its option C part.
type Detail struct {
	selfqual.Event
	Error, AuditUnknown uint32
	PathReason, Class   uint32
	Roles               [8]uint64
	KnownMask           uint32
	Variant             uint32
	Path                string
	Flags               uint32 // commit flags
}

type Engine struct {
	opts    Options
	variant Variant
	object  []byte
	coll    *ebpf.Collection
	links   map[string]link.Link
	rd      *ringbuf.Reader
	loadErr map[Variant]string

	mu        sync.Mutex
	nextGen   uint64
	current   map[uint64]uint64            // cgroup -> current generation
	gens      map[uint64]genState          // generation -> its blobs
	epochs    map[uint64]map[string]uint64 // cgroup -> policy UID -> activation epoch
	initTID   map[uint64]uint32
	regStart  map[uint32]uint64 // init tid -> start ticks recorded at Bind (review C4)
	container map[uint64]string // cgroup -> container name the policies compile for
	fault     map[uint64]bool
	testFlags map[uint64]uint32
	initStart map[uint64]uint64
	clobber   map[uint64]bool
	idents    map[uint64]string // role and policy hashes -> names
	detailMu  sync.Mutex
	lastDet   map[uint32][]Detail
}

type genState struct {
	cgroup   uint64
	count    int
	class    uint32
	roleMask uint32
}

type binding struct {
	Gen         uint64
	FaultInject uint32
	Class       uint32
	InitTID     uint32
	Clobber     uint32
	InitStart   uint64 // USER_HZ ticks since boot (review R6)
	RoleMask    uint32 // role-bearing policy indexes of Gen (review R1)
	MaxTasks    uint32 // R12 ceiling (0: none)
	TestFlags   uint32
	_           uint32
}

// Test-only binding flags (bpf/optc.bpf.c OC_TF_*); the product object
// ignores them.
const (
	TestRetireAfterWindow = 1
	TestBracketFail       = 2
	TestKillFail          = 4 // review C5: the re-evaluation's SIGKILL is refused
)

type blobKey struct {
	Gen uint64
	Key uint32
	_   uint32
}

type adopt struct {
	Cgroup uint64
	IsInit uint32
	_      uint32
}

// Anchor is the binding's root anchor as BPF captured it.
type Anchor struct {
	RootIno                         uint64
	RootMntID, RootDev, MntNS, Init uint32
	CapturedNS                      uint64
}

type fePath struct {
	Length uint32
	Bytes  [256]byte
}

type rawEvent struct {
	Kind, Fault                              uint32
	Cgroup, Gen, ExecID, Dev, Ino            uint64
	PID, TID, Mode, Deny, Blocked, Pass, Out uint32
	Ret                                      int32
	Error, AuditUnknown, PathReason, Class   uint32
	Roles                                    [8]uint64
	KnownMask, Variant                       uint32
	Path                                     fePath
}

// Load loads and attaches the engine: the real evaluator first, the compat
// variant if the verifier refuses it (unless opts.Variant forces one).
func Load(opts Options) (*Engine, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}
	v, obj := VariantTest, objectTest
	if opts.Product {
		// Review M2: every test or negative-control option is refused.
		if opts.Mutant != MutantNone || opts.StageCap != 0 || opts.UnsafeNoPublishLimit || opts.StaleInitAdopt ||
			opts.WrongInitStart || opts.NoReevaluate {
			return nil, errors.New("option C engine: test switches requested on the product object")
		}
		v, obj = VariantProduct, objectProduct
	}
	return load(opts, v, obj)
}

func tail(s string, n int) string {
	if len(s) > n {
		return "..." + s[len(s)-n:]
	}
	return s
}

func joinLines(l []string) string {
	var b bytes.Buffer
	for _, s := range l {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	return b.String()
}

func load(opts Options, v Variant, obj []byte) (*Engine, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("spec: %w", err)
	}
	reeval := uint32(1)
	if opts.NoReevaluate {
		reeval = 0
	}
	stageCap := uint32(DefaultStageCap)
	if opts.StageCap != 0 {
		stageCap = opts.StageCap
	}
	vars := map[string]uint32{"oc_reeval": reeval, "oc_agent_tgid": uint32(os.Getpid())}
	if v == VariantTest {
		vars["oc_mutant"], vars["oc_stage_cap"] = uint32(opts.Mutant), stageCap
	}
	for name, val := range vars {
		variable, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("no variable %s", name)
		}
		if err := variable.Set(val); err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 64 << 20}})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load %s: %+v", v, ve)
		}
		return nil, fmt.Errorf("load %s: %w", v, err)
	}
	e := &Engine{
		opts: opts, variant: v, object: obj, coll: coll, links: map[string]link.Link{}, nextGen: 1,
		current: map[uint64]uint64{}, gens: map[uint64]genState{}, epochs: map[uint64]map[string]uint64{},
		initTID: map[uint64]uint32{}, regStart: map[uint32]uint64{}, container: map[uint64]string{}, fault: map[uint64]bool{}, clobber: map[uint64]bool{}, testFlags: map[uint64]uint32{}, initStart: map[uint64]uint64{}, idents: map[uint64]string{},
		lastDet: map[uint32][]Detail{},
	}
	for _, name := range Programs {
		prog := coll.Programs[name]
		if prog == nil {
			e.Close()
			return nil, fmt.Errorf("no program %s", name)
		}
		var l link.Link
		if prog.Type() == ebpf.LSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: prog})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: prog})
		}
		if err != nil {
			e.Close()
			return nil, fmt.Errorf("attach %s: %w", name, err)
		}
		e.links[name] = l
	}
	// Staged variants: the rule-window programs, reached by tail call.
	for arr, prog := range map[string]string{"oc_check_stages": "oc_check_stage", "oc_commit_stages": "oc_commit_stage"} {
		m, p := coll.Maps[arr], coll.Programs[prog]
		if m == nil && p == nil {
			continue
		}
		if m == nil || p == nil {
			e.Close()
			return nil, fmt.Errorf("stage %s/%s incomplete", arr, prog)
		}
		if err := m.Put(uint32(0), p); err != nil {
			e.Close()
			return nil, fmt.Errorf("stage %s: %w", arr, err)
		}
	}
	e.rd, err = ringbuf.NewReader(coll.Maps["oc_events"])
	if err != nil {
		e.Close()
		return nil, fmt.Errorf("events: %w", err)
	}
	if err := e.armWitness(); err != nil {
		e.Close()
		return nil, err
	}
	return e, nil
}

// Witness cells (bpf/optc.bpf.c enum oc_wcell).
const (
	wArmed = iota
	wLatched
	wExecUnmarked
	wForkUnmarked
	wGuardKills
	wMarkFail
	wExecSeen
	wForkSeen
	wLSMAlloc
	wLSMCreds
	wLSMCheck
	wLSMCommit
	wSignalFail
	wUndecided
	wMax
)

// Witness is the E4 exec/fork witness and exec-receipt guard state.
type Witness struct {
	Armed, Latched                          bool
	ExecUnmarked, ForkUnmarked, GuardKills  uint64
	MarkFail, ExecSeen, ForkSeen            uint64
	LSMAlloc, LSMCreds, LSMCheck, LSMCommit uint64
	SignalFail, Undecided                   uint64
}

// Witness reads the witness cells.
func (e *Engine) Witness() (Witness, error) {
	var c [wMax]uint64
	for i := range c {
		if err := e.coll.Maps["oc_witness"].Lookup(uint32(i), &c[i]); err != nil {
			return Witness{}, fmt.Errorf("witness cell %d: %w", i, err)
		}
	}
	return Witness{Armed: c[wArmed] != 0, Latched: c[wLatched] != 0, ExecUnmarked: c[wExecUnmarked],
		ForkUnmarked: c[wForkUnmarked], GuardKills: c[wGuardKills], MarkFail: c[wMarkFail],
		ExecSeen: c[wExecSeen], ForkSeen: c[wForkSeen], LSMAlloc: c[wLSMAlloc], LSMCreds: c[wLSMCreds],
		LSMCheck: c[wLSMCheck], LSMCommit: c[wLSMCommit], SignalFail: c[wSignalFail], Undecided: c[wUndecided]}, nil
}

// Ready is false once the witness has latched (an exec or fork the LSM
// hooks did not see: ftrace off, programs detached), and once any task
// record, work area or witness mark could not be allocated (review R4: a
// fail-closed path the node should report). Sticky until restart.
func (e *Engine) Ready() (bool, error) {
	w, err := e.Witness()
	if err != nil {
		return false, err
	}
	sf, err := e.Raw(CStorageFail)
	if err != nil {
		return false, err
	}
	return w.Armed && !w.Latched && w.MarkFail == 0 && sf == 0, nil
}

// WorkArea reports whether the task behind pidfd holds an exec work area.
func (e *Engine) WorkArea(pidfd int) (bool, error) {
	v, err := e.coll.Maps["oc_works"].LookupBytes(uint32(pidfd))
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, nil
	}
	return err == nil && v != nil, err
}

// armWitness is the start canary: a fork and exec of this agent must each
// reach both the LSM hook and the tracepoint; only then does the witness
// latch on unmarked events (events straddling the attach are not latched).
// Review M9: the LSM counters are node-wide, so another task's fork or exec
// in the same instant can satisfy a counter for the canary's; the canary
// proves each program is attached and runs, not that it ran for the
// canary's own task.
func (e *Engine) armWitness() error {
	before, err := e.Witness()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if out, err := exec.Command("/bin/true").CombinedOutput(); err != nil {
			return fmt.Errorf("witness canary: %v %s", err, out)
		}
		now, err := e.Witness()
		if err != nil {
			return err
		}
		// Review E4-1: all four LSM programs and both tracepoints ran.
		if now.ExecSeen > before.ExecSeen && now.ForkSeen > before.ForkSeen && now.LSMAlloc > before.LSMAlloc &&
			now.LSMCreds > before.LSMCreds && now.LSMCheck > before.LSMCheck && now.LSMCommit > before.LSMCommit {
			return e.coll.Maps["oc_witness"].Put(uint32(wArmed), uint64(1))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("witness canary: the hooks did not see the canary (%+v)", now)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Limits of the loaded build.
func (e *Engine) Limits() Limits {
	c := DefaultStageCap
	if e.opts.StageCap != 0 {
		c = int(e.opts.StageCap)
	}
	return Limits{MaxRules: min(fullpolicy.MaxRules, c*RulesPerWindow), WindowRules: RulesPerWindow, WindowCap: c, Staged: true, TailCallsPerOp: c + 1}
}

// ClearStages empties the rule-window program slots. Negative controls only:
// a pass whose window cannot run must be denied in every mode.
func (e *Engine) ClearStages() error {
	for _, arr := range []string{"oc_check_stages", "oc_commit_stages"} {
		m := e.coll.Maps[arr]
		if m == nil {
			return fmt.Errorf("%s: not a staged build", arr)
		}
		if err := m.Delete(uint32(0)); err != nil {
			return fmt.Errorf("%s: %w", arr, err)
		}
	}
	return nil
}

// Variant is the evaluator build that loaded; LoadErrors the verifier
// refusals of the builds tried before it.
func (e *Engine) Variant() Variant               { return e.variant }
func (e *Engine) LoadErrors() map[Variant]string { return e.loadErr }

func (e *Engine) Name() string {
	return fmt.Sprintf("optcengine(variant=%s,mutant=%d,reeval=%v)", e.variant, e.opts.Mutant, !e.opts.NoReevaluate)
}

func (e *Engine) Identity() selfqual.EngineIdentity {
	sum := sha256.Sum256(e.object)
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

// AllowList is the policy a selfqual.Policy without Spec stands for: one
// policy, default deny, an exact-path allow rule.
func AllowList(mode selfqual.Mode, paths []string) []fullpolicy.Policy {
	m := fullpolicy.Enforce
	if mode == selfqual.ModeAudit {
		m = fullpolicy.Audit
	}
	p := fullpolicy.Policy{ID: "e1-allowlist", Revision: "1", Mode: m, Default: fullpolicy.Deny}
	if len(paths) > 0 {
		p.Rules = []fullpolicy.Rule{{Name: "allow", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: append([]string(nil), paths...)}}}
	}
	return []fullpolicy.Policy{p}
}

func (e *Engine) policies(p selfqual.Policy) ([]fullpolicy.Policy, error) {
	if p.Spec != nil {
		ps, ok := p.Spec.([]fullpolicy.Policy)
		if !ok {
			return nil, fmt.Errorf("policy spec %T", p.Spec)
		}
		return ps, nil
	}
	if p.Mode != selfqual.ModeAudit && p.Mode != selfqual.ModeStrict {
		return nil, fmt.Errorf("policy mode %d", p.Mode)
	}
	return AllowList(p.Mode, p.Paths), nil
}

// class is fe_execution_class over the compiled program: 2 if any policy or
// rule enforces, else 1.
func class(prog *fullpolicy.KernelProgram) (uint32, error) {
	h, err := fullpolicy.Decode[fullpolicy.KernelHeader](prog.Entries[0])
	if err != nil {
		return 0, err
	}
	c := uint32(1)
	for i := 0; i < int(h.PolicyCount); i++ {
		p, err := fullpolicy.Decode[fullpolicy.KernelPolicy](prog.Entries[fullpolicy.KernelPolicyBase+i])
		if err != nil {
			return 0, err
		}
		c = max(c, p.Mode)
	}
	for i := 0; i < int(h.RuleCount); i++ {
		r, err := fullpolicy.Decode[fullpolicy.KernelRule](prog.Entries[fullpolicy.KernelRuleBase+i])
		if err != nil {
			return 0, err
		}
		c = max(c, r.Mode)
	}
	return c, nil
}

// roleMask: the policy indexes that write or test roles (review R1). Every
// policy has a root role; one without role rules needs no row, since no rule
// can move or test a task's role under it. A later generation that adds a
// role rule to it finds no row for tasks adopted before: their role is
// UNKNOWN there (fail closed, as for any role the engine did not track).
func roleMask(prog *fullpolicy.KernelProgram) (uint32, error) {
	h, err := fullpolicy.Decode[fullpolicy.KernelHeader](prog.Entries[0])
	if err != nil {
		return 0, err
	}
	var m uint32
	for i := 0; i < int(h.RuleCount); i++ {
		r, err := fullpolicy.Decode[fullpolicy.KernelRule](prog.Entries[fullpolicy.KernelRuleBase+i])
		if err != nil {
			return 0, err
		}
		if r.SetRole != 0 || r.ActorRole.Count != 0 {
			m |= 1 << r.PolicyIndex
		}
	}
	return m, nil
}

// startTicks is /proc/<pid>/stat field 22 (USER_HZ ticks since boot).
func startTicks(pid uint32) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, fmt.Errorf("stat of %d", pid)
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return 0, fmt.Errorf("stat of %d", pid)
	}
	return strconv.ParseUint(f[19], 10, 64)
}

// SetTestFlags sets a binding's test flags (test object only).
func (e *Engine) SetTestFlags(cgroup uint64, flags uint32) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.testFlags[cgroup] = flags
	return e.writeBinding(cgroup)
}

// DetachLSM closes the four LSM links, ReattachLSM recreates them: a
// silencer that works where ftrace cannot be turned off (review E4-2).
func (e *Engine) DetachLSM() error {
	for _, name := range lsmPrograms {
		if l, ok := e.links[name]; ok {
			if err := l.Close(); err != nil {
				return err
			}
			delete(e.links, name)
		}
	}
	return nil
}

func (e *Engine) ReattachLSM() error {
	for _, name := range lsmPrograms {
		if _, ok := e.links[name]; ok {
			continue
		}
		l, err := link.AttachLSM(link.LSMOptions{Program: e.coll.Programs[name]})
		if err != nil {
			return fmt.Errorf("reattach %s: %w", name, err)
		}
		e.links[name] = l
	}
	return nil
}

// DetachProgram closes one program's link (test silencer); ReattachLSM
// restores it.
func (e *Engine) DetachProgram(name string) error {
	l, ok := e.links[name]
	if !ok {
		return fmt.Errorf("program %s is not attached", name)
	}
	delete(e.links, name)
	return l.Close()
}

var lsmPrograms = []string{"oc_task_alloc", "oc_bprm_creds", "oc_bprm_check", "oc_bprm_committed"}

func (e *Engine) writeBinding(cgroup uint64) error {
	gen := e.current[cgroup]
	b := binding{Gen: gen, Class: e.gens[gen].class, InitTID: e.initTID[cgroup], RoleMask: e.gens[gen].roleMask,
		MaxTasks: e.opts.MaxTasks, TestFlags: e.testFlags[cgroup], InitStart: e.initStart[cgroup]}
	if e.fault[cgroup] {
		b.FaultInject = 1
	}
	if e.clobber[cgroup] {
		b.Clobber = 1
	}
	// Review 2: the count first, so the in-kernel ancestor walk for
	// untracked tasks is on before the binding exists.
	if err := e.writeBindCount(); err != nil {
		return err
	}
	return e.coll.Maps["oc_bindings"].Put(cgroup, b)
}

// writeBindCount publishes the number of bindings (the in-kernel ancestor
// walk for untracked tasks runs only while there are any).
func (e *Engine) writeBindCount() error {
	return e.coll.Maps["oc_nbind"].Put(uint32(0), uint32(len(e.current)))
}

// initReg mirrors struct oc_init.
type initReg struct {
	Cgroup        uint64
	Execs, Closed uint32
}

// RegisterInit (review C4) names tid as cgroup's init at Bind, before any
// policy: its start time is recorded now, and the kernel counts its execs
// from now on. The anchor is captured only at its first exec since; an init
// that exec'd before (or a late bind after the entrypoint ran) never
// anchors, and the binding stays NotReady.
func (e *Engine) RegisterInit(cgroup uint64, tid uint32) error {
	start, err := startTicks(tid)
	if err != nil {
		return fmt.Errorf("init %d: %w", tid, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.coll.Maps["oc_inits"].Update(tid, initReg{Cgroup: cgroup}, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("register init %d: %w", tid, err)
	}
	e.regStart[tid] = start
	return nil
}

// UnregisterInit forgets tid (its binding was removed before any policy).
func (e *Engine) UnregisterInit(tid uint32) error {
	e.mu.Lock()
	delete(e.regStart, tid)
	e.mu.Unlock()
	if err := e.coll.Maps["oc_inits"].Delete(tid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// CloseInit ends tid's anchor capture (the bind deadline passed): a later
// exec never captures.
func (e *Engine) CloseInit(tid uint32) error {
	var r initReg
	if err := e.coll.Maps["oc_inits"].Lookup(tid, &r); err != nil {
		return err
	}
	r.Closed = 1
	return e.coll.Maps["oc_inits"].Put(tid, r)
}

// InitState reports tid's execs since Bind and whether capture is closed.
func (e *Engine) InitState(tid uint32) (execs uint32, closed, ok bool, err error) {
	var r initReg
	err = e.coll.Maps["oc_inits"].Lookup(tid, &r)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return 0, false, false, nil
	}
	return r.Execs, r.Closed != 0, err == nil, err
}

func (e *Engine) publish(cgroup uint64, p selfqual.Policy, first bool) (uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, bound := e.current[cgroup]; bound == first {
		return 0, fmt.Errorf("cgroup %d bound=%v", cgroup, bound)
	}
	ps, err := e.policies(p)
	if err != nil {
		return 0, err
	}
	gen := e.nextGen
	activated := map[string]uint64{}
	for id, ep := range e.epochs[cgroup] {
		activated[id] = ep
	}
	cname := e.container[cgroup]
	if cname == "" {
		cname = "e1-container"
	}
	prog, err := fullpolicy.CompileKernelWithRoleEpochs(ps, gen, cname, activated)
	if err != nil {
		return 0, fmt.Errorf("compile: %w", err)
	}
	c, err := class(prog)
	if err != nil {
		return 0, err
	}
	rmask, err := roleMask(prog)
	if err != nil {
		return 0, err
	}
	h, err := fullpolicy.Decode[fullpolicy.KernelHeader](prog.Entries[0])
	if err != nil {
		return 0, err
	}
	if lim := e.Limits(); int(h.RuleCount) > lim.MaxRules && !e.opts.UnsafeNoPublishLimit {
		return 0, fmt.Errorf("%w: %d rules, the loaded %s build walks at most %d", ErrUnsupportedPolicy, h.RuleCount, e.variant, lim.MaxRules)
	}
	// Stage the generation's blobs, then flip the binding (atomic publish).
	for i, blob := range prog.Entries {
		if err := e.coll.Maps["oc_blobs"].Put(blobKey{Gen: gen, Key: uint32(i)}, blob[:]); err != nil {
			e.dropBlobs(gen, i)
			return 0, fmt.Errorf("stage blob %d: %w", i, err)
		}
	}
	e.nextGen++
	e.gens[gen] = genState{cgroup: cgroup, count: len(prog.Entries), class: c, roleMask: rmask}
	for h, name := range prog.Identities {
		e.idents[h] = name
	}
	prev, had := e.current[cgroup]
	e.current[cgroup] = gen
	if err := e.writeBinding(cgroup); err != nil {
		if had {
			e.current[cgroup] = prev
		} else {
			delete(e.current, cgroup)
		}
		return 0, fmt.Errorf("publish generation: %w", err)
	}
	if e.epochs[cgroup] == nil {
		e.epochs[cgroup] = map[string]uint64{}
	}
	for _, pol := range ps {
		if _, ok := e.epochs[cgroup][pol.ID]; !ok {
			e.epochs[cgroup][pol.ID] = gen
		}
	}
	return gen, nil
}

func (e *Engine) dropBlobs(gen uint64, count int) {
	for i := 0; i < count; i++ {
		_ = e.coll.Maps["oc_blobs"].Delete(blobKey{Gen: gen, Key: uint32(i)})
	}
}

func (e *Engine) Bind(cgroup uint64, p selfqual.Policy) (uint64, error) {
	return e.publish(cgroup, p, true)
}

// Publish makes a new generation current. It never waits for execs in
// flight (option C, R6): execs that begin afterwards freeze it.
func (e *Engine) Publish(cgroup uint64, p selfqual.Policy) (uint64, error) {
	return e.publish(cgroup, p, false)
}

// BindPolicies binds cgroup with its first generation, compiled for the
// named container.
func (e *Engine) BindPolicies(cgroup uint64, container string, ps []fullpolicy.Policy) (uint64, error) {
	e.mu.Lock()
	e.container[cgroup] = container
	e.mu.Unlock()
	gen, err := e.publish(cgroup, selfqual.Policy{Spec: ps}, true)
	if err != nil {
		e.mu.Lock()
		delete(e.container, cgroup)
		e.mu.Unlock()
	}
	return gen, err
}

// PublishPolicies publishes an explicit fullpolicy policy set.
func (e *Engine) PublishPolicies(cgroup uint64, ps []fullpolicy.Policy) (uint64, error) {
	return e.publish(cgroup, selfqual.Policy{Spec: ps}, false)
}

// Retire drops a superseded generation's blobs.
func (e *Engine) Retire(cgroup, gen uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.current[cgroup] == gen {
		return fmt.Errorf("generation %d is current", gen)
	}
	g, ok := e.gens[gen]
	if !ok || g.cgroup != cgroup {
		return fmt.Errorf("generation %d of cgroup %d unknown", gen, cgroup)
	}
	e.dropBlobs(gen, g.count)
	delete(e.gens, gen)
	return nil
}

func (e *Engine) InjectFault(cgroup uint64, on bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.current[cgroup]; !ok {
		return fmt.Errorf("cgroup %d is not bound", cgroup)
	}
	e.fault[cgroup] = on
	return e.writeBinding(cgroup)
}

// ClobberStamp makes every pass of the binding write a foreign owner stamp.
// Negative controls only: the owner check must turn it into a stage fault.
func (e *Engine) ClobberStamp(cgroup uint64, on bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clobber[cgroup] = on
	return e.writeBinding(cgroup)
}

func (e *Engine) Adopt(cgroup uint64, tid uint32) error {
	return e.coll.Maps["oc_adopt"].Put(tid, adopt{Cgroup: cgroup})
}

// AdoptInit adopts tid as the binding's seeded init: the root anchor is
// captured from its first exec.
func (e *Engine) AdoptInit(cgroup uint64, tid uint32) error {
	// An init not registered at Bind is registered now (the oracle seeds
	// its init and adopts it at once).
	if _, _, ok, err := e.InitState(tid); err != nil {
		return err
	} else if !ok {
		if err := e.RegisterInit(cgroup, tid); err != nil {
			return err
		}
	}
	e.mu.Lock()
	if !e.opts.StaleInitAdopt {
		e.initTID[cgroup] = tid
		// The start time recorded at Bind (review C4): a pid reused
		// since never matches.
		start, ok := e.regStart[tid]
		if !ok {
			e.mu.Unlock()
			return fmt.Errorf("init %d: no start time", tid)
		}
		if e.opts.WrongInitStart {
			start++
		}
		e.initStart[cgroup] = start
	}
	err := e.writeBinding(cgroup)
	e.mu.Unlock()
	if err != nil {
		return err
	}
	return e.coll.Maps["oc_adopt"].Put(tid, adopt{Cgroup: cgroup, IsInit: 1})
}

// Anchor returns the binding's captured root anchor (ok false: none yet).
func (e *Engine) Anchor(cgroup uint64) (Anchor, bool, error) {
	var a Anchor
	err := e.coll.Maps["oc_anchors"].Lookup(cgroup, &a)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return a, false, nil
	}
	return a, err == nil, err
}

func (e *Engine) Unbind(cgroup uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.current[cgroup]; !ok {
		return nil
	}
	errs := []error{e.coll.Maps["oc_bindings"].Delete(cgroup)}
	if err := e.coll.Maps["oc_anchors"].Delete(cgroup); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, err)
	}
	for gen, g := range e.gens {
		if g.cgroup == cgroup {
			e.dropBlobs(gen, g.count)
			delete(e.gens, gen)
		}
	}
	delete(e.current, cgroup)
	delete(e.epochs, cgroup)
	if tid, ok := e.initTID[cgroup]; ok {
		delete(e.regStart, tid)
	}
	delete(e.initTID, cgroup)
	delete(e.container, cgroup)
	var tid uint32
	var r initReg
	for it := e.coll.Maps["oc_inits"].Iterate(); it.Next(&tid, &r); {
		if r.Cgroup == cgroup {
			_ = e.coll.Maps["oc_inits"].Delete(tid)
		}
	}
	errs = append(errs, e.writeBindCount())
	return errors.Join(errs...)
}

// RecordSize is the value size of a task record (oc_tasks) and of a mark.
func (e *Engine) RecordSize() uint32 {
	return e.coll.Maps["oc_tasks"].ValueSize() + e.coll.Maps["oc_marks"].ValueSize()
}

// Raw reads one counter of oc_counters.
func (e *Engine) Raw(idx int) (uint64, error) {
	var v uint64
	err := e.coll.Maps["oc_counters"].Lookup(uint32(idx), &v)
	return v, err
}

func (e *Engine) Counters() (selfqual.Counters, error) {
	var c [CMax]uint64
	for i := range c {
		if err := e.coll.Maps["oc_counters"].Lookup(uint32(i), &c[i]); err != nil {
			return selfqual.Counters{}, fmt.Errorf("counter %d: %w", i, err)
		}
	}
	var g [2]int64
	for i := range g {
		if err := e.coll.Maps["oc_gauges"].Lookup(uint32(i), &g[i]); err != nil {
			return selfqual.Counters{}, fmt.Errorf("gauge %d: %w", i, err)
		}
	}
	// Faults: blocked ones in FaultDeny; allowed (audit-only class) ones are
	// reported through events and FaultAllow (Raw).
	return selfqual.Counters{
		Execs: c[CExecs], Decisions: c[CDecisions], Allow: c[CAllow], Deny: c[CDeny], WouldDeny: c[CWouldDeny],
		FaultDeny: c[CFaultDeny], UnknownExec: c[CUnknownExec], UnknownFork: c[CUnknownFork], Births: c[CBirths],
		Adopted: c[CAdopted], Exits: c[CExits], ExecOK: c[CCommits], StalePending: c[CStalePending],
		EventLost: c[CEventLost], StorageFail: c[CStorageFail], Pending: g[0], Live: g[1],
	}, nil
}

// RoleName maps a role or policy hash to its name ("" if unknown).
func (e *Engine) RoleName(h uint64) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.idents[h]
}

// Details returns the option C details of the events of pid, in order.
func (e *Engine) Details(pid uint32) []Detail {
	e.detailMu.Lock()
	defer e.detailMu.Unlock()
	return append([]Detail(nil), e.lastDet[pid]...)
}

// ResetDetails forgets every event detail.
func (e *Engine) ResetDetails() {
	e.detailMu.Lock()
	e.lastDet = map[uint32][]Detail{}
	e.detailMu.Unlock()
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
	n := raw.Path.Length
	if n > 255 {
		n = 0
	}
	d := Detail{
		Error: raw.Error, AuditUnknown: raw.AuditUnknown, PathReason: raw.PathReason, Class: raw.Class,
		Roles: raw.Roles, KnownMask: raw.KnownMask, Variant: raw.Variant, Path: string(raw.Path.Bytes[:n]),
	}
	if raw.Kind == EventCommit {
		d.Flags = raw.Out
	}
	out := uint32(0)
	if raw.Kind == EventCommit {
		out = selfqual.OutcomeOK
	}
	ev := selfqual.Event{
		Kind: raw.Kind, Fault: raw.Fault, Cgroup: raw.Cgroup, Gen: raw.Gen, ExecID: raw.ExecID,
		File: selfqual.FileID{Dev: raw.Dev, Ino: raw.Ino}, PID: raw.PID, TID: raw.TID,
		Mode: selfqual.Mode(raw.Mode), Deny: raw.Deny != 0, Blocked: raw.Blocked != 0, Pass: raw.Pass,
		Outcome: out, Ret: raw.Ret,
	}
	d.Event = ev
	e.detailMu.Lock()
	e.lastDet[raw.PID] = append(e.lastDet[raw.PID], d)
	e.detailMu.Unlock()
	return ev, nil
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
