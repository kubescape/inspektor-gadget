// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package selfqual

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ErrNotQualified is returned for every run that does not admit.
var ErrNotQualified = errors.New("kernel not qualified by self-test")

// Options configures a run. The zero value is the full admission suite.
type Options struct {
	// Probes restricts the run to the named probes (empty: all).
	Probes []string
	// CanaryOnly runs the probes marked Canary.
	CanaryOnly bool
	// Shared relaxes the checks to what holds while real bindings are live
	// (a canary after admission): the global counter equalities are skipped
	// and only events from the probe cgroups are examined.
	Shared bool
	// RequireBinfmtMisc makes a kernel without binfmt_misc a failure instead
	// of "not applicable".
	RequireBinfmtMisc bool
	// Timeout bounds the whole run (0: 120 s); ProbeTimeout one probe step
	// (0: 15 s).
	Timeout, ProbeTimeout time.Duration
	// StormWorkers x StormIters x 2 execs per storm (0: 8 x 100).
	StormWorkers, StormIters int
	// RaceRounds repeats the race tokens (0: 6).
	RaceRounds int
	// UnsafeSkipStaticChecks runs the probes even when a static precondition
	// fails. Negative controls only: it shows what the probes alone detect.
	UnsafeSkipStaticChecks bool
	// HelperImage replaces the embedded helper. Negative controls only: it
	// shows that a helper with the wrong digest is refused.
	HelperImage []byte
	// InitExec (E1): after binding, adopt one probe root per bound cgroup as
	// the binding's seeded init (InitAdopter) and have it exec the allowed
	// fixture once, the way a container's init execs its entrypoint.
	InitExec bool
	// NoPendingGauge (E1): the engine keeps no pending-exec gauge (no
	// failure tracking), so a parked exec is not checked against it.
	NoPendingGauge bool
	// Log receives progress lines.
	Log func(format string, a ...any)
}

func (o Options) helperImage() []byte {
	if o.HelperImage != nil {
		return o.HelperImage
	}
	return helperBinary
}

func (o Options) probeTimeout() time.Duration {
	if o.ProbeTimeout > 0 {
		return o.ProbeTimeout
	}
	return 15 * time.Second
}

func (o Options) quiesceTimeout() time.Duration { return 3 * time.Second }

func (o Options) stormWorkers() int {
	if o.StormWorkers > 0 {
		return o.StormWorkers
	}
	return 8
}

func (o Options) stormIters() int {
	if o.StormIters > 0 {
		return o.StormIters
	}
	return 100
}

func (o Options) raceRounds() int {
	if o.RaceRounds > 0 {
		return o.RaceRounds
	}
	return 6
}

// ProbeResult is one probe in one mode.
type ProbeResult struct {
	Name     string        `json:"name"`
	Mode     string        `json:"mode"`
	Status   string        `json:"status"` // pass, FAIL, ERROR, not-applicable
	Detail   []string      `json:"detail,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

// Report is a qualification run.
type Report struct {
	Admitted bool   `json:"admitted"`
	Reason   string `json:"reason,omitempty"`
	Engine   string `json:"engine"`
	// EngineIdentity is the loaded engine the probes were driven through.
	// The admission gate matches it against the node's own engine.
	EngineIdentity EngineIdentity `json:"engine_identity"`
	Kernel         Fingerprint    `json:"kernel"`
	HelperSHA256   string         `json:"helper_sha256"`
	StaticCheck    string         `json:"static_check"`
	Probes         []ProbeResult  `json:"probes"`
	Passed         int            `json:"passed"`
	Failed         int            `json:"failed"`
	NotApplic      int            `json:"not_applicable"`
	Setup          time.Duration  `json:"setup_ns"`
	Duration       time.Duration  `json:"duration_ns"`
	Final          Counters       `json:"final_counters"`
}

// EngineLink is one attached program of an engine.
type EngineLink struct {
	Name      string `json:"name"`
	Target    string `json:"target"`
	LinkID    uint32 `json:"link_id"`
	ProgramID uint32 `json:"program_id"`
}

// EngineIdentity identifies a loaded engine: the sha256 of the object it was
// loaded from and the kernel IDs of its attached programs and links.
type EngineIdentity struct {
	ObjectSHA256 string       `json:"object_sha256"`
	Links        []EngineLink `json:"links"`
}

// Same reports whether e and o are the same loaded engine. An empty digest
// or an empty link set is never the same as anything.
func (e EngineIdentity) Same(o EngineIdentity) bool {
	if e.ObjectSHA256 == "" || len(e.Links) == 0 || e.ObjectSHA256 != o.ObjectSHA256 || len(e.Links) != len(o.Links) {
		return false
	}
	seen := map[EngineLink]bool{}
	for _, l := range e.Links {
		if l.LinkID == 0 || l.ProgramID == 0 {
			return false
		}
		seen[l] = true
	}
	for _, l := range o.Links {
		if !seen[l] {
			return false
		}
	}
	return len(seen) == len(e.Links)
}

// Run qualifies the running kernel for eng. It admits (nil error, Admitted)
// only if the static preconditions hold, every probe passes in both modes,
// the engine ends quiet and the teardown is clean. Everything else, a
// timeout and an error included, is ErrNotQualified: the caller must stay
// NotReady and must not enable real bindings.
//
// The engine must have no other binding while the full suite runs (Shared
// false): the suite reads the engine's global counters.
func Run(ctx context.Context, eng Engine, opts Options) (*Report, error) {
	start := time.Now()
	rep := &Report{Engine: eng.Name(), Kernel: ReadFingerprint(), HelperSHA256: helperSHA256}
	if id, ok := eng.(interface{ Identity() EngineIdentity }); ok {
		rep.EngineIdentity = id.Identity()
	}
	logf := opts.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	refuse := func(format string, a ...any) (*Report, error) {
		rep.Admitted = false
		rep.Reason = fmt.Sprintf(format, a...)
		rep.Duration = time.Since(start)
		logf("REFUSED: %s", rep.Reason)
		return rep, fmt.Errorf("%w: %s", ErrNotQualified, rep.Reason)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if !rep.Kernel.Complete() {
		return refuse("kernel fingerprint unreadable: %+v", rep.Kernel)
	}
	if err := StaticChecks(); err != nil {
		rep.StaticCheck = err.Error()
		if !opts.UnsafeSkipStaticChecks {
			return refuse("static check: %v", err)
		}
		logf("static check failed, continuing (UnsafeSkipStaticChecks): %v", err)
	} else {
		rep.StaticCheck = "ok"
	}
	for _, name := range opts.Probes {
		if !slices.ContainsFunc(Probes, func(p Probe) bool { return p.Name == name }) {
			return refuse("unknown probe %q", name)
		}
	}
	if !opts.Shared {
		c, err := eng.Counters()
		if err != nil {
			return refuse("engine counters: %v", err)
		}
		if c.Pending != 0 || c.Live != 0 {
			return refuse("engine is not idle before qualification (pending %d, live %d)", c.Pending, c.Live)
		}
	}
	s, err := newSession(eng, opts)
	if err != nil {
		return refuse("setup: %v", err)
	}
	rep.Setup = time.Since(start)
	closed := false
	defer func() {
		if !closed {
			s.close()
		}
	}()

	for _, p := range Probes {
		if len(opts.Probes) > 0 && !slices.Contains(opts.Probes, p.Name) {
			continue
		}
		if opts.CanaryOnly && !p.Canary {
			continue
		}
		for _, cg := range []*cgroupRef{s.strict, s.audit} {
			res := ProbeResult{Name: p.Name, Mode: cg.mode.String()}
			if err := ctx.Err(); err != nil {
				res.Status, res.Detail = "ERROR", []string{"qualification deadline: " + err.Error()}
				rep.Probes = append(rep.Probes, res)
				rep.Failed++
				continue
			}
			t0 := time.Now()
			bad, err := p.run(s, cg)
			res.Duration = time.Since(t0)
			switch {
			case errors.Is(err, errNotApplicable) && !opts.RequireBinfmtMisc:
				res.Status = "not-applicable"
				rep.NotApplic++
			case err != nil:
				res.Status, res.Detail = "ERROR", append(bad, err.Error())
				rep.Failed++
			case len(bad) > 0:
				res.Status, res.Detail = "FAIL", bad
				rep.Failed++
			default:
				res.Status = "pass"
				rep.Passed++
			}
			logf("%-18s %-6s %-14s %8.1f ms %v", p.Name, res.Mode, res.Status, float64(res.Duration.Microseconds())/1000, res.Detail)
			rep.Probes = append(rep.Probes, res)
		}
	}
	closed = true
	closeErr := s.close()
	final, cErr := eng.Counters()
	rep.Final = final
	rep.Duration = time.Since(start)
	switch {
	case rep.Failed > 0:
		return refuse("%d of %d probe runs failed", rep.Failed, len(rep.Probes))
	case rep.Passed == 0:
		return refuse("no probe ran")
	case closeErr != nil:
		return refuse("teardown: %v", closeErr)
	case cErr != nil:
		return refuse("engine counters: %v", cErr)
	case !opts.Shared && (final.Pending != 0 || final.Live != 0 || final.StalePending != 0 || final.EventLost != 0 || final.StorageFail != 0):
		return refuse("engine is not clean after qualification: %+v", final)
	case ctx.Err() != nil:
		return refuse("qualification deadline: %v", ctx.Err())
	}
	if err := RuntimeControls(); err != nil && !opts.UnsafeSkipStaticChecks {
		return refuse("runtime controls changed during qualification: %v", err)
	}
	rep.Admitted = true
	logf("ADMITTED: %d probe runs passed, %d not applicable, %.1f ms", rep.Passed, rep.NotApplic, float64(rep.Duration.Microseconds())/1000)
	return rep, nil
}
