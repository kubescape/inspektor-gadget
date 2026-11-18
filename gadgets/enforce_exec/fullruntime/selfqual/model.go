// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package selfqual

import (
	"fmt"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// fileSpec is what the kernel does with a fixture when nothing denies it: the
// files whose binfmt pass reaches the decision hook, in order, and the errno
// the exec ends with (0: the image runs).
type fileSpec struct {
	chain []string
	end   unix.Errno
}

var fileSpecs = map[string]fileSpec{
	"allow":          {chain: []string{"allow"}},
	"deny":           {chain: []string{"deny"}},
	"sh_ok":          {chain: []string{"sh_ok", "allow"}},
	"sh_deny_interp": {chain: []string{"sh_deny_interp", "deny"}},
	"sh_denied":      {chain: []string{"sh_denied", "allow"}},
	"sh_hold":        {chain: []string{"sh_hold", "hold_interp"}},
	"sh_nointerp":    {chain: []string{"sh_nointerp"}, end: unix.ENOENT},
	"sh_dirinterp":   {chain: []string{"sh_dirinterp"}, end: unix.EACCES},
	"garbage":        {chain: []string{"garbage"}, end: unix.ENOEXEC},
	"garbage_denied": {chain: []string{"garbage_denied"}, end: unix.ENOEXEC},
	"noperm":         {end: unix.EACCES},
	"missing":        {end: unix.ENOENT},
	"c1":             {chain: []string{"c1", "c2", "c3", "c4", "c5", "allow"}},
	"l1":             {chain: []string{"l1", "l2", "l3", "l4", "l5", "l6"}, end: unix.ELOOP},
	"bm_file":        {chain: []string{"bm_file", "allow"}},
}

// creatorBirths is how many tracked tasks a creator starts.
var creatorBirths = map[string]uint64{
	"self": 0, "fork": 1, "vfork": 1, "clonevm": 1, "spawn": 1, "into": 1,
	"thread": 5, "threadrace": 5, "exitrace": 2, "killrace": 1,
}

var racyCreators = []string{"threadrace", "exitrace", "killrace"}

type passExpect struct {
	file    string // "" : a file that is on no allow-list (memfd copy)
	deny    bool
	blocked bool
}

type expect struct {
	codes   []int
	passes  []passExpect
	outcome uint32 // 0: the exec never reached the decision hook
	ret     int32
	ran     bool
	births  uint64
	racy    bool
}

func splitToken(tok string) (creator, variant, file string, err error) {
	colon := strings.LastIndexByte(tok, ':')
	if colon < 0 {
		return "", "", "", fmt.Errorf("token %q", tok)
	}
	plus := strings.LastIndexByte(tok[:colon], '+')
	if plus < 0 {
		return "", "", "", fmt.Errorf("token %q", tok)
	}
	creator = tok[:plus]
	if strings.HasPrefix(creator, "into@") {
		creator = "into"
	}
	return creator, tok[plus+1 : colon], tok[colon+1:], nil
}

// model is the contract, stated once: what a token must do under a policy.
func (s *session) model(cg *cgroupRef, tok string) (expect, error) {
	creator, variant, file, err := splitToken(tok)
	if err != nil {
		return expect{}, err
	}
	births, ok := creatorBirths[creator]
	if !ok {
		return expect{}, fmt.Errorf("token %q: creator", tok)
	}
	spec, ok := fileSpecs[file]
	if !ok {
		return expect{}, fmt.Errorf("token %q: file", tok)
	}
	e := expect{births: births, racy: slices.Contains(racyCreators, creator)}
	if variant == "check" {
		// AT_EXECVE_CHECK executes nothing: no decision is due. Kernels
		// without the flag refuse it.
		e.codes = []int{99, int(unix.EINVAL)}
		return e, nil
	}
	pol := s.policies[cg.gen]
	for i, name := range spec.chain {
		p := passExpect{file: name}
		if variant == "memfd" && i == 0 {
			p.file = ""
			p.deny = true
		} else {
			p.deny = !pol.allow[s.st.files[name]]
		}
		p.blocked = p.deny && cg.mode == ModeStrict
		e.passes = append(e.passes, p)
		if p.blocked {
			e.outcome, e.ret, e.codes = OutcomeFail, -int32(unix.EPERM), []int{int(unix.EPERM)}
			return e, nil
		}
	}
	switch {
	case spec.end == 0:
		e.outcome, e.codes, e.ran = OutcomeOK, []int{0}, true
	case len(e.passes) > 0:
		e.outcome, e.ret, e.codes = OutcomeFail, -int32(spec.end), []int{int(spec.end)}
	default:
		e.codes = []int{int(spec.end)}
	}
	return e, nil
}

// exact checks a step of deterministic tokens against the model, token by
// token, and that the kernel recorded nothing beyond it.
func (s *session) exact(r *stepResult) []string {
	var bad []string
	fail := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	// A probe root that execs itself successfully is replaced by the image:
	// it cannot report, the image does.
	if n := len(r.spec.tokens); n > 0 && len(r.out.Results) == n-1 && strings.HasPrefix(r.spec.tokens[n-1], "self+") && r.out.Ran[r.root] {
		r.out.Results = append(r.out.Results, tokenResult{Token: r.spec.tokens[n-1], Code: 0, PID: r.root})
	}
	if len(r.out.Results) != len(r.spec.tokens) {
		fail("%d results for %d tokens (probe root status %d)", len(r.out.Results), len(r.spec.tokens), r.out.Done)
	}
	byPID := map[uint32][]Event{}
	for _, ev := range r.events {
		byPID[ev.PID] = append(byPID[ev.PID], ev)
	}
	var births uint64
	claimed, orphans := 0, 0
	for i, res := range r.out.Results {
		if i >= len(r.spec.tokens) || res.Token != r.spec.tokens[i] {
			fail("result %d is for %q", i, res.Token)
			continue
		}
		e, err := s.model(r.spec.cg, res.Token)
		if err != nil {
			fail("%v", err)
			continue
		}
		births += e.births
		if !slices.Contains(e.codes, res.Code) {
			fail("%s: code %d, contract says %v", res.Token, res.Code, e.codes)
		}
		if r.out.Ran[res.PID] != e.ran {
			fail("%s: image ran=%v, contract says %v", res.Token, r.out.Ran[res.PID], e.ran)
		}
		if res.PID == 0 {
			// The creator reported no pid (posix_spawn after a failed
			// exec): its events are checked by the invariants and by count.
			orphans += len(e.passes)
			if e.outcome != 0 {
				orphans++
			}
			continue
		}
		evs := byPID[res.PID]
		claimed += len(evs)
		var decisions []Event
		var outcome *Event
		for j := range evs {
			switch evs[j].Kind {
			case EventDecision:
				decisions = append(decisions, evs[j])
			case EventOutcome:
				if outcome != nil {
					fail("%s: two outcomes", res.Token)
				}
				outcome = &evs[j]
			default:
				fail("%s: unexpected event %+v", res.Token, evs[j])
			}
		}
		if len(decisions) != len(e.passes) {
			fail("%s: %d decisions, contract says %d", res.Token, len(decisions), len(e.passes))
		} else {
			for j, p := range e.passes {
				d := decisions[j]
				fileOK := d.File == s.st.files[p.file]
				if p.file == "" {
					_, onList := s.policies[d.Gen].allow[d.File]
					fileOK = !onList
				}
				if !fileOK || d.Deny != p.deny || d.Blocked != p.blocked || int(d.Pass) != j || d.Cgroup != r.spec.cg.id || d.Mode != r.spec.cg.mode {
					fail("%s: pass %d is %+v, contract says file %q deny=%v blocked=%v", res.Token, j, d, p.file, p.deny, p.blocked)
				}
			}
		}
		switch {
		case e.outcome == 0 && outcome != nil:
			fail("%s: outcome %+v for an exec that never reached the decision hook", res.Token, *outcome)
		case e.outcome != 0 && outcome == nil:
			fail("%s: no outcome recorded", res.Token)
		case e.outcome != 0 && (outcome.Outcome != e.outcome || outcome.Ret != e.ret):
			fail("%s: outcome %d ret %d, contract says %d ret %d", res.Token, outcome.Outcome, outcome.Ret, e.outcome, e.ret)
		}
	}
	if claimed+orphans != len(r.events) {
		fail("%d events, %d matched to tokens and %d expected without a pid", len(r.events), claimed, orphans)
	}
	if !s.opts.Shared && r.delta.Births != births {
		fail("%d tracked births, contract says %d", r.delta.Births, births)
	}
	return bad
}
