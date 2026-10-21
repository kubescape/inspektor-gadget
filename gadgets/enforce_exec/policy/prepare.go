// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import (
	"errors"
	"strings"
)

const ParameterName = "exec-policy"

var ErrBackendUnavailable = errors.New("enforce_exec: policy validated, but enforcement backend unavailable; no enforcement was installed")

// Prepared is gadget-local validated configuration, not attachment readiness.
// Its document is private so callers cannot change it after validation.
type Prepared struct{ document Document }

func Prepare(raw string) (*Prepared, error) {
	d, err := Parse(strings.NewReader(raw), DefaultLimits())
	if err != nil {
		return nil, err
	}
	return &Prepared{document: d}, nil
}

func (p *Prepared) Hash() string   { return p.document.Hash() }
func (p *Prepared) RuleCount() int { return len(p.document.Policy.Exec.Rules) }

// Start deliberately fails until real target resolution, admission and attachment
// exist. Even audit/off cannot advertise a functioning gadget in this spike.
func (p *Prepared) Start() error { return ErrBackendUnavailable }
