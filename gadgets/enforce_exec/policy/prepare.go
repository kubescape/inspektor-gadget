// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import (
	"strings"
)

const ParameterName = "exec-policy"

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
