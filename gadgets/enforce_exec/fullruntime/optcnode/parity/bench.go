// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package parity

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// Workload is one E6 measurement, run by the bound init; Key=<value> is
// read from its output. The workloads are S1's (S1 review N2 bench), plus
// fork-only (a subshell, no exec).
type Workload struct{ Metric, Line, Key string }

// BenchForks is the iteration count of the fork workloads.
const BenchForks = 500

// Workloads with helper, S1's static d1-helper ("bench N": getppid loop,
// ns per 1000 syscalls; "noop": exits).
func Workloads(helper string) []Workload {
	return []Workload{
		{"syscall_ns_per_1000", helper + " bench 200000", "NS_PER_1000_SYSCALLS"},
		{"forkexec_ns", fmt.Sprintf(`s=$(date +%%s%%N); for i in $(seq %d); do %s noop; done; e=$(date +%%s%%N); echo FE=$(( (e-s)/%d ))`, BenchForks, helper, BenchForks), "FE"},
		{"fork_ns", fmt.Sprintf(`s=$(date +%%s%%N); for i in $(seq %d); do ( : ); done; e=$(date +%%s%%N); echo FO=$(( (e-s)/%d ))`, BenchForks, BenchForks), "FO"},
		{"buildish_ms", `s=$(date +%s%N); find /usr/lib /usr/share -type f 2>/dev/null | head -6000 | xargs -n 20 -P 4 sha256sum >/dev/null 2>&1; e=$(date +%s%N); echo B=$(( (e-s)/1000000 ))`, "B"},
	}
}

// BenchPolicy is S1's bench policy: Strict, default allow, one deny rule
// that never matches.
func BenchPolicy() fullpolicy.Policy {
	return fullpolicy.Policy{ID: "s1-bench", Revision: "1", Mode: fullpolicy.Enforce, RootRole: "app", Default: fullpolicy.Allow,
		Rules: []fullpolicy.Rule{{Name: "never", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{"/nonexistent/never"}}}}}
}

// Value reads key=<int> from out.
func Value(out, key string) (int64, error) {
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == key {
			return strconv.ParseInt(v, 10, 64)
		}
	}
	return 0, fmt.Errorf("no %s in %q", key, out)
}
