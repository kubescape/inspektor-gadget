// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package containercollection

import (
	containerhook "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook"
	log "github.com/sirupsen/logrus"
)

// ExecHoldStats returns the exec-hold fanotify gate's current counters, and
// whether they are available at all.
//
// ok=false means only "no exec-hold fanotify group exists to report on" --
// the same routine, non-error condition SetExecHoldHooks and
// MarkExecHoldCandidateByMntns already treat as a no-op (an empty allowlist,
// or WithContainerFanotifyEbpf's caller never enabling it), never "exec-hold
// is enabled but reporting failed". A caller wiring this into a metrics
// exporter (see armosec/private-node-agent's execholdmetrics package) should
// treat ok=false as "nothing to export yet", not as a warning.
//
// Checked via ExecHoldAvailable, not just cc.containerNotifier == nil:
// WithContainerFanotifyEbpf always creates a notifier, even when the
// allowlist is empty and no exec-hold fanotify group was ever created, so a
// nil-notifier-only check would report ok=true (with all-zero counters) for
// an exec-hold subsystem that is not actually available, indistinguishable
// to a metrics caller from real zero counts.
func (cc *ContainerCollection) ExecHoldStats() (containerhook.ExecHoldStats, bool) {
	if cc.containerNotifier == nil || !cc.containerNotifier.ExecHoldAvailable() {
		return containerhook.ExecHoldStats{}, false
	}
	return cc.containerNotifier.ExecHoldStats(), true
}

// SetExecHoldHooks wires the exec-hold dispatcher's crediter and resolve+attach
// hand-off to the container-hook's own, single ContainerNotifier -- the one
// MarkExecHoldCandidateByMntns above also delegates to.
//
// A consumer must call this through the collection, never by constructing a
// second ContainerNotifier of its own: the fanotify group and its dispatcher
// live on this collection's one notifier, so a second notifier would gate a
// fanotify group whose holds nothing here ever sees, silently doing nothing.
//
// It is a no-op if exec-hold's fanotify group was never created (the
// allowlist was empty, or WithContainerFanotifyEbpf's caller never enabled
// it) -- there is nothing to wire hooks into yet, and calling this before or
// after that state is both a normal, expected sequencing outcome, not an
// error a caller needs to guard against.
func (cc *ContainerCollection) SetExecHoldHooks(crediter containerhook.ExecHoldCrediter, attacher containerhook.ResolveAttacher) {
	if cc.containerNotifier == nil {
		// A log line, not a silent return: this branch is reachable by a
		// genuinely normal sequencing case (calling this before
		// Initialize(WithContainerFanotifyEbpf()) has run), but a caller
		// that gates this call on its own feature-active check first (the
		// intended pattern -- see e.g. armosec/private-node-agent's
		// ExecHoldWirer, which only calls here once it has already found a
		// live crediter) should never hit it in steady state. If it does,
		// the crediter/attacher this call carried are silently discarded
		// with no retry, and exec-hold provides zero uprobe-attach
		// protection for this process's lifetime despite appearing
		// configured -- a warning here is the only thing that can ever
		// surface that, since nothing else observes the drop.
		log.Warn("container-collection: SetExecHoldHooks called before the container-hook notifier exists (or exec-hold is not enabled); crediter/attacher discarded, exec-hold provides no protection until this is called again after the notifier exists")
		return
	}
	cc.containerNotifier.SetExecHoldHooks(crediter, attacher)
}

// MarkExecHoldCandidateByMntns asks the container-hook to install an exec-hold
// mark on candidatePath — a path as seen INSIDE the container — for the tracked
// container whose mount namespace is mntnsID.
//
// It exists for consumers that observe container activity the container-hook
// does not. The container-hook marks exec-hold candidates from two places, both
// driven by events it sees itself: the enumeration at container create, which
// only sees what already existed in the rootfs, and the first exec of an
// allowlisted binary, which is one exec too late for that binary's first run. A
// consumer whose own tracer watched the binary being WRITTEN can close that gap
// by calling here before it is ever executed.
//
// The mount namespace id is the identity used because it is what the
// collection already resolves containers by for exactly this kind of caller
// (LookupContainerByMntns, EnrichByMntNs), and it is the identity the
// container-hook itself keys its per-container exec-hold bookkeeping on, so
// nothing has to be translated between the two.
//
// Every refusal is reported as an ExecHoldMarkResult rather than an error, and
// ExecHoldMarkNotApplicable covers both "exec-hold was never enabled" and "that
// container is not (or no longer) tracked" — a caller driven by a live event
// stream races container lifecycle by construction and must not treat losing
// that race as a failure.
//
// The candidate is resolved and validated entirely inside the container-hook,
// under the same openat2 RESOLVE_IN_ROOT and st_dev hardening as every other
// exec-hold mark, and against the container-hook's own allowlist: a path whose
// basename is not allowlisted is a cheap no-op here, not a mark attempt.
//
// It is safe to call from any goroutine.
func (cc *ContainerCollection) MarkExecHoldCandidateByMntns(mntnsID uint64, candidatePath string) containerhook.ExecHoldMarkResult {
	if cc.containerNotifier == nil {
		return containerhook.ExecHoldMarkNotApplicable
	}

	container := cc.LookupContainerByMntns(mntnsID)
	if container == nil {
		return containerhook.ExecHoldMarkNotApplicable
	}

	pid := container.ContainerPid()
	if pid == 0 {
		return containerhook.ExecHoldMarkNotApplicable
	}

	return cc.containerNotifier.MarkExecHoldCandidate(mntnsID, pid, candidatePath)
}
