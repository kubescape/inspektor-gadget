// Copyright 2026 The Inspektor Gadget authors
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

package uprobetracer

// Observability for the exec-driven re-attach path (ReattachContainerExecPid),
// added alongside the bounded-LRU fix for armosec/private-node-agent#541.
// Follows the pkg/metrics convention used elsewhere in the fork (see e.g.
// pkg/gadget-service/service.go's ig_grpc_* counters and
// pkg/gadget-context/run.go's ig_gadgets_running updown counter): a
// package-level var initialized once via metrics.<Kind>(name, ...), with the
// registration error discarded. This is nil-safe by construction, not by an
// explicit nil check -- metrics.Int64Counter/Float64Histogram always return a
// non-nil Proxy-owned wrapper (see pkg/metrics/metrics.go's int64Counter /
// float64Histogram types) whose Add/Record methods iterate an (initially
// empty) per-provider map, so calling them is always safe whether or not any
// MeterProvider has been registered yet, and regardless of whether this
// particular registration returned an error.

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/metrics"
)

var reattachDurationHistogram, _ = metrics.Float64Histogram("ig_uprobetracer_reattach_duration_seconds",
	metric.WithUnit("s"),
	metric.WithDescription("Duration of ReattachContainerExecPid's Phase-1 resolve+open I/O (resolveLibraryPaths + openTargets), per uprobe program"),
)

var attachTimeoutCounter, _ = metrics.Int64Counter("ig_uprobetracer_attach_timeout_total",
	metric.WithUnit("{timeout}"),
	metric.WithDescription("Number of times ReattachContainerExecPid's Phase-1 I/O hit attachIOTimeout instead of completing, per uprobe program"),
)

// redundantAttachCounter signals CONCURRENT-RACE redundancy only: Phase-1 I/O
// ran for a path that, by the time this call reached its own commit, was
// already resident in the cache WITH THE SAME exeIdentity -- see
// exeLRUCache.touchAndReport's "current" return for exactly what counts.
// This does NOT signal that exeLRUCap is too small: an entry that aged out of
// the cap-N set is (by definition) no longer resident when re-added, so it can
// never look "already present" here. For genuine capacity pressure, see
// exeCacheEvictionCounter below -- that is the counter exeLRUCap's own
// retuning guidance now points at (see exeLRUCap's doc comment in
// execache.go).
var redundantAttachCounter, _ = metrics.Int64Counter("ig_uprobetracer_redundant_attach_total",
	metric.WithUnit("{attach}"),
	metric.WithDescription("Number of times Phase-1 attach I/O ran for an exe path already resident (with the same content identity) in the container's recent-set, per uprobe program -- signals concurrent-race redundancy, NOT capacity pressure; see ig_uprobetracer_exe_cache_miss_total for that"),
)

// exeCacheEvictionCounter is the production signal for whether exeLRUCap
// itself needs retuning (code-review follow-up: matthyx's non-blocker review
// comment on this PR noted redundantAttachCounter above cannot serve this
// purpose, since a capacity-driven eviction miss is never "already present" by
// definition). It increments exactly when exeLRUCache's single insert+evict
// implementation (touchAndReport, see execache.go) evicts an existing entry to
// make room for a new one -- i.e. the cache was genuinely at capacity, as
// opposed to touchIfCurrent/touchAndReport reporting a plain first-time miss
// for a cache that still had room. A rising rate here, unlike
// redundantAttachCounter, is a direct measurement of "more than exeLRUCap
// distinct binaries are staying hot concurrently under one container than the
// cap can hold."
var exeCacheEvictionCounter, _ = metrics.Int64Counter("ig_uprobetracer_exe_cache_miss_total",
	metric.WithUnit("{miss}"),
	metric.WithDescription("Number of times the exec-reattach exe cache evicted an entry to make room for a new one, per uprobe program -- the production signal for whether exeLRUCap needs retuning"),
)

// progNameAttrsCache memoizes progNameAttrs' built attribute.Set per distinct
// progName (code-review follow-up): progName cardinality is small and fixed
// per process (a handful of uprobe programs, e.g. gotls's four separate
// Tracer instances), but without memoization attribute.NewSet allocates and
// sorts a brand new Set on EVERY call -- and these four
// recordReattachDuration/recordAttachTimeout/recordRedundantAttach/
// recordExeCacheEviction helpers are called from the exec-driven reattach hot
// path this whole PR exists to protect the latency budget of. A sync.Map
// (rather than a mutex-guarded plain map) is used because these can be called
// concurrently from multiple goroutines/programs and reads vastly outnumber
// the handful of first-time writes (one per distinct progName, ever).
var progNameAttrsCache sync.Map // map[string]attribute.Set

// progNameAttrs is the shared attribute set for all four counters/histogram
// above: progName distinguishes the (small, fixed) set of uprobe programs one
// process runs (e.g. gotls's four separate Tracer instances) without any
// unbounded/high-cardinality label such as a pid or exe path.
func progNameAttrs(progName string) attribute.Set {
	if v, ok := progNameAttrsCache.Load(progName); ok {
		return v.(attribute.Set)
	}
	set := attribute.NewSet(attribute.KeyValue{Key: "prog_name", Value: attribute.StringValue(progName)})
	actual, _ := progNameAttrsCache.LoadOrStore(progName, set)
	return actual.(attribute.Set)
}

func recordReattachDuration(progName string, d time.Duration) {
	reattachDurationHistogram.Record(context.Background(), d.Seconds(), metric.WithAttributeSet(progNameAttrs(progName)))
}

func recordAttachTimeout(progName string) {
	attachTimeoutCounter.Add(context.Background(), 1, metric.WithAttributeSet(progNameAttrs(progName)))
}

func recordRedundantAttach(progName string) {
	redundantAttachCounter.Add(context.Background(), 1, metric.WithAttributeSet(progNameAttrs(progName)))
}

func recordExeCacheEviction(progName string) {
	exeCacheEvictionCounter.Add(context.Background(), 1, metric.WithAttributeSet(progNameAttrs(progName)))
}

// A 5th signal was requested by armosec/private-node-agent#541: a
// ringbuf-backlog/drop gauge or counter for the kernel exec-event source, so
// an operator can see when the SINGLE goroutine draining it (watchExecEvents,
// see ReattachContainerExecPid's doc comment on attachIOTimeout) is falling
// behind the rate exec events actually arrive at, independent of any one
// call's own duration.
//
// That signal DOES exist, cheaply, with no kernel-side change needed:
// cilium/ebpf's ringbuf.Record (returned by ringbuf.Reader.Read) carries a
// Remaining field -- the ring's unread byte count at the moment of that read
// -- which is exactly a backlog/queue-depth measurement. But the read site
// that could observe it is pkg/container-hook/tracer.go's watchExecEvents,
// NOT anywhere under pkg/container-collection: that package has no
// ringbuf-draining code of its own, it only receives already-dequeued events
// via the callback watchExecEvents invokes (see
// pkg/container-collection/options.go's WithContainerFanotifyEbpf, whose
// EventTypeExecContainer case is the one that goes on to call
// cc.pubsub.PublishExec -- the explicitly out-of-scope call for this fix).
//
// Recording it here is deliberately deferred, not silently dropped:
//   - It requires editing pkg/container-hook/tracer.go, a different package
//     from pkg/uprobetracer entirely and outside what this fix's plan
//     reviewed line-by-line (attachIOTimeout's own doc comment, the code this
//     PR touches) -- a change there deserves its own read of that file's
//     invariants and its own review, not a rider on this cache fix.
//   - It is the exact hot loop this whole fix protects the latency budget of
//     (see attachIOTimeout's doc comment): watchExecEvents runs once per exec
//     event, synchronously, on the only goroutine draining that ringbuf, so
//     adding a metrics.Record call there needs its own scrutiny of overhead
//     and label cardinality (a histogram per read, unconditionally, at
//     whatever rate exec events arrive) -- not a two-line drive-by add.
//   - The natural place to OBSERVE degraded throughput as a result (vs.
//     backlog as a raw byte count) is right next to the callback that goes on
//     to call cc.pubsub.PublishExec -- immediately adjacent to, and coupled
//     with, the explicitly out-of-scope Publish/PublishExec change this task
//     was told not to make.
//
// If exeLRUCap retuning (via ig_uprobetracer_exe_cache_miss_total above)
// turns out not to explain a throughput regression, this Remaining field is
// where the next investigation should start -- in pkg/container-hook/tracer.go,
// as its own change.
