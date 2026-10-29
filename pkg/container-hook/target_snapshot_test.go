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

//go:build linux

package containerhook

import (
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type hookTargetSnapshot struct {
	pendingPIDFiles []string
	future          bool
	watched         bool
	callbackStats   CallbackStats
}

// snapshotHookTarget copies only the target's membership under each map's lock.
// Locks are never nested, and logging happens after they are released. Stages
// can change between reads: this is post-deadline evidence, not an atomic view
// or proof that a missing target was never observed. It does not read BPF maps.
func snapshotHookTarget(n *ContainerNotifier, containerID string) hookTargetSnapshot {
	var snapshot hookTargetSnapshot
	n.pendingMu.Lock()
	for pidFile, pending := range n.pendingContainers {
		if pending.id == containerID {
			snapshot.pendingPIDFiles = append(snapshot.pendingPIDFiles, pidFile)
		}
	}
	n.pendingMu.Unlock()
	sort.Strings(snapshot.pendingPIDFiles)

	n.futureMu.Lock()
	_, snapshot.future = n.futureContainers[containerID]
	n.futureMu.Unlock()

	n.containersMu.Lock()
	_, snapshot.watched = n.containers[containerID]
	n.containersMu.Unlock()

	snapshot.callbackStats = n.CallbackStats()
	return snapshot
}

func TestHookTargetSnapshot(t *testing.T) {
	n := &ContainerNotifier{
		pendingContainers: map[string]*pendingContainer{
			"/target-b.pid": {id: "target"},
			"/target-a.pid": {id: "target"},
			"/other.pid":    {id: "other"},
		},
		futureContainers: map[string]*futureContainer{"target": {id: "target"}},
		containers:       map[string]*watchedContainer{"target": {id: "target"}},
	}
	n.cbInFlight.Store(2)
	n.cbBreaches.Store(3)
	n.cbDuration.Observe(time.Millisecond)
	snapshot := snapshotHookTarget(n, "target")
	require.Equal(t, []string{"/target-a.pid", "/target-b.pid"}, snapshot.pendingPIDFiles)
	require.True(t, snapshot.future)
	require.True(t, snapshot.watched)
	require.Equal(t, n.CallbackStats(), snapshot.callbackStats)
	missing := snapshotHookTarget(n, "missing")
	require.Empty(t, missing.pendingPIDFiles)
	require.False(t, missing.future)
	require.False(t, missing.watched)
	require.Equal(t, hookTargetSnapshot{}, snapshotHookTarget(&ContainerNotifier{}, "target"))

	// Returned data must not alias notifier state, including the histogram.
	snapshot.pendingPIDFiles[0] = "changed"
	snapshot.callbackStats.Duration.Histogram.Intervals[0].Count = 99
	again := snapshotHookTarget(n, "target")
	require.Equal(t, []string{"/target-a.pid", "/target-b.pid"}, again.pendingPIDFiles)
	require.Equal(t, n.CallbackStats(), again.callbackStats)
	require.Len(t, n.pendingContainers, 3)
	require.Len(t, n.futureContainers, 1)
	require.Len(t, n.containers, 1)
}

func TestHookTargetSnapshotConcurrent(t *testing.T) {
	n := &ContainerNotifier{
		pendingContainers: make(map[string]*pendingContainer),
		futureContainers:  make(map[string]*futureContainer),
		containers:        make(map[string]*watchedContainer),
	}
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; i < 1000; i++ {
			n.pendingMu.Lock()
			n.pendingContainers["/target.pid"] = &pendingContainer{id: "target"}
			n.pendingMu.Unlock()
			n.futureMu.Lock()
			n.futureContainers["target"] = &futureContainer{id: "target"}
			n.futureMu.Unlock()
			n.containersMu.Lock()
			n.containers["target"] = &watchedContainer{id: "target"}
			n.containersMu.Unlock()
			n.cbInFlight.Add(1)
			n.cbBreaches.Add(1)
			n.cbDuration.Observe(time.Microsecond)
			n.pendingMu.Lock()
			delete(n.pendingContainers, "/target.pid")
			n.pendingMu.Unlock()
			n.futureMu.Lock()
			delete(n.futureContainers, "target")
			n.futureMu.Unlock()
			n.containersMu.Lock()
			delete(n.containers, "target")
			n.containersMu.Unlock()
			n.cbInFlight.Add(-1)
		}
	}()
	for i := 0; i < 1000; i++ {
		snapshot := snapshotHookTarget(n, "target")
		for _, pidFile := range snapshot.pendingPIDFiles {
			require.Equal(t, "/target.pid", pidFile)
		}
	}
	writer.Wait()
	snapshot := snapshotHookTarget(n, "target")
	require.Empty(t, snapshot.pendingPIDFiles)
	require.False(t, snapshot.future)
	require.False(t, snapshot.watched)
	require.Zero(t, snapshot.callbackStats.InFlight)
	require.Equal(t, uint64(1000), snapshot.callbackStats.Breaches)
	require.Equal(t, uint64(1000), snapshot.callbackStats.Duration.Count)
}
