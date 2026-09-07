// Copyright 2022-2025 The Inspektor Gadget authors
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

package tracercollection

import (
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

const (
	MaxContainersPerNode = 1024
	MountMapPrefix       = "mntnsset_"
)

type TracerCollection struct {
	tracers             map[string]tracer
	tracersMutex        *sync.RWMutex
	containerCollection *containercollection.ContainerCollection
	testOnly            bool
}

type tracer struct {
	tracerID string

	containerSelector containercollection.ContainerSelector

	mntnsSetMap  *ebpf.Map
	testMntnsSet *sync.Map
}

func NewTracerCollection(cc *containercollection.ContainerCollection) (*TracerCollection, error) {
	return &TracerCollection{
		tracers:             make(map[string]tracer),
		tracersMutex:        &sync.RWMutex{},
		containerCollection: cc,
	}, nil
}

func NewTracerCollectionTest(cc *containercollection.ContainerCollection) (*TracerCollection, error) {
	return &TracerCollection{
		tracers:             make(map[string]tracer),
		tracersMutex:        &sync.RWMutex{},
		containerCollection: cc,
		testOnly:            true,
	}, nil
}

// isPauseContainer checks whether a container is a Kubernetes pause container.
// Pause containers belong to a Kubernetes pod (PodName != "") but do not have
// a container name. Containers in non-Kubernetes environments (e.g. ECS, standalone Docker)
// or containers where runtime enrichment has not yet populated ContainerName must not be skipped.
func isPauseContainer(c *containercollection.Container) bool {
	return c.K8s.PodName != "" && c.K8s.ContainerName == ""
}

func (tc *TracerCollection) TracerMapsUpdater() containercollection.FuncNotify {
	return func(event containercollection.PubSubEvent) {
		switch event.Type {
		case containercollection.EventTypeAddContainer:
			// Skip Kubernetes pause containers (part of a pod, but without a container name).
			// Do not skip containers in non-Kubernetes environments (e.g. ECS/Docker)
			// or containers where runtime enrichment has not yet populated Runtime.ContainerName.
			if isPauseContainer(event.Container) {
				return
			}

			tc.tracersMutex.RLock()
			defer tc.tracersMutex.RUnlock()
			for _, t := range tc.tracers {
				if containercollection.ContainerSelectorMatches(&t.containerSelector, event.Container) {
					mntnsC := uint64(event.Container.Mntns)
					one := uint32(1)
					if mntnsC != 0 {
						if t.mntnsSetMap != nil {
							t.mntnsSetMap.Put(mntnsC, one)
						}
						if t.testMntnsSet != nil {
							t.testMntnsSet.Store(mntnsC, struct{}{})
						}
					} else {
						log.Errorf("new container with mntns=0")
					}
				}
			}

		case containercollection.EventTypeRemoveContainer:
			tc.tracersMutex.RLock()
			defer tc.tracersMutex.RUnlock()
			for _, t := range tc.tracers {
				if containercollection.ContainerSelectorMatches(&t.containerSelector, event.Container) {
					mntnsC := uint64(event.Container.Mntns)
					if t.mntnsSetMap != nil {
						t.mntnsSetMap.Delete(mntnsC)
					}
					if t.testMntnsSet != nil {
						t.testMntnsSet.Delete(mntnsC)
					}
				}
			}
		}
	}
}

func (tc *TracerCollection) AddTracer(id string, containerSelector containercollection.ContainerSelector) error {
	tc.tracersMutex.Lock()
	defer tc.tracersMutex.Unlock()
	if _, ok := tc.tracers[id]; ok {
		return fmt.Errorf("tracer id %q: %w", id, os.ErrExist)
	}
	var mntnsSetMap *ebpf.Map
	var testMntnsSet *sync.Map
	if !tc.testOnly {
		mntnsSpec := &ebpf.MapSpec{
			Name:       MountMapPrefix + id,
			Type:       ebpf.Hash,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: MaxContainersPerNode,
		}
		var err error
		mntnsSetMap, err = ebpf.NewMap(mntnsSpec)
		if err != nil {
			return fmt.Errorf("creating mntnsset map: %w", err)
		}

		tc.containerCollection.ContainerRangeWithSelector(&containerSelector, func(c *containercollection.Container) {
			one := uint32(1)
			mntnsC := uint64(c.Mntns)
			if mntnsC != 0 {
				mntnsSetMap.Put(mntnsC, one)
			}
		})
	} else {
		testMntnsSet = &sync.Map{}
		tc.containerCollection.ContainerRangeWithSelector(&containerSelector, func(c *containercollection.Container) {
			mntnsC := uint64(c.Mntns)
			if mntnsC != 0 {
				testMntnsSet.Store(mntnsC, struct{}{})
			}
		})
	}
	tc.tracers[id] = tracer{
		tracerID:          id,
		containerSelector: containerSelector,
		mntnsSetMap:       mntnsSetMap,
		testMntnsSet:      testMntnsSet,
	}
	return nil
}

func (tc *TracerCollection) RemoveTracer(id string) error {
	if id == "" {
		return fmt.Errorf("container id not set")
	}

	tc.tracersMutex.Lock()
	defer tc.tracersMutex.Unlock()
	t, ok := tc.tracers[id]
	if !ok {
		return fmt.Errorf("unknown tracer %q", id)
	}

	if t.mntnsSetMap != nil {
		t.mntnsSetMap.Close()
	}

	delete(tc.tracers, id)
	return nil
}

func (tc *TracerCollection) TracerCount() int {
	tc.tracersMutex.RLock()
	defer tc.tracersMutex.RUnlock()
	return len(tc.tracers)
}

func (tc *TracerCollection) TracerDump() (out string) {
	tc.tracersMutex.RLock()
	defer tc.tracersMutex.RUnlock()
	for i, t := range tc.tracers {
		out += fmt.Sprintf("%v -> %q/%q (%s) Labels: \n",
			i,
			t.containerSelector.K8s.Namespace,
			t.containerSelector.K8s.PodName,
			t.containerSelector.K8s.ContainerName)
		for k, v := range t.containerSelector.K8s.PodLabels {
			out += fmt.Sprintf("                  %v: %v\n", k, v)
		}
		out += "        Matches:\n"
		tc.containerCollection.ContainerRangeWithSelector(&t.containerSelector, func(c *containercollection.Container) {
			out += fmt.Sprintf("        - %s/%s [Mntns=%v CgroupID=%v]\n", c.K8s.Namespace, c.K8s.PodName, c.Mntns, c.CgroupID)
		})
	}
	return
}

func (tc *TracerCollection) TracerExists(id string) bool {
	tc.tracersMutex.RLock()
	defer tc.tracersMutex.RUnlock()
	_, ok := tc.tracers[id]
	return ok
}

func (tc *TracerCollection) Close() {}

func (tc *TracerCollection) TracerMountNsMap(id string) (*ebpf.Map, error) {
	tc.tracersMutex.RLock()
	defer tc.tracersMutex.RUnlock()
	t, ok := tc.tracers[id]
	if !ok {
		return nil, fmt.Errorf("unknown tracer %q", id)
	}

	return t.mntnsSetMap, nil
}

// TracerMountNsExistsForTest reports whether a mount namespace is tracked by the tracer in test mode.
func (tc *TracerCollection) TracerMountNsExistsForTest(id string, mntns uint64) bool {
	tc.tracersMutex.RLock()
	defer tc.tracersMutex.RUnlock()
	t, ok := tc.tracers[id]
	if !ok || t.testMntnsSet == nil {
		return false
	}
	_, exists := t.testMntnsSet.Load(mntns)
	return exists
}
