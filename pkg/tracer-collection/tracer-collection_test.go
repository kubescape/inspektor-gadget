// Copyright 2022 The Inspektor Gadget authors
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
	"testing"

	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTracer(t *testing.T) {
	var cc containercollection.ContainerCollection
	cc.Initialize([]containercollection.ContainerCollectionOption{}...)

	tc, err := NewTracerCollectionTest(&cc)
	require.NoError(t, err, "Failed to create tracer collection")
	require.NotNil(t, tc, "Tracer collection is nil")

	// Add 3 Tracers
	for i := range 3 {
		err := tc.AddTracer(
			fmt.Sprintf("my_tracer_id%d", i),
			containercollection.ContainerSelector{
				K8s: containercollection.K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: fmt.Sprintf("this-namespace%d", i),
					},
				},
			},
		)
		require.NoError(t, err, "Failed to add tracer")
	}

	// Check Tracer count
	require.Equal(t, 3, tc.TracerCount(), "Tracer count mismatch after adding tracers")

	// Check error on duplicate tracer
	err = tc.AddTracer(
		fmt.Sprintf("my_tracer_id%d", 0),
		containercollection.ContainerSelector{
			K8s: containercollection.K8sSelector{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace: fmt.Sprintf("this-namespace%d", 0),
				},
			},
		},
	)
	require.Error(t, err, "Expected error when adding duplicate tracer")

	// Remove 1 Tracer
	require.NoError(t, tc.RemoveTracer(fmt.Sprintf("my_tracer_id%d", 1)), "Failed to remove tracer")

	// Remove non-existent Tracer
	require.Error(t, tc.RemoveTracer(fmt.Sprintf("my_tracer_id%d", 99)), "Expected error when removing non-existent tracer")

	// Check content
	require.Equal(t, 2, tc.TracerCount(), "Error while checking tracers")
	require.True(t, tc.TracerExists("my_tracer_id0"), "Error while checking tracer my_tracer_id0: not found")
	require.True(t, tc.TracerExists("my_tracer_id2"), "Error while checking tracer my_tracer_id2: not found")
}

func tracerMountNsExists(tc *TracerCollection, id string, mntns uint64) bool {
	tc.tracersMutex.RLock()
	defer tc.tracersMutex.RUnlock()
	t, ok := tc.tracers[id]
	if !ok || t.testMntnsSet == nil {
		return false
	}
	_, exists := t.testMntnsSet.Load(mntns)
	return exists
}

func TestIsPauseContainer(t *testing.T) {
	tests := []struct {
		name      string
		container containercollection.Container
		expected  bool
	}{
		{
			name: "k8s pause container with empty container name",
			container: containercollection.Container{
				K8s: containercollection.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "default",
						PodName:       "mypod",
						ContainerName: "",
					},
				},
			},
			expected: true,
		},
		{
			name: "k8s normal container",
			container: containercollection.Container{
				K8s: containercollection.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "default",
						PodName:       "mypod",
						ContainerName: "mycontainer",
					},
				},
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerName: "k8s_mycontainer_mypod",
					},
				},
			},
			expected: false,
		},
		{
			name: "non-k8s container before runtime enrichment (e.g. ECS startup delay / timeout)",
			container: containercollection.Container{
				K8s: containercollection.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						PodName:       "",
						ContainerName: "",
					},
				},
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerID:   "c12345",
						ContainerName: "",
					},
				},
			},
			expected: false,
		},
		{
			name: "non-k8s standalone container with runtime name",
			container: containercollection.Container{
				K8s: containercollection.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						PodName:       "",
						ContainerName: "",
					},
				},
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerID:   "c12345",
						ContainerName: "standalone-app",
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.container.IsPauseContainer())
		})
	}
}

func TestTracerMapsUpdater(t *testing.T) {
	var cc containercollection.ContainerCollection
	cc.Initialize([]containercollection.ContainerCollectionOption{}...)

	tc, err := NewTracerCollectionTest(&cc)
	require.NoError(t, err)

	// Tracer 1: matches all containers
	err = tc.AddTracer("all-containers", containercollection.ContainerSelector{})
	require.NoError(t, err)

	// Tracer 2: matches only default namespace
	err = tc.AddTracer("k8s-default", containercollection.ContainerSelector{
		K8s: containercollection.K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "default",
			},
		},
	})
	require.NoError(t, err)

	updater := tc.TracerMapsUpdater()

	// 1. K8s pause container: should be ignored (not added to any tracer)
	k8sPause := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "default",
				PodName:       "mypod",
				ContainerName: "",
			},
		},
		Mntns: 1001,
	}
	updater(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: k8sPause,
	})
	require.False(t, tracerMountNsExists(tc, "all-containers", 1001), "K8s pause container mntns should not be added")
	require.False(t, tracerMountNsExists(tc, "k8s-default", 1001), "K8s pause container mntns should not be added")

	// 2. Non-K8s / ECS container with delayed inspect (both container names empty):
	// MUST NOT be skipped as pause container
	ecsContainer := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerID:   "ecs123",
				ContainerName: "",
			},
		},
		Mntns: 1002,
	}
	updater(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: ecsContainer,
	})
	require.True(t, tracerMountNsExists(tc, "all-containers", 1002), "Non-k8s container mntns must be added")
	require.False(t, tracerMountNsExists(tc, "k8s-default", 1002), "Non-k8s container should not match k8s-default selector")

	// 3. K8s regular container: should match both
	k8sContainer := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "default",
				PodName:       "mypod",
				ContainerName: "mycontainer",
			},
		},
		Mntns: 1003,
	}
	updater(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: k8sContainer,
	})
	require.True(t, tracerMountNsExists(tc, "all-containers", 1003), "K8s container should be added to all-containers tracer")
	require.True(t, tracerMountNsExists(tc, "k8s-default", 1003), "K8s container should be added to k8s-default tracer")

	// 4. Remove container: mntns should be deleted
	updater(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: ecsContainer,
	})
	require.False(t, tracerMountNsExists(tc, "all-containers", 1002), "Removed container mntns should be deleted")
}

func TestAddTracerInitialContainers(t *testing.T) {
	var cc containercollection.ContainerCollection
	cc.Initialize([]containercollection.ContainerCollectionOption{}...)

	// Pre-populate container collection with containers
	pauseContainer := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "default",
				PodName:       "mypod",
				ContainerName: "",
			},
		},
		Mntns: 2001,
	}
	cc.AddContainer(pauseContainer)

	ecsContainer := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerID:   "ecs456",
				ContainerName: "",
			},
		},
		Mntns: 2002,
	}
	cc.AddContainer(ecsContainer)

	tc, err := NewTracerCollectionTest(&cc)
	require.NoError(t, err)

	err = tc.AddTracer("initial-test", containercollection.ContainerSelector{})
	require.NoError(t, err)

	// Pre-existing pause container should NOT be added to tracer mount ns set
	require.False(t, tracerMountNsExists(tc, "initial-test", 2001), "Pre-existing pause container must not be added to tracer")
	// Pre-existing non-K8s container MUST be added to tracer mount ns set
	require.True(t, tracerMountNsExists(tc, "initial-test", 2002), "Pre-existing non-K8s container must be added to tracer")
}
