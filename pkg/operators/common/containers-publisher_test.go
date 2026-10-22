// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestContainersPublisherRuntimeIdentity(t *testing.T) {
	ctx := gadgetcontext.New(context.Background(), "test")
	publisher, err := NewContainersPublisher(ctx, nil)
	require.NoError(t, err)
	container := &containercollection.Container{CgroupID: 123}
	container.Runtime.RuntimeName = types.RuntimeNameContainerd
	container.Runtime.ContainerID = "full-container-id"
	var events int
	require.NoError(t, publisher.containersDs.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
		runtime, err := publisher.runtimeField.String(data)
		require.NoError(t, err)
		require.Equal(t, "containerd", runtime)
		id, err := publisher.idField.String(data)
		require.NoError(t, err)
		require.Equal(t, "full-container-id", id)
		events++
		return nil
	}, 0))
	require.NoError(t, publisher.emitContainersDatasourceEvent(containercollection.EventTypeAddContainer, container, false))
	require.NoError(t, publisher.emitContainersDatasourceEvent(containercollection.EventTypeRemoveContainer, container, true))
	require.Equal(t, 2, events)
}

// An absent or root v2 path must remain distinguishable even if enrichment
// supplied a nonzero ID. Consumers can then reject hybrid/v1 root identities.
func TestContainersPublisherCgroupV2Path(t *testing.T) {
	for _, path := range []string{"", "/", "/kubepods/container"} {
		t.Run("path="+path, func(t *testing.T) {
			ctx := gadgetcontext.New(context.Background(), "test")
			publisher, err := NewContainersPublisher(ctx, nil)
			require.NoError(t, err)
			var received bool
			require.NoError(t, publisher.containersDs.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
				actual, err := publisher.cgroupV2PathField.String(data)
				require.NoError(t, err)
				require.Equal(t, path, actual)
				received = true
				return nil
			}, 0))
			require.NoError(t, publisher.emitContainersDatasourceEvent(containercollection.EventTypeAddContainer, &containercollection.Container{CgroupID: 123, CgroupV2: path}, false))
			require.True(t, received)
		})
	}
}

func TestContainersPublisherReplayBeforeChanges(t *testing.T) {
	for _, change := range []string{"remove", "add"} {
		t.Run(change, func(t *testing.T) {
			collection := &containercollection.ContainerCollection{}
			require.NoError(t, collection.Initialize(containercollection.WithPubSub()))
			defer collection.Close()
			existing := &containercollection.Container{}
			existing.Runtime.ContainerID = "existing"
			collection.AddContainer(existing)
			ctx := gadgetcontext.New(context.Background(), "test")
			defer ctx.Cancel()
			publisher, err := NewContainersPublisher(ctx, collection)
			require.NoError(t, err)
			defer publisher.Unsubscribe()
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			var mu sync.Mutex
			var events []string
			require.NoError(t, publisher.containersDs.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
				kind, _ := publisher.eventTypeField.String(data)
				id, _ := publisher.idField.String(data)
				if kind == "CREATED" && id == "existing" {
					close(entered)
					<-release
				}
				mu.Lock()
				events = append(events, kind+":"+id)
				mu.Unlock()
				return nil
			}, 0))
			published := make(chan error, 1)
			go func() { published <- publisher.PublishContainers(false, nil, containercollection.ContainerSelector{}) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("snapshot did not start")
			}
			changed := make(chan struct{})
			go func() {
				if change == "remove" {
					collection.RemoveContainer("existing")
				} else {
					added := &containercollection.Container{}
					added.Runtime.ContainerID = "added"
					collection.AddContainer(added)
				}
				close(changed)
			}()
			select {
			case <-changed:
			case <-time.After(5 * time.Second):
				t.Fatal("change was not queued")
			}
			mu.Lock()
			beforeRelease := append([]string(nil), events...)
			mu.Unlock()
			require.Empty(t, beforeRelease, "live events overtook snapshot replay")
			once.Do(func() { close(release) })
			require.NoError(t, <-published)
			expected := "DELETED:existing"
			if change == "add" {
				expected = "CREATED:added"
			}
			mu.Lock()
			defer mu.Unlock()
			require.Equal(t, []string{"CREATED:existing", expected}, events)
		})
	}
}

func TestContainersPublisherReplayFailureUnsubscribes(t *testing.T) {
	collection := &containercollection.ContainerCollection{}
	require.NoError(t, collection.Initialize(containercollection.WithPubSub()))
	defer collection.Close()
	existing := &containercollection.Container{}
	existing.Runtime.ContainerID = "existing"
	collection.AddContainer(existing)
	ctx := gadgetcontext.New(context.Background(), "test")
	defer ctx.Cancel()
	publisher, err := NewContainersPublisher(ctx, collection)
	require.NoError(t, err)
	defer publisher.Unsubscribe()
	failure := errors.New("binding failed")
	calls := 0
	require.NoError(t, publisher.containersDs.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
		calls++
		return failure
	}, 0))
	require.ErrorIs(t, publisher.PublishContainers(false, nil, containercollection.ContainerSelector{}), failure)
	collection.RemoveContainer("existing")
	require.Equal(t, 1, calls, "failed startup left its subscription active")
}
