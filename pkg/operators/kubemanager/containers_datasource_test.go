// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kubemanager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

// A gadget consuming container notifications need not request mount-namespace
// filtering or expose process fields. Its manager must still publish targets.
func TestContainersDatasourceOnlyActivatesManager(t *testing.T) {
	collection := &containercollection.ContainerCollection{}
	require.NoError(t, collection.Initialize(containercollection.WithPubSub()))
	t.Cleanup(collection.Close)
	container := &containercollection.Container{CgroupID: 123, CgroupV2: "/test/container"}
	container.Runtime.ContainerID = "known-container"
	collection.AddContainer(container)
	gc := gadgetcontext.New(context.Background(), "test")
	require.NoError(t, gc.SetMetadata([]byte("annotations:\n  enable-containers-datasource: true\n")))
	manager := &KubeManager{containerCollection: collection}
	instance, err := manager.InstantiateDataOperator(gc, nil)
	require.NoError(t, err)
	require.NotNil(t, instance, "container datasource alone must activate the manager")
	ds := gc.GetDataSources()["containers"]
	require.NotNil(t, ds)
	var ids []string
	require.NoError(t, ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
		id, err := ds.GetField("container_id").String(data)
		if err != nil {
			return err
		}
		ids = append(ids, id)
		return nil
	}, 0))
	// Exercise notification publishing without invoking root-only tracer setup.
	t.Cleanup(instance.(*KubeManagerInstance).containersPublisher.Unsubscribe)
	require.NoError(t, instance.Start(gc))
	require.Equal(t, []string{"known-container"}, ids)
}
