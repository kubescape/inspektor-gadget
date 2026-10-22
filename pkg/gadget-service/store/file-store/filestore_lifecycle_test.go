// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package filestore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
)

func createStoredInstance(t *testing.T) (*FileStore, *fakeFileManager, string) {
	t.Helper()
	manager := &fakeFileManager{}
	store := &FileStore{instanceMgr: manager, directory: t.TempDir(), observed: make(map[string]string)}
	req := &api.CreateGadgetInstanceRequest{GadgetInstance: &api.GadgetInstance{
		Id: "abcdef", Name: "original", GadgetConfig: &api.GadgetRunRequest{ImageName: "enforce", ParamValues: map[string]string{"policy": "initial"}},
	}}
	response, err := store.CreateGadgetInstance(context.Background(), req)
	require.NoError(t, err)
	require.Zero(t, response.Result)
	require.Equal(t, 1, manager.starts)
	return store, manager, filepath.Join(store.directory, "abcdef.gadget")
}

func TestCreateRejectsExistingInvalidInstance(t *testing.T) {
	for name, invalid := range map[string]string{
		"malformed":             "{",
		"missing configuration": "{}",
		"different identity":    `{"gadgetInstance":{"id":"other","name":"other","gadgetConfig":{"imageName":"enforce"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			store, manager, path := createStoredInstance(t)
			require.NoError(t, os.WriteFile(path, []byte(invalid), 0o600))
			require.NoError(t, store.reconcileFiles(context.Background()))
			before := store.observed["abcdef"]
			req := &api.CreateGadgetInstanceRequest{GadgetInstance: &api.GadgetInstance{
				Id: "abcdef", Name: "replacement", GadgetConfig: &api.GadgetRunRequest{ImageName: "replacement"},
			}}
			_, err := store.CreateGadgetInstance(context.Background(), req)
			require.ErrorContains(t, err, "already exists")
			require.Equal(t, 1, manager.starts, "duplicate create must not replace the reachable instance")
			require.Empty(t, manager.removed)
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, invalid, string(raw), "duplicate create must not overwrite desired state")
			require.Equal(t, before, store.observed["abcdef"])
		})
	}
}

func TestRemoveInvalidInstance(t *testing.T) {
	for name, invalid := range map[string]string{"malformed": "{", "missing configuration": "{}"} {
		t.Run(name, func(t *testing.T) {
			store, manager, path := createStoredInstance(t)
			require.NoError(t, os.WriteFile(path, []byte(invalid), 0o600))
			require.NoError(t, store.reconcileFiles(context.Background()))
			response, err := store.RemoveGadgetInstance(context.Background(), &api.GadgetInstanceId{Id: "abcdef"})
			require.NoError(t, err)
			require.Zero(t, response.Result, response.Message)
			require.Equal(t, []string{"abcdef"}, manager.removed)
			_, err = os.Lstat(path)
			require.ErrorIs(t, err, os.ErrNotExist)
			require.NotContains(t, store.observed, "abcdef")
			require.NoError(t, store.reconcileFiles(context.Background()))
			require.Len(t, manager.removed, 1, "watcher must not repeat explicit removal")
		})
	}
}

func TestRemoveTrackedInstanceWithMissingFile(t *testing.T) {
	store, manager, path := createStoredInstance(t)
	require.NoError(t, os.Remove(path))
	response, err := store.RemoveGadgetInstance(context.Background(), &api.GadgetInstanceId{Id: "abcdef"})
	require.NoError(t, err)
	require.Zero(t, response.Result, response.Message)
	require.Equal(t, []string{"abcdef"}, manager.removed)
	require.NotContains(t, store.observed, "abcdef")
}

func TestRemoveInvalidFileWithoutRunningInstance(t *testing.T) {
	manager := &fakeFileManager{removeErr: instancemanager.ErrNotFound}
	store := &FileStore{instanceMgr: manager, directory: t.TempDir(), observed: make(map[string]string)}
	path := filepath.Join(store.directory, "abcdef.gadget")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	response, err := store.RemoveGadgetInstance(context.Background(), &api.GadgetInstanceId{Id: "abcdef"})
	require.NoError(t, err)
	require.Zero(t, response.Result, response.Message)
	_, err = os.Lstat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestCreateRejectsTrackedInstanceWithMissingFile(t *testing.T) {
	store, manager, path := createStoredInstance(t)
	require.NoError(t, os.Remove(path))
	req := &api.CreateGadgetInstanceRequest{GadgetInstance: &api.GadgetInstance{
		Id: "abcdef", Name: "replacement", GadgetConfig: &api.GadgetRunRequest{ImageName: "replacement"},
	}}
	_, err := store.CreateGadgetInstance(context.Background(), req)
	require.ErrorContains(t, err, "already exists")
	require.Equal(t, 1, manager.starts)
	require.Empty(t, manager.removed)
	response, err := store.RemoveGadgetInstance(context.Background(), &api.GadgetInstanceId{Id: "abcdef"})
	require.NoError(t, err)
	require.Zero(t, response.Result, response.Message)
	_, err = store.CreateGadgetInstance(context.Background(), req)
	require.NoError(t, err, "explicit removal releases the instance ID")
	require.Equal(t, 2, manager.starts)
}

func TestCreateRejectsUntrackedInvalidFile(t *testing.T) {
	manager := &fakeFileManager{}
	store := &FileStore{instanceMgr: manager, directory: t.TempDir(), observed: make(map[string]string)}
	path := filepath.Join(store.directory, "abcdef.gadget")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	req := &api.CreateGadgetInstanceRequest{GadgetInstance: &api.GadgetInstance{
		Id: "abcdef", Name: "replacement", GadgetConfig: &api.GadgetRunRequest{ImageName: "replacement"},
	}}
	_, err := store.CreateGadgetInstance(context.Background(), req)
	require.ErrorContains(t, err, "already exists")
	require.Zero(t, manager.starts)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "{}", string(raw))
	require.Empty(t, store.observed)
}
