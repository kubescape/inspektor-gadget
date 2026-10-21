// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package filestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type fakeFileManager struct {
	applied     []string
	removed     []string
	reject      bool
	updateError error
	starts      int
	active      string
}

func (m *fakeFileManager) RunGadget(*api.GadgetInstance) { m.starts++ }
func (m *fakeFileManager) RemoveGadget(id string) error {
	m.removed = append(m.removed, id)
	return nil
}

func (m *fakeFileManager) ReconcileGadget(_ context.Context, instance *api.GadgetInstance) error {
	if m.reject {
		m.updateError = errors.New("invalid policy")
		return m.updateError
	}
	m.updateError = nil
	m.active = instance.GadgetConfig.ParamValues["policy"]
	m.applied = append(m.applied, m.active)
	return nil
}

func writeInstance(t *testing.T, directory, id, policy string) {
	t.Helper()
	blob, err := protojson.Marshal(&api.CreateGadgetInstanceRequest{GadgetInstance: &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{ImageName: "enforce", ParamValues: map[string]string{"policy": policy}}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, id+".gadget"), blob, 0o600))
}

func TestFileReconciliationRetainsLastGood(t *testing.T) {
	manager := &fakeFileManager{}
	store := &FileStore{instanceMgr: manager, directory: t.TempDir(), observed: make(map[string]string)}
	path := filepath.Join(store.directory, "instance.gadget")
	writeInstance(t, store.directory, "instance", "initial")
	require.NoError(t, store.reconcileFiles(context.Background()))
	require.Equal(t, []string{"initial"}, manager.applied)
	require.NoError(t, store.reconcileFiles(context.Background()))
	require.Len(t, manager.applied, 1, "unchanged files do not reapply")
	for _, bad := range []string{"{", "{}", `{"gadgetInstance":{"id":"other","gadgetConfig":{"imageName":"enforce"}}}`} {
		require.NoError(t, os.WriteFile(path, []byte(bad), 0o600))
		require.NoError(t, store.reconcileFiles(context.Background()))
		require.Len(t, manager.applied, 1)
		require.Empty(t, manager.removed)
	}
	writeInstance(t, store.directory, "instance", "updated")
	manager.reject = true
	require.NoError(t, store.reconcileFiles(context.Background()))
	require.Len(t, manager.applied, 1)
	require.Empty(t, manager.removed)
	manager.reject = false
	require.NoError(t, store.reconcileFiles(context.Background()))
	require.Equal(t, []string{"initial", "updated"}, manager.applied)
	require.NoError(t, os.Remove(path))
	require.NoError(t, store.reconcileFiles(context.Background()))
	require.Equal(t, []string{"instance"}, manager.removed)
}

func TestFileWatcherAppliesEditsAndCloses(t *testing.T) {
	manager := &fakeFileManager{}
	store := &FileStore{instanceMgr: manager, directory: t.TempDir(), observed: make(map[string]string)}
	writeInstance(t, store.directory, "instance", "initial")
	require.NoError(t, store.ResumeStoredGadgets())
	t.Cleanup(store.Close)
	writeInstance(t, store.directory, "instance", "edited")
	require.Eventually(t, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(manager.applied) == 2 && manager.applied[1] == "edited"
	}, 3*time.Second, 10*time.Millisecond)
	store.Close()
}

func TestFileRestoreClearsRejectedUpdate(t *testing.T) {
	manager := &fakeFileManager{}
	store := &FileStore{instanceMgr: manager, directory: t.TempDir(), observed: make(map[string]string)}
	writeInstance(t, store.directory, "instance", "initial")
	require.NoError(t, store.reconcileFiles(context.Background()))
	writeInstance(t, store.directory, "instance", "rejected")
	manager.reject = true
	require.NoError(t, store.reconcileFiles(context.Background()))
	require.Error(t, manager.updateError)
	_, tracked := store.observed["instance"]
	require.True(t, tracked, "failed updates must retain deletion tracking")
	manager.reject = false
	writeInstance(t, store.directory, "instance", "initial")
	require.NoError(t, store.reconcileFiles(context.Background()))
	require.NoError(t, manager.updateError)
	require.Equal(t, []string{"initial", "initial"}, manager.applied)
	require.Zero(t, manager.starts)
	require.Empty(t, manager.removed)
	require.NoError(t, os.Remove(filepath.Join(store.directory, "instance.gadget")))
	require.NoError(t, store.reconcileFiles(context.Background()))
	require.Equal(t, []string{"instance"}, manager.removed)
}

func TestRestoreAfterInvalidFileRequiresAcknowledgement(t *testing.T) {
	for name, invalid := range map[string]string{
		"malformed":          "{",
		"missing instance":   "{}",
		"different identity": `{"gadgetInstance":{"id":"other","gadgetConfig":{"imageName":"enforce"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			manager := &fakeFileManager{}
			store := &FileStore{instanceMgr: manager, directory: t.TempDir(), observed: make(map[string]string)}
			path := filepath.Join(store.directory, "instance.gadget")
			writeInstance(t, store.directory, "instance", "initial")
			require.NoError(t, store.reconcileFiles(context.Background()))
			manager.active = "direct" // Another producer bypasses the stored desired file.
			require.NoError(t, os.WriteFile(path, []byte(invalid), 0o600))
			require.NoError(t, store.reconcileFiles(context.Background()))
			require.Equal(t, "direct", manager.active)
			require.Len(t, manager.applied, 1)
			_, tracked := store.observed["instance"]
			require.True(t, tracked)
			writeInstance(t, store.directory, "instance", "initial")
			manager.reject = true
			require.NoError(t, store.reconcileFiles(context.Background()))
			require.Error(t, manager.updateError, "restoration must reach the manager")
			require.Equal(t, "direct", manager.active)
			manager.reject = false
			require.NoError(t, store.reconcileFiles(context.Background()))
			require.Equal(t, "initial", manager.active)
			require.Equal(t, []string{"initial", "initial"}, manager.applied)
			require.NoError(t, manager.updateError)
			require.Zero(t, manager.starts)
			require.Empty(t, manager.removed)
			require.NoError(t, os.WriteFile(path, []byte(invalid), 0o600))
			require.NoError(t, store.reconcileFiles(context.Background()))
			require.NoError(t, os.Remove(path))
			require.NoError(t, store.reconcileFiles(context.Background()))
			require.Equal(t, []string{"instance"}, manager.removed, "invalid edits retain deletion ownership")
		})
	}
}
