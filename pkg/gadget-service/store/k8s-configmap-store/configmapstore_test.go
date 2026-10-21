// Copyright 2024-2025 The Inspektor Gadget authors
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

package k8sconfigmapstore

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
)

type fakeManager struct {
	removed   []string
	desired   *api.GadgetInstance
	updateErr error
	removeErr error
}

func (m *fakeManager) RemoveGadget(id string) error {
	m.removed = append(m.removed, id)
	return m.removeErr
}

func (m *fakeManager) ReconcileGadget(_ context.Context, desired *api.GadgetInstance) error {
	m.desired = desired
	return m.updateErr
}

func TestConfigMapReconcilePreservesRunningInstance(t *testing.T) {
	for _, tc := range []struct {
		name      string
		invalid   bool
		updateErr error
	}{
		{name: "valid live update"},
		{name: "malformed annotation", invalid: true},
		{name: "invalid policy", updateErr: errors.New("policy rejected")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := &fakeManager{updateErr: tc.updateErr}
			store := &Store{store: cache.NewStore(cache.MetaNamespaceKeyFunc), instanceMgr: mgr, nodeName: "node"}
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "instance", Namespace: "ig", Annotations: map[string]string{gadgetImage: "enforce"}}, Data: map[string]string{"operator.oci.wasm.exec-policy": "updated"}}
			if tc.invalid {
				cm.Annotations[gadgetTimeout] = "invalid"
			}
			require.NoError(t, store.store.Add(cm))
			err := store.reconcile("ig/instance")
			if tc.invalid || tc.updateErr != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Empty(t, mgr.removed)
			if tc.invalid {
				require.Nil(t, mgr.desired)
			} else {
				require.Equal(t, "updated", mgr.desired.GadgetConfig.ParamValues["operator.oci.wasm.exec-policy"])
			}
		})
	}
}

func TestConfigMapRemovalAndNodeSelection(t *testing.T) {
	mgr := &fakeManager{removeErr: instancemanager.ErrNotFound}
	store := &Store{store: cache.NewStore(cache.MetaNamespaceKeyFunc), instanceMgr: mgr, nodeName: "here"}
	require.NoError(t, store.reconcile("ig/deleted"))
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "elsewhere", Namespace: "ig", Annotations: map[string]string{gadgetNodes: "other-node"}}}
	require.NoError(t, store.store.Add(cm))
	require.NoError(t, store.reconcile("ig/elsewhere"))
	require.Equal(t, []string{"deleted", "elsewhere"}, mgr.removed)
	require.Nil(t, mgr.desired)
}
