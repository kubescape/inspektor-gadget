// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package instancemanager

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type attachmentStream struct {
	api.GadgetManager_RunGadgetServer
	ctx       context.Context
	sent      int
	sendError error
}

func (s *attachmentStream) Context() context.Context { return s.ctx }
func (s *attachmentStream) Send(*api.GadgetEvent) error {
	s.sent++
	return s.sendError
}

func TestAttachReportsInitializationFailure(t *testing.T) {
	m := testManager(t)
	d := desired("failed")
	d.GadgetConfig.Version = 0
	m.RunGadget(d)
	instance := m.LookupInstance("failed")
	require.NotNil(t, instance)
	failure := instance.WaitStopped(context.Background())
	require.Error(t, failure)
	t.Cleanup(func() { require.NoError(t, m.RemoveGadget("failed")) })

	stream := &attachmentStream{ctx: context.Background()}
	result := make(chan error, 1)
	go func() { result <- m.AttachToGadgetInstance("failed", stream) }()
	require.ErrorIs(t, receive(t, result), failure)
	require.Zero(t, stream.sent, "failed initialization must not send metadata or events")
	require.Empty(t, instance.clients)
}

func TestAttachReportsMetadataSendFailure(t *testing.T) {
	m := testManager(t)
	require.NoError(t, m.StartGadget(context.Background(), desired("running")))
	t.Cleanup(func() { require.NoError(t, m.StopGadget(context.Background(), "running")) })
	failure := errors.New("metadata send failed")
	stream := &attachmentStream{ctx: context.Background(), sendError: failure}
	require.ErrorIs(t, m.AttachToGadgetInstance("running", stream), failure)
	require.Equal(t, 1, stream.sent)
	require.Empty(t, m.LookupInstance("running").clients)
}

func TestAttachSuccessfulCompletion(t *testing.T) {
	m := testManager(t)
	require.NoError(t, m.StartGadget(context.Background(), desired("running")))
	t.Cleanup(func() { require.NoError(t, m.StopGadget(context.Background(), "running")) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stream := &attachmentStream{ctx: ctx}
	require.NoError(t, m.AttachToGadgetInstance("running", stream))
	require.Equal(t, 1, stream.sent)
	require.Empty(t, m.LookupInstance("running").clients)
}
