// Copyright 2024 The Inspektor Gadget authors
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

package containercollection

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	containerhook "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook"
)

// fakeExecHoldCrediter and fakeResolveAttacher are minimal stand-ins so this
// test can assert SetExecHoldHooks reaches the real ContainerNotifier without
// needing a live uprobetracer.Tracer or a real resolve+attach pipeline.
type fakeExecHoldCrediter struct{}

func (fakeExecHoldCrediter) CreditIfAttached(uint32, *os.File) (uint64, bool, error) {
	return 0, false, nil
}

type fakeResolveAttacher struct{}

func (fakeResolveAttacher) ResolveAndAttach(uint32, *os.File) error { return nil }

// TestMarkExecHoldCandidateByMntnsNotApplicable asserts the routine outcomes an
// external caller must be able to distinguish from a real failure. Both are
// reached on every node where the container-hook is not running the exec-hold
// path, so neither may look like an error to a caller driven by a live event
// stream.
func TestMarkExecHoldCandidateByMntnsNotApplicable(t *testing.T) {
	t.Run("no container notifier installed", func(t *testing.T) {
		cc := &ContainerCollection{}
		require.Equal(t, containerhook.ExecHoldMarkNotApplicable,
			cc.MarkExecHoldCandidateByMntns(4242, "/usr/bin/allowed"))
	})

	t.Run("mount namespace not tracked", func(t *testing.T) {
		cc := &ContainerCollection{}
		require.NoError(t, cc.Initialize())
		t.Cleanup(cc.Close)

		// A container the collection knows nothing about: the mntns of an
		// already-exited container looks exactly like this.
		require.Nil(t, cc.LookupContainerByMntns(4242))
		require.Equal(t, containerhook.ExecHoldMarkNotApplicable,
			cc.MarkExecHoldCandidateByMntns(4242, "/usr/bin/allowed"))
	})
}

// TestSetExecHoldHooksNoNotifierIsSafeNoOp asserts SetExecHoldHooks never
// panics when exec-hold's fanotify group -- and therefore the notifier that
// owns it -- was never created (plain Initialize() with no
// WithContainerFanotifyEbpf option, exactly like MarkExecHoldCandidateByMntns's
// own "no container notifier installed" case above). Delegation to a REAL
// notifier is covered at the container-hook layer
// (ContainerNotifier.SetExecHoldHooks's own tests); constructing one here
// would need a live, root-privileged fanotify group and would only be
// re-testing that same behavior through an extra layer of indirection.
func TestSetExecHoldHooksNoNotifierIsSafeNoOp(t *testing.T) {
	cc := &ContainerCollection{}
	require.NotPanics(t, func() {
		cc.SetExecHoldHooks(fakeExecHoldCrediter{}, fakeResolveAttacher{})
	})

	cc2 := &ContainerCollection{}
	require.NoError(t, cc2.Initialize())
	t.Cleanup(cc2.Close)
	require.Nil(t, cc2.containerNotifier,
		"plain Initialize() with no WithContainerFanotifyEbpf must not construct a notifier")
	require.NotPanics(t, func() {
		cc2.SetExecHoldHooks(fakeExecHoldCrediter{}, fakeResolveAttacher{})
	})
}

// TestExecHoldStatsNoNotifierReportsUnavailable pins ExecHoldStats' ok=false
// contract: no exec-hold fanotify group means "nothing to export yet", not a
// panic and not a (zero-value, true) that a metrics exporter could mistake
// for real all-zero counters.
func TestExecHoldStatsNoNotifierReportsUnavailable(t *testing.T) {
	cc := &ContainerCollection{}
	stats, ok := cc.ExecHoldStats()
	require.False(t, ok, "no notifier at all must report unavailable")
	require.Zero(t, stats)

	cc2 := &ContainerCollection{}
	require.NoError(t, cc2.Initialize())
	t.Cleanup(cc2.Close)
	stats2, ok2 := cc2.ExecHoldStats()
	require.False(t, ok2, "plain Initialize() with no WithContainerFanotifyEbpf must report unavailable")
	require.Zero(t, stats2)
}
