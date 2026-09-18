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
	"testing"

	"github.com/stretchr/testify/require"

	containerhook "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook"
)

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
