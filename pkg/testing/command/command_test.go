// Copyright 2019-2024 The Inspektor Gadget authors
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

package command

import (
	"bytes"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestObservedCommandRetainsOutputAndReaps(t *testing.T) {
	var observed bytes.Buffer
	c := &Command{Name: "observed", Cmd: exec.Command("sh", "-c", "printf 'out'; printf 'err' >&2"), StdErrWriter: &observed, ObserveExit: true}
	c.Start(t)
	select {
	case <-c.Exited():
	case <-time.After(time.Second):
		t.Fatal("exit not observed")
	}
	require.NoError(t, c.ExitError())
	require.Equal(t, "out", c.stdout.String())
	require.Equal(t, "err", c.stderr.String())
	require.Equal(t, "err", observed.String())
	c.Stop(t)
	require.False(t, c.Running())
}

func TestObservedCommandStop(t *testing.T) {
	c := &Command{Name: "observed", Cmd: exec.Command("sleep", "60"), ObserveExit: true}
	c.Start(t)
	c.Stop(t)
	select {
	case <-c.Exited():
	default:
		t.Fatal("process not reaped")
	}
	require.False(t, c.Running())
}

func TestObservedCommandError(t *testing.T) {
	c := &Command{Name: "observed", Cmd: exec.Command("sh", "-c", "exit 7"), ObserveExit: true}
	c.Start(t)
	<-c.Exited()
	require.ErrorContains(t, c.ExitError(), "exit status 7")
	require.ErrorContains(t, c.kill(), "exit status 7")
}
