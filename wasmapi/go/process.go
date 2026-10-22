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

package api

import (
	"fmt"
	"runtime"
	_ "unsafe"
)

//go:wasmimport ig bindProcess
//go:linkname bindProcess bindProcess
func bindProcess(target uint32, node uint64, bootID uint64, hostPID uint32, startTicks uint64) uint32

// BindProcess validates an IG-owned blocked child and writes uint64(1) to
// its task-storage entry. The map must have a 4-byte key and 8-byte value.
// StartTicks is field 22 of /proc/PID/stat. IG must run in the host PID namespace.
// Kernel task storage disappears on task exit and cannot select a reused PID.
// The host context must carry the private processlaunch capability for the child.
// Arbitrary running processes cannot be bound by supplying their identity.
// Before calling, register process_lifecycle with event_type (string), host_pid
// (uint32), start_time_ticks (uint64). It receives EXITED after gadgetStart
// completes. One process binding is supported per gadget instance.
func BindProcess(target Map, node, bootID string, hostPID uint32, startTicks uint64) error {
	result := bindProcess(uint32(target), uint64(stringToBufPtr(node)), uint64(stringToBufPtr(bootID)), hostPID, startTicks)
	runtime.KeepAlive(node)
	runtime.KeepAlive(bootID)
	if result != 0 {
		return fmt.Errorf("binding process identity")
	}
	return nil
}
