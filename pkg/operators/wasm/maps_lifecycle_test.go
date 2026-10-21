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

package wasm

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func TestMapFreezeInvalidHandle(t *testing.T) {
	i := &wasmOperatorInstance{logger: log.New(), handleMap: map[uint32]any{1: "not a map"}}
	for _, h := range []uint64{0, 1, 99} {
		stack := []uint64{h}
		i.mapFreeze(context.Background(), nil, stack)
		if stack[0] != 1 {
			t.Fatalf("handle %d accepted", h)
		}
	}
}

func TestOwnedMapCleanupAndFreeze(t *testing.T) {
	_ = rlimit.RemoveMemlock()
	newMap := func() *ebpf.Map {
		t.Helper()
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skip("requires BPF map privileges")
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close() })
		return m
	}
	owned, borrowed := newMap(), newMap()
	i := &wasmOperatorInstance{logger: log.New(), handleMap: make(map[uint32]any), createdMap: make(map[uint32]*ebpf.Map)}
	h := i.addHandle(owned)
	i.createdMap[h] = owned
	i.addHandle(borrowed)
	if err := owned.Put(uint32(0), uint32(1)); err != nil {
		t.Fatal(err)
	}
	stack := []uint64{uint64(h)}
	i.mapFreeze(context.Background(), nil, stack)
	if stack[0] != 0 {
		t.Fatal("freeze failed")
	}
	if err := owned.Put(uint32(0), uint32(2)); err == nil {
		t.Fatal("frozen map accepted update")
	}
	i.closeMaps()
	i.closeMaps()
	if owned.FD() != -1 {
		t.Fatal("owned map remains open")
	}
	if err := borrowed.Put(uint32(0), uint32(3)); err != nil {
		t.Fatalf("borrowed map closed: %v", err)
	}
	if len(i.handleMap) != 0 || len(i.createdMap) != 0 {
		t.Fatal("handles remain")
	}
	// Releasing a map-of-maps lookup handle must close its separately owned FD.
	lookup := newMap()
	h = i.addHandle(lookup)
	i.createdMap[h] = lookup
	i.delHandle(h)
	if lookup.FD() != -1 {
		t.Fatal("lookup map FD remains open")
	}
}

func TestStoppedGuestIgnoresCallbacks(t *testing.T) {
	i := &wasmOperatorInstance{}
	i.guestStopped.Store(true)
	// Shutdown can emit to a subscribed datasource while holding this mutex.
	// The stopped check must happen before waiting for it.
	i.dataSourceCallbackLock.Lock()
	defer i.dataSourceCallbackLock.Unlock()
	// No callback function exists: invoking it would panic.
	if err := i.callDsCallbackWithLock(context.Background(), 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := i.Stop(nil); err != nil {
		t.Fatal(err)
	}
}
