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
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/processlaunch"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func (i *wasmOperatorInstance) addProcessFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "bindProcess", i.bindProcess,
		[]wapi.ValueType{wapi.ValueTypeI32, wapi.ValueTypeI64, wapi.ValueTypeI64, wapi.ValueTypeI32, wapi.ValueTypeI64},
		[]wapi.ValueType{wapi.ValueTypeI32})
}

// bindProcess seeds task storage through a pidfd, tying the binding to the
// actual task rather than a PID that could later be reused.
func (i *wasmOperatorInstance) bindProcess(ctx context.Context, m wapi.Module, stack []uint64) {
	target, ok := getHandle[*ebpf.Map](i, wapi.DecodeU32(stack[0]))
	if !ok {
		stack[0] = 1
		return
	}
	if target.Type() != ebpf.TaskStorage || target.KeySize() != 4 || target.ValueSize() != 8 {
		i.logger.Warnf("bindProcess: expected task storage with 4-byte key and 8-byte value")
		stack[0] = 1
		return
	}
	node, err := stringFromStack(m, stack[1])
	if err != nil {
		stack[0] = 1
		return
	}
	boot, err := stringFromStack(m, stack[2])
	if err == nil {
		var inHost bool
		inHost, err = host.IsHostPidNs()
		if err == nil && !inHost {
			err = fmt.Errorf("process binding requires the host PID namespace")
		}
	}
	if err == nil {
		ds := i.gadgetCtx.GetDataSources()["process_lifecycle"]
		if i.ctx == nil || i.processLifecycleReady == nil || ds == nil ||
			ds.GetField("event_type") == nil || ds.GetField("host_pid") == nil || ds.GetField("start_time_ticks") == nil {
			err = fmt.Errorf("process lifecycle datasource and pre-start context required")
		} else if !i.processWatchActive.CompareAndSwap(false, true) {
			err = fmt.Errorf("only one process binding per gadget instance is supported")
		} else {
			pid, ticks := wapi.DecodeU32(stack[3]), stack[4]
			bind := func(fd int) error {
				watchFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
				if err != nil {
					return err
				}
				if err := target.Update(int32(fd), uint64(1), ebpf.UpdateNoExist); err != nil {
					unix.Close(watchFD)
					return err
				}
				i.processWatchWG.Add(1)
				go i.watchProcess(watchFD, ds, pid, ticks)
				return nil
			}
			err = bindProcessIdentity(i.gadgetCtx.Context(), node, boot, pid, ticks, bind)
			if err != nil {
				i.processWatchActive.Store(false)
			}
		}
	}
	stack[0] = 0
	if err != nil {
		i.logger.Warnf("bindProcess: %v", err)
		stack[0] = 1
	}
}

// bindProcessIdentity only accepts the host-owned child held by processlaunch.
// Policy fields identify that child but cannot grant permission to bind a PID.
func bindProcessIdentity(ctx context.Context, node, boot string, pid uint32, ticks uint64, bind func(int) error) error {
	return processlaunch.Bind(ctx, processlaunch.Identity{
		Node: node, BootID: boot, PID: pid, StartTimeTicks: ticks,
	}, bind)
}

func (i *wasmOperatorInstance) watchProcess(fd int, ds datasource.DataSource, pid uint32, ticks uint64) {
	defer i.processWatchWG.Done()
	defer unix.Close(fd)
	select {
	case <-i.ctx.Done():
		return
	case <-i.processLifecycleReady:
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for i.ctx.Err() == nil {
		_, err := unix.Poll(fds, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			i.logger.Warnf("watching process: %v", err)
			return
		}
		if fds[0].Revents == 0 {
			continue
		}
		if i.ctx.Err() != nil {
			return
		}
		packet, err := ds.NewPacketSingle()
		if err != nil {
			i.logger.Warnf("process exit packet: %v", err)
			return
		}
		if err = ds.GetField("event_type").PutString(packet, "EXITED"); err == nil {
			err = ds.GetField("host_pid").PutUint32(packet, pid)
		}
		if err == nil {
			err = ds.GetField("start_time_ticks").PutUint64(packet, ticks)
		}
		if err != nil {
			ds.Release(packet)
			i.logger.Warnf("process exit fields: %v", err)
			return
		}
		if err := ds.EmitAndRelease(packet); err != nil {
			i.logger.Warnf("process exit event: %v", err)
		}
		return
	}
}
