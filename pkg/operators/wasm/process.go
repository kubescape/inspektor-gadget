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
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

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
			err = bindProcessIdentity(i.gadgetCtx.Context(), host.HostProcFs, node, boot, pid, ticks, bind)
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

// bindProcessIdentity uses a host-owned launch barrier when present. Policy
// fields alone cannot select this path: only the native launcher can supply
// the private context capability. Existing-process attachment retains its
// exclusive ptrace activation protocol.
func bindProcessIdentity(ctx context.Context, procRoot, node, boot string, pid uint32, ticks uint64, bind func(int) error) error {
	matched, err := processlaunch.Bind(ctx, processlaunch.Identity{
		Node: node, BootID: boot, PID: pid, StartTimeTicks: ticks,
	}, bind)
	if matched {
		return err
	}
	return validateProcessIdentity(procRoot, node, boot, pid, ticks, bind)
}

func validateProcessIdentity(procRoot, node, boot string, pid uint32, startTicks uint64, bind func(int) error) (resultErr error) {
	if pid == uint32(os.Getpid()) {
		return fmt.Errorf("binding IG itself is unsupported: process activation requires a group stop")
	}
	if node == "" || boot == "" || pid == 0 || startTicks == 0 {
		return fmt.Errorf("incomplete process identity")
	}
	localNode := os.Getenv("NODE_NAME")
	if localNode == "" {
		var err error
		localNode, err = os.Hostname()
		if err != nil {
			return err
		}
	}
	if node != localNode {
		return fmt.Errorf("process node %q does not match %q", node, localNode)
	}
	bootData, err := os.ReadFile(filepath.Join(procRoot, "sys/kernel/random/boot_id"))
	if err != nil {
		return fmt.Errorf("reading boot ID: %w", err)
	}
	if strings.TrimSpace(string(bootData)) != boot {
		return fmt.Errorf("process boot ID does not match")
	}
	// pidfd_open accepts thread-group leaders only. Polling after reading stat
	// rejects an identity whose process exited during validation. The callback
	// may duplicate the FD for monitoring; this validation FD is always closed.
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return fmt.Errorf("opening process: %w", err)
	}
	defer unix.Close(fd)
	stat, err := os.ReadFile(filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "stat"))
	if err != nil {
		return fmt.Errorf("reading process stat: %w", err)
	}
	actual, err := processStartTicks(string(stat), pid)
	if err != nil {
		return err
	}
	if actual != startTicks {
		return fmt.Errorf("process start time does not match")
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if _, err := unix.Poll(fds, 0); err != nil {
		return fmt.Errorf("checking process liveness: %w", err)
	}
	if fds[0].Revents != 0 {
		return fmt.Errorf("process has exited")
	}
	return withProcessQuiesced(procRoot, pid, func() error {
		stat, err := os.ReadFile(filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "stat"))
		if err != nil {
			return err
		}
		actual, err := processStartTicks(string(stat), pid)
		if err != nil {
			return err
		}
		if actual != startTicks {
			return fmt.Errorf("process identity changed while stopping")
		}
		return bind(fd)
	})
}

// withProcessQuiesced owns ptrace stops, so SIGCONT from another process cannot
// resume a thread between identity validation and the task-storage update.
func withProcessQuiesced(procRoot string, pid uint32, bind func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Deliberately never unlock. Go retires this tracer thread on return,
		// ensuring the kernel detaches any tracee that could not stop by the deadline.
		result <- traceAndBindProcess(procRoot, pid, bind)
	}()
	return <-result
}

func traceAndBindProcess(procRoot string, pid uint32, bind func() error) (resultErr error) {
	states, err := processThreadStates(procRoot, pid)
	if err != nil {
		return err
	}
	stopped := 0
	for _, state := range states {
		if state == "t" {
			return fmt.Errorf("binding a ptrace-stopped process is unsupported")
		}
		if state == "T" {
			stopped++
		}
	}
	preserveStop := stopped == len(states)
	if stopped != 0 && !preserveStop {
		return fmt.Errorf("binding a partially stopped process is unsupported")
	}
	type traceStop struct {
		stopped bool
		signal  unix.Signal
	}
	traced := make(map[int]traceStop)
	defer func() {
		for tid, stop := range traced {
			if !stop.stopped {
				continue
			} // Retiring tracer thread handles this case.
			signal := uintptr(stop.signal)
			if preserveStop && signal == 0 {
				signal = uintptr(unix.SIGSTOP)
			}
			_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_DETACH), uintptr(tid), 0, signal, 0, 0)
			if errno != 0 && errno != unix.ESRCH {
				resultErr = errors.Join(resultErr, fmt.Errorf("detaching thread %d: %w", tid, errno))
			}
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out stopping process thread group")
		}
		tasks, err := os.ReadDir(filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "task"))
		if err != nil {
			return err
		}
		if len(tasks) == 0 {
			return fmt.Errorf("process has no threads")
		}
		if len(tasks) > maxHandles {
			return fmt.Errorf("too many process threads")
		}
		added := false
		for _, task := range tasks {
			tid, err := strconv.Atoi(task.Name())
			if err != nil {
				return err
			}
			if _, ok := traced[tid]; ok {
				continue
			}
			if err := unix.PtraceSeize(tid); err != nil {
				return fmt.Errorf("seizing thread %d: %w", tid, err)
			}
			traced[tid] = traceStop{}
			if err := unix.PtraceInterrupt(tid); err != nil {
				return fmt.Errorf("interrupting thread %d: %w", tid, err)
			}
			added = true
		}
		for tid, stop := range traced {
			if stop.stopped {
				continue
			}
			for {
				var status unix.WaitStatus
				waited, err := unix.Wait4(tid, &status, unix.WALL|unix.WNOHANG, nil)
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if err != nil {
					return fmt.Errorf("waiting for thread %d: %w", tid, err)
				}
				if waited == tid {
					if !status.Stopped() {
						return fmt.Errorf("thread %d exited while stopping", tid)
					}
					traced[tid] = traceStop{stopped: true, signal: signalForDetach(status)}
					break
				}
				if time.Now().After(deadline) {
					return fmt.Errorf("timed out stopping process thread group")
				}
				time.Sleep(time.Millisecond)
			}
		}
		// Re-enumerate after all observed threads stopped, catching threads created
		// before their parent entered its stop. Stable stopped parents cannot clone.
		if !added {
			return bind()
		}
	}
}

func processThreadStates(procRoot string, pid uint32) ([]string, error) {
	dir := filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "task")
	tasks, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	states := make([]string, 0, len(tasks))
	for _, task := range tasks {
		data, err := os.ReadFile(filepath.Join(dir, task.Name(), "stat"))
		if err != nil {
			return nil, err
		}
		end := strings.LastIndexByte(string(data), ')')
		if end == -1 {
			return nil, fmt.Errorf("invalid thread stat")
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) == 0 {
			return nil, fmt.Errorf("missing thread state")
		}
		if fields[0] == "Z" || fields[0] == "X" {
			return nil, fmt.Errorf("thread has exited")
		}
		states = append(states, fields[0])
	}
	if len(states) == 0 {
		return nil, fmt.Errorf("process has no threads")
	}
	return states, nil
}

func processStartTicks(stat string, pid uint32) (uint64, error) {
	// comm may contain spaces and closing parentheses; the final ')' ends it.
	open, close := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if open < 1 || close <= open {
		return 0, fmt.Errorf("invalid process stat")
	}
	actualPID, err := strconv.ParseUint(strings.TrimSpace(stat[:open]), 10, 32)
	if err != nil || uint32(actualPID) != pid {
		return 0, fmt.Errorf("process stat PID does not match")
	}
	fields := strings.Fields(stat[close+1:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("truncated process stat")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid process start time: %w", err)
	}
	return ticks, nil
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

// signalForDetach preserves ordinary signal-delivery stops. Interrupt/event
// stops are ptrace machinery and must not inject a synthetic signal on resume.
func signalForDetach(status unix.WaitStatus) unix.Signal {
	if !status.Stopped() || uint32(status)>>16 != 0 {
		return 0
	}
	return status.StopSignal()
}
