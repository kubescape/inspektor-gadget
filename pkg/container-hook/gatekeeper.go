// Copyright 2026 The Inspektor Gadget authors
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

package containerhook

// Fanotify permission events are answered from a separate process, the
// gatekeeper (package gatekeeper).
//
// Permission events have no kernel-side timeout: a runc exec (or pid-file
// access) blocks in fanotify_get_response until the reader answers. When the
// reader is a large process that is alive but cannot make progress (throttled
// in memcg reclaim, CPU-starved, a handler stuck on a slow dependency, or
// stopped), every container start, stop and exec on the host blocks, kubelet
// cannot restart the process through the same runtime, and the node freezes
// while still reporting Ready.
//
// An in-process watchdog does not help: under memcg throttling the threads
// holding the Go scheduler's Ps are themselves throttled, so no goroutine runs
// (observed with GOMAXPROCS=2 from a 200m CPU limit). The answer therefore
// has to come from another process.
//
// The gatekeeper is the only reader of both fanotify groups. For each event it
// dequeues the matching eBPF record (runtime group), then forwards the event
// to this process over a SOCK_SEQPACKET socket, passing the event fd with
// SCM_RIGHTS. We process it exactly as before and reply "done"; the
// gatekeeper then answers FAN_ALLOW. If we do not reply within the bound, or
// the socket is full, the gatekeeper allows on its own. It never waits on us
// and allocates nothing per event, so it keeps answering while we are stuck.
//
// The gatekeeper runs the dedicated small binary (cmd/container-hook-gatekeeper)
// when it is installed, or else this binary re-executed: init() below diverts
// it into gatekeeper.Run before main, so embedders work unchanged (at the
// cost of the embedder's package initialization in that process).
//
// Failing open loses detection for the affected containers; it never denies.
// That is the intended trade: a missed container is recoverable, a frozen
// node is not.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/s3rj1k/go-fanotify/fanotify"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook/gatekeeper"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	// gatekeeperDisableEnv makes this process read and answer the fanotify
	// groups itself, without a deadline (the behavior before the
	// gatekeeper). Escape hatch only.
	gatekeeperDisableEnv = "IG_CONTAINER_HOOK_GATEKEEPER_DISABLE"
	// gatekeeperBinEnv overrides the path of the dedicated gatekeeper binary.
	gatekeeperBinEnv = "IG_CONTAINER_HOOK_GATEKEEPER_BIN"
	// defaultGatekeeperBin is where images ship the dedicated binary.
	defaultGatekeeperBin = "/usr/bin/ig-container-hook-gatekeeper"
	// gatekeeperCgroupEnv overrides the cgroup v2 directory the gatekeeper
	// runs in; "none" keeps it in our cgroup. Default: defaultGatekeeperCgroup
	// under the host's cgroup v2 root.
	gatekeeperCgroupEnv     = "IG_CONTAINER_HOOK_GATEKEEPER_CGROUP_DIR"
	defaultGatekeeperCgroup = "ig-container-hook-gatekeeper"

	defaultPermResponseBound = time.Second
	minPermResponseBound     = 100 * time.Millisecond
	maxPermResponseBound     = 60 * time.Second
	// The bound has to leave room for the AddContainer callback budget, which
	// is deliberately allowed to hold the pid-file event (create→start).
	permBoundCallbackMargin = 500 * time.Millisecond
)

var recordSize = int(unsafe.Sizeof(execruntimeRecord{}))

var configuredPermResponseBound atomic.Int64

// SetPermissionResponseBound sets how long a container runtime exec may wait
// for the container hook before the gatekeeper allows it on its own. It must be
// called before starting container collection. The pid-file event, which
// deliberately holds create→start for the AddContainer callback, gets at least
// that callback budget plus a margin; see PidFileResponseBound.
func SetPermissionResponseBound(bound time.Duration) error {
	if bound < minPermResponseBound || bound > maxPermResponseBound {
		return fmt.Errorf("permission response bound must be in [%s, %s]: %s",
			minPermResponseBound, maxPermResponseBound, bound)
	}
	configuredPermResponseBound.Store(int64(bound))
	return nil
}

// PermissionResponseBound returns the bound for runtime-binary events (see
// SetPermissionResponseBound).
func PermissionResponseBound() time.Duration {
	if b := configuredPermResponseBound.Load(); b != 0 {
		return time.Duration(b)
	}
	return defaultPermResponseBound
}

// PidFileResponseBound returns the bound for pid-file events: the
// runtime-binary bound, but never below the AddContainer callback budget plus
// a margin, so the callback guardrail keeps its meaning.
func PidFileResponseBound() time.Duration {
	bound := PermissionResponseBound()
	if floor := AddContainerCallbackHardBound() + permBoundCallbackMargin; bound < floor {
		bound = floor
	}
	return bound
}

func init() {
	if os.Getenv(gatekeeper.Env) == "1" {
		os.Exit(gatekeeper.Run())
	}
}

// gkEvent is an event the gatekeeper forwarded. data.Fd is our own copy of
// the event fd (or -1).
type gkEvent struct {
	seq       uint32
	data      *fanotify.EventMetadata
	record    execruntimeRecord
	recordErr error
}

var errNoRecord = errors.New("no eBPF record for this event")

type gatekeeperProc struct {
	cmd  *exec.Cmd
	sock int

	runtimeCh chan *gkEvent
	pidCh     chan *gkEvent

	sendMu    sync.Mutex
	closeOnce sync.Once
	exited    chan struct{}
}

// gatekeeperCgroup returns the cgroup directory for the gatekeeper, or "".
// It must not be our own memcg: see gatekeeper.joinCgroup.
func gatekeeperCgroup() string {
	switch v := os.Getenv(gatekeeperCgroupEnv); v {
	case "none":
		return ""
	case "":
		return filepath.Join(host.HostRoot, "sys/fs/cgroup", defaultGatekeeperCgroup)
	default:
		return v
	}
}

func gatekeeperBinary() string {
	if p := os.Getenv(gatekeeperBinEnv); p != "" {
		return p
	}
	if st, err := os.Stat(defaultGatekeeperBin); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
		return defaultGatekeeperBin
	}
	return "/proc/self/exe"
}

// dupCloexec duplicates fd with O_CLOEXEC, so the only copy the gatekeeper
// inherits is the one exec.Cmd places at its ExtraFiles position.
func dupCloexec(fd int, name string) (*os.File, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("dup %s fd: %w", name, err)
	}
	return os.NewFile(uintptr(dup), name), nil
}

// startGatekeeper starts the gatekeeper for the two fanotify groups.
// recordsFd may be -1.
func startGatekeeper(runtimeFd, pidFd, recordsFd int, runtimeBound, pidFileBound time.Duration) (*gatekeeperProc, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}
	parentSock := fds[0]
	child := os.NewFile(uintptr(fds[1]), "gatekeeper-sock")
	defer child.Close()

	// Order must match gatekeeper.Fd*.
	files := make([]*os.File, 0, 4)
	defer func() {
		for _, f := range files {
			if f != child {
				f.Close()
			}
		}
	}()
	for _, src := range []struct {
		fd   int
		name string
	}{{runtimeFd, "fanotify-runtime"}, {pidFd, "fanotify-pidfile"}} {
		f, err := dupCloexec(src.fd, src.name)
		if err != nil {
			unix.Close(parentSock)
			return nil, err
		}
		files = append(files, f)
	}
	files = append(files, child)
	size := 0
	if recordsFd >= 0 {
		f, err := dupCloexec(recordsFd, "ig_fa_records")
		if err != nil {
			unix.Close(parentSock)
			return nil, err
		}
		files = append(files, f)
		size = recordSize
	}

	cmd := exec.Command(gatekeeperBinary())
	cmd.Env = append(os.Environ(),
		gatekeeper.Env+"=1",
		gatekeeper.BoundRuntimeEnv+"="+strconv.FormatInt(int64(runtimeBound), 10),
		gatekeeper.BoundPidFileEnv+"="+strconv.FormatInt(int64(pidFileBound), 10),
		gatekeeper.RecordSizeEnv+"="+strconv.Itoa(size),
		gatekeeper.CgroupEnv+"="+gatekeeperCgroup())
	cmd.ExtraFiles = files
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	// Belt and braces: the gatekeeper also exits when the socket closes,
	// which is what happens when we die.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		unix.Close(parentSock)
		return nil, fmt.Errorf("starting gatekeeper %s: %w", cmd.Path, err)
	}

	g := &gatekeeperProc{
		cmd:       cmd,
		sock:      parentSock,
		runtimeCh: make(chan *gkEvent, 256),
		pidCh:     make(chan *gkEvent, 256),
		exited:    make(chan struct{}),
	}
	go func() {
		_ = cmd.Wait()
		close(g.exited)
	}()
	return g, nil
}

// receive forwards gatekeeper events to the per-group channels until the
// gatekeeper goes away or close is called. onLost runs in both cases; it is up
// to the caller to tell them apart.
func (g *gatekeeperProc) receive(onLost func(error)) {
	defer close(g.runtimeCh)
	defer close(g.pidCh)

	buf := make([]byte, gatekeeper.HeaderLen+recordSize)
	oob := make([]byte, unix.CmsgSpace(4))
	for {
		n, oobn, _, _, err := unix.Recvmsg(g.sock, buf, oob, unix.MSG_CMSG_CLOEXEC)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			if err == nil {
				err = errors.New("gatekeeper closed the connection")
			}
			onLost(err)
			return
		}
		if n < gatekeeper.HeaderLen {
			continue
		}
		ev := &gkEvent{seq: binary.LittleEndian.Uint32(buf[0:])}
		group := buf[4]
		flags := buf[5]
		meta := unix.FanotifyEventMetadata{
			Event_len:    uint32(fanotifyEventMetadataSize),
			Vers:         unix.FANOTIFY_METADATA_VERSION,
			Metadata_len: uint16(fanotifyEventMetadataSize),
			Mask:         binary.LittleEndian.Uint64(buf[8:]),
			Fd:           -1,
			Pid:          int32(binary.LittleEndian.Uint32(buf[16:])),
		}
		if flags&gatekeeper.FlagHasFd != 0 && oobn > 0 {
			if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil && len(msgs) > 0 {
				if fds, err := unix.ParseUnixRights(&msgs[0]); err == nil && len(fds) > 0 {
					meta.Fd = int32(fds[0])
					for _, extra := range fds[1:] {
						unix.Close(extra)
					}
				}
			}
		}
		ev.data = &fanotify.EventMetadata{FanotifyEventMetadata: meta}
		if flags&gatekeeper.FlagHasRecord != 0 {
			if flags&gatekeeper.FlagRecordOK != 0 && n >= gatekeeper.HeaderLen+recordSize {
				ev.record = *(*execruntimeRecord)(unsafe.Pointer(&buf[gatekeeper.HeaderLen]))
			} else {
				ev.recordErr = errNoRecord
			}
		}
		if group == gatekeeper.GroupRuntime {
			g.runtimeCh <- ev
		} else {
			g.pidCh <- ev
		}
	}
}

// done tells the gatekeeper we finished with an event, so it can be allowed
// now. A late or failed reply is harmless: the gatekeeper has already allowed
// the event on its own.
func (g *gatekeeperProc) done(seq uint32) {
	var b [gatekeeper.DoneLen]byte
	binary.LittleEndian.PutUint32(b[:], seq)
	g.sendMu.Lock()
	defer g.sendMu.Unlock()
	if g.sock >= 0 {
		_, _ = unix.Write(g.sock, b[:])
	}
}

// close makes the gatekeeper allow everything pending and exit, and unblocks
// receive. Idempotent.
func (g *gatekeeperProc) close() {
	g.closeOnce.Do(func() {
		_ = unix.Shutdown(g.sock, unix.SHUT_RDWR)
		select {
		case <-g.exited:
		case <-time.After(5 * time.Second):
			_ = g.cmd.Process.Kill()
			<-g.exited
		}
		g.sendMu.Lock()
		unix.Close(g.sock)
		g.sock = -1
		g.sendMu.Unlock()
	})
}

func gatekeeperDisabled() bool {
	v := os.Getenv(gatekeeperDisableEnv)
	return v == "1" || v == "true"
}

func (g *gatekeeperProc) String() string {
	if g == nil || g.cmd == nil || g.cmd.Process == nil {
		return "gatekeeper(none)"
	}
	return fmt.Sprintf("gatekeeper(pid %d, %s)", g.cmd.Process.Pid, g.cmd.Path)
}
