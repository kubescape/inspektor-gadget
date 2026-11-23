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

// Package gatekeeper is the process that reads the container hook's fanotify
// groups and answers their permission events with a deadline, so a stalled
// container hook cannot freeze container lifecycle on the host. See
// pkg/container-hook/gatekeeper.go for the design; this package holds only the
// process side and the wire protocol, and imports nothing heavy, so the
// dedicated binary (cmd/container-hook-gatekeeper) stays small.
package gatekeeper

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// Env marks a process started as the gatekeeper.
	Env = "IG_CONTAINER_HOOK_GATEKEEPER"
	// BoundRuntimeEnv and BoundPidFileEnv are the response bounds, in
	// nanoseconds, for the runtime-binary and pid-file groups.
	BoundRuntimeEnv = "IG_CONTAINER_HOOK_GATEKEEPER_BOUND_RUNTIME_NS"
	BoundPidFileEnv = "IG_CONTAINER_HOOK_GATEKEEPER_BOUND_PIDFILE_NS"
	// RecordSizeEnv is the size of an ig_fa_records value; 0 when there is
	// no record queue.
	RecordSizeEnv = "IG_CONTAINER_HOOK_GATEKEEPER_RECORD_SIZE"
	// CgroupEnv is the cgroup v2 directory the gatekeeper moves itself into
	// (see joinCgroup). Empty: stay in the inherited cgroup.
	CgroupEnv = "IG_CONTAINER_HOOK_GATEKEEPER_CGROUP"

	// File descriptors in the gatekeeper (exec.Cmd ExtraFiles start at 3).
	FdRuntime = 3
	FdPidFile = 4
	FdSock    = 5
	FdRecords = 6 // optional

	GroupRuntime uint8 = 0
	GroupPidFile uint8 = 1

	FlagHasFd     uint8 = 1 << 0
	FlagRecordOK  uint8 = 1 << 1
	FlagHasRecord uint8 = 1 << 2

	// HeaderLen is the header of a gatekeeper→parent message, followed by
	// the eBPF record for runtime events:
	//   0  u32 seq
	//   4  u8  group
	//   5  u8  flags
	//   6  u16 reserved
	//   8  u64 mask
	//   16 i32 pid
	//   20 u32 reserved
	HeaderLen = 24
	// DoneLen is a parent→gatekeeper message: u32 seq of a processed event.
	DoneLen = 4

	// Pending permission events tracked. A slot reused before its event was
	// answered is allowed first (fail-open).
	slots = 4096
	// Socket send buffer, see Run.
	sndBuf = 8 << 20

	defaultBound = time.Second

	bpfMapLookupAndDeleteElem = 21
)

var metadataSize = int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))

// IsPermMask reports whether a fanotify event mask is a permission event.
func IsPermMask(mask uint64) bool {
	return mask&(unix.FAN_OPEN_PERM|unix.FAN_ACCESS_PERM|unix.FAN_OPEN_EXEC_PERM) != 0
}

type pendingEvent struct {
	active   bool
	group    uint8
	seq      uint32
	fd       int32
	deadline int64
}

type state struct {
	bounds     [2]int64 // per group, ns
	recordSize int
	sock       int
	records    int // -1 when there is no record queue

	seq     uint32
	pending [slots]pendingEvent
	nActive int

	// Preallocated I/O buffers: nothing is allocated per event.
	meta    [24]byte
	msg     []byte
	oob     []byte
	done    [DoneLen * 64]byte
	resp    [8]byte
	bpfAttr [32]byte
	pollFds [3]unix.PollFd

	// Counters, reported periodically on stderr.
	forwarded, answered, expired, dropped, evicted uint64
	lastReport                                     int64
	reported                                       [4]uint64
}

var monoBase = time.Now()

func now() int64 { return int64(time.Since(monoBase)) }

// closeInheritedFanotifyGroups closes fanotify group fds other than ours that
// leaked in from the parent (fds without O_CLOEXEC). Holding one would keep
// that group, and its permission marks, alive after the parent closed it to
// fail open, with nobody reading it. Only fanotify groups are touched: the Go
// runtime owns other fds (epoll, eventfd) here.
func closeInheritedFanotifyGroups() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= FdRecords {
			continue
		}
		if target, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && target == "anon_inode:[fanotify]" {
			unix.Close(fd)
		}
	}
}

// Limits of the gatekeeper cgroup. The gatekeeper itself needs ~2 MiB; the
// limits only bound a misbehaving one.
var cgroupLimits = []struct{ file, value string }{
	{"memory.max", strconv.Itoa(64 << 20)},
	{"pids.max", "32"},
	{"cpu.max", "50000 100000"},
}

// joinCgroup moves this process into its own cgroup v2 directory, out of the
// parent's cgroup. Answering an event charges kernel memory (the event's
// struct file) to the reader's memcg, so a gatekeeper left in the parent's
// memcg is throttled in mem_cgroup_handle_over_high exactly when the parent
// is, and stops answering. The parent usually runs in a private cgroup
// namespace, which forbids migrating outside it, so the move happens from a
// thread that first joins the host cgroup namespace (/proc/1 is the host
// init with hostPID). That thread is locked and discarded afterwards.
func joinCgroup(dir string) error {
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "cgroup.controllers")); err != nil {
		return fmt.Errorf("not a cgroup v2 hierarchy: %w", err)
	}
	errc := make(chan error, 1)
	go func() {
		// No UnlockOSThread: the runtime discards this thread, and its
		// cgroup namespace, when the goroutine exits.
		runtime.LockOSThread()
		self, err1 := os.Readlink("/proc/thread-self/ns/cgroup")
		host, err2 := os.Readlink("/proc/1/ns/cgroup")
		if err1 == nil && err2 == nil && self != host {
			fd, err := unix.Open("/proc/1/ns/cgroup", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				errc <- fmt.Errorf("opening host cgroup namespace: %w", err)
				return
			}
			err = unix.Setns(fd, unix.CLONE_NEWCGROUP)
			unix.Close(fd)
			if err != nil {
				errc <- fmt.Errorf("joining host cgroup namespace: %w", err)
				return
			}
		}
		if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
			errc <- fmt.Errorf("creating %s: %w", dir, err)
			return
		}
		for _, l := range cgroupLimits {
			// Best effort: a controller may not be enabled for this
			// subtree.
			if err := os.WriteFile(filepath.Join(dir, l.file), []byte(l.value), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "container-hook gatekeeper: setting %s: %s\n", l.file, err)
			}
		}
		// "0" is the writing process; cgroup.procs moves all its threads.
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("0"), 0o644); err != nil {
			errc <- fmt.Errorf("moving into %s: %w", dir, err)
			return
		}
		errc <- nil
	}()
	return <-errc
}

// Run is the gatekeeper process main loop. It returns the exit code.
func Run() int {
	// Keep this process small and independent of the parent's runtime
	// settings.
	runtime.GOMAXPROCS(1)

	var bounds [2]int64
	for group, env := range [2]string{BoundRuntimeEnv, BoundPidFileEnv} {
		b, err := strconv.ParseInt(os.Getenv(env), 10, 64)
		if err != nil || b <= 0 {
			b = int64(defaultBound)
		}
		bounds[group] = b
	}
	recordSize, err := strconv.Atoi(os.Getenv(RecordSizeEnv))
	if err != nil || recordSize < 0 {
		recordSize = 0
	}
	closeInheritedFanotifyGroups()

	if dir := os.Getenv(CgroupEnv); dir != "" {
		if err := joinCgroup(dir); err != nil {
			fmt.Fprintf(os.Stderr, "container-hook gatekeeper: staying in the parent's cgroup, so it can be throttled with it: %s\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "container-hook gatekeeper: running in cgroup %s\n", dir)
		}
	}

	s := &state{
		bounds:     bounds,
		sock:       FdSock,
		records:    -1,
		recordSize: recordSize,
		msg:        make([]byte, HeaderLen+recordSize),
		oob:        unix.UnixRights(0),
	}
	if _, err := unix.FcntlInt(FdRecords, unix.F_GETFD, 0); err == nil {
		s.records = FdRecords
	}
	// Room for bursts (each runtime event carries its ~5 KiB eBPF record):
	// with the default buffer a busy-but-healthy parent would hit the
	// "socket full → allow now" path during a deploy burst and miss
	// containers. FORCE needs CAP_NET_ADMIN; fall back to the capped size.
	if err := unix.SetsockoptInt(FdSock, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sndBuf); err != nil {
		_ = unix.SetsockoptInt(FdSock, unix.SOL_SOCKET, unix.SO_SNDBUF, sndBuf)
	}
	binary.LittleEndian.PutUint32(s.resp[4:], unix.FAN_ALLOW)
	// The record buffer and the attr live as long as the process.
	binary.LittleEndian.PutUint32(s.bpfAttr[0:], uint32(s.records))
	if s.recordSize > 0 {
		binary.LittleEndian.PutUint64(s.bpfAttr[16:], uint64(uintptr(unsafe.Pointer(&s.msg[HeaderLen]))))
	} else {
		s.records = -1
	}

	s.pollFds[0] = unix.PollFd{Fd: FdRuntime, Events: unix.POLLIN}
	s.pollFds[1] = unix.PollFd{Fd: FdPidFile, Events: unix.POLLIN}
	s.pollFds[2] = unix.PollFd{Fd: FdSock, Events: unix.POLLIN}

	fmt.Fprintf(os.Stderr, "container-hook gatekeeper: started (pid %d, bounds: runtime-binary %s, pid-file %s)\n",
		os.Getpid(), time.Duration(bounds[GroupRuntime]), time.Duration(bounds[GroupPidFile]))
	s.loop()
	s.allowAll()
	s.report(true)
	runtime.KeepAlive(s)
	return 0
}

func (s *state) loop() {
	for {
		timeout := -1
		if s.nActive > 0 {
			timeout = int(time.Duration(s.nextDeadline()-now()) / time.Millisecond)
			if timeout < 0 {
				timeout = 0
			}
			timeout++ // round up, so we wake after the deadline
		}
		for i := range s.pollFds {
			s.pollFds[i].Revents = 0
		}
		if _, err := unix.Poll(s.pollFds[:], timeout); err != nil && err != unix.EINTR {
			fmt.Fprintf(os.Stderr, "container-hook gatekeeper: poll: %s\n", err)
			return
		}
		// Parent gone or socket closed: answer everything and exit. Our
		// fanotify fds close with us; once the parent's copies are closed
		// too, the kernel drops the marks.
		if s.pollFds[2].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
			return
		}
		if s.pollFds[2].Revents&unix.POLLIN != 0 {
			if !s.recvDone() {
				return
			}
		}
		if s.pollFds[0].Revents&unix.POLLIN != 0 {
			s.readEvent(FdRuntime, GroupRuntime)
		}
		if s.pollFds[1].Revents&unix.POLLIN != 0 {
			s.readEvent(FdPidFile, GroupPidFile)
		}
		if s.pollFds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 &&
			s.pollFds[1].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return
		}
		s.expire(now())
		s.report(false)
	}
}

func (s *state) nextDeadline() int64 {
	next := int64(1<<63 - 1)
	for i := range s.pending {
		if s.pending[i].active && s.pending[i].deadline < next {
			next = s.pending[i].deadline
		}
	}
	return next
}

// release answers FAN_ALLOW for a pending event on the group it came from and
// closes our copy of its fd. The fd stays open until then so its number
// cannot be reused by another pending event of the same group.
func (s *state) release(slot *pendingEvent) {
	groupFd := FdRuntime
	if slot.group == GroupPidFile {
		groupFd = FdPidFile
	}
	binary.LittleEndian.PutUint32(s.resp[0:], uint32(slot.fd))
	// ENOENT: the waiting process went away; nothing to answer.
	_, _ = unix.Write(groupFd, s.resp[:])
	unix.Close(int(slot.fd))
	slot.active = false
	s.nActive--
}

func (s *state) readEvent(fd int, group uint8) {
	n, err := unix.Read(fd, s.meta[:])
	if err != nil || n < metadataSize {
		return
	}
	mask := binary.LittleEndian.Uint64(s.meta[8:16])
	efd := int32(binary.LittleEndian.Uint32(s.meta[16:20]))
	pid := int32(binary.LittleEndian.Uint32(s.meta[20:24]))

	flags := uint8(0)
	msgLen := HeaderLen
	if group == GroupRuntime {
		// The eBPF program pushed exactly one record when this event was
		// dequeued; take it now to stay in lockstep with ig_fa_records.
		flags |= FlagHasRecord
		msgLen += s.recordSize
		if s.records >= 0 && s.lookupAndDeleteRecord() {
			flags |= FlagRecordOK
		}
	}

	s.seq++
	seq := s.seq
	perm := efd >= 0 && IsPermMask(mask)
	if perm {
		idx := int(seq % slots)
		slot := &s.pending[idx]
		if slot.active {
			// Wrapped around a still-pending event: allow it first.
			s.release(slot)
			s.evicted++
		}
		*slot = pendingEvent{active: true, group: group, seq: seq, fd: efd, deadline: now() + s.bounds[group]}
		s.nActive++
	}

	binary.LittleEndian.PutUint32(s.msg[0:], seq)
	s.msg[4] = group
	if efd >= 0 {
		flags |= FlagHasFd
	}
	s.msg[5] = flags
	binary.LittleEndian.PutUint64(s.msg[8:], mask)
	binary.LittleEndian.PutUint32(s.msg[16:], uint32(pid))

	var oob []byte
	if efd >= 0 {
		// Patch the fd into the preallocated SCM_RIGHTS message.
		binary.LittleEndian.PutUint32(s.oob[unix.CmsgLen(0):], uint32(efd))
		oob = s.oob
	}
	// Never block on the parent: if it is not draining the socket, fail open.
	err = unix.Sendmsg(s.sock, s.msg[:msgLen], oob, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
	if err != nil {
		s.dropped++
		if perm {
			idx := int(seq % slots)
			s.release(&s.pending[idx])
		} else if efd >= 0 {
			unix.Close(int(efd))
		}
		return
	}
	s.forwarded++
	if !perm && efd >= 0 {
		// The parent got its own copy; ours is not needed for a response.
		unix.Close(int(efd))
	}
}

func (s *state) lookupAndDeleteRecord() bool {
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfMapLookupAndDeleteElem,
		uintptr(unsafe.Pointer(&s.bpfAttr[0])), uintptr(len(s.bpfAttr)))
	return errno == 0
}

// recvDone drains "done" replies. It returns false when the parent is gone.
func (s *state) recvDone() bool {
	for {
		n, _, _, _, err := unix.Recvmsg(s.sock, s.done[:], nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN || err == unix.EINTR {
			return true
		}
		if err != nil || n == 0 {
			return false
		}
		for off := 0; off+DoneLen <= n; off += DoneLen {
			seq := binary.LittleEndian.Uint32(s.done[off:])
			idx := int(seq % slots)
			slot := &s.pending[idx]
			if slot.active && slot.seq == seq {
				s.release(slot)
				s.answered++
			}
		}
	}
}

func (s *state) expire(now int64) {
	if s.nActive == 0 {
		return
	}
	for i := range s.pending {
		if s.pending[i].active && s.pending[i].deadline <= now {
			s.release(&s.pending[i])
			s.expired++
		}
	}
}

func (s *state) allowAll() {
	for i := range s.pending {
		if s.pending[i].active {
			s.release(&s.pending[i])
			s.expired++
		}
	}
}

// report prints counters when the fail-open ones changed, at most every 10s.
func (s *state) report(force bool) {
	now := now()
	if !force && time.Duration(now-s.lastReport) < 10*time.Second {
		return
	}
	cur := [4]uint64{s.expired, s.dropped, s.evicted, s.forwarded}
	if !force && cur[0] == s.reported[0] && cur[1] == s.reported[1] && cur[2] == s.reported[2] {
		return
	}
	s.lastReport = now
	fmt.Fprintf(os.Stderr, "container-hook gatekeeper: fail-open: expired=%d dropped=%d evicted=%d (forwarded=%d answered=%d)\n",
		s.expired-s.reported[0], s.dropped-s.reported[1], s.evicted-s.reported[2], s.forwarded, s.answered)
	s.reported = cur
}
