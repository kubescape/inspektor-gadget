// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package selfqual

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// holder parks an exec deterministically between two binfmt passes: a
// fanotify FAN_OPEN_EXEC_PERM mark on a script's interpreter blocks the exec
// after the script's decision and before the interpreter's.
type holder struct {
	fd   int
	stop chan struct{}
	done chan struct{}
}

type heldExec struct {
	fd  int32
	PID uint32
}

func newHolder(path string) (*holder, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("fanotify_mark %s: %w", path, err)
	}
	return &holder{fd: fd}, nil
}

// wait returns the next exec parked on the mark.
func (h *holder) wait(timeout time.Duration) (heldExec, error) {
	pfd := []unix.PollFd{{Fd: int32(h.fd), Events: unix.POLLIN}}
	deadline := time.Now().Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return heldExec{}, errors.New("no exec reached the hold point")
		}
		n, err := unix.Poll(pfd, int(left.Milliseconds())+1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return heldExec{}, err
		}
		if n == 0 {
			continue
		}
		break
	}
	// struct fanotify_event_metadata: one event per read.
	buf := make([]byte, 24)
	n, err := unix.Read(h.fd, buf)
	if err != nil || n != 24 {
		return heldExec{}, fmt.Errorf("fanotify read: n=%d: %v", n, err)
	}
	mask := binary.LittleEndian.Uint64(buf[8:16])
	fd := int32(binary.LittleEndian.Uint32(buf[16:20]))
	pid := binary.LittleEndian.Uint32(buf[20:24])
	if mask&unix.FAN_OPEN_EXEC_PERM == 0 {
		if fd >= 0 {
			unix.Close(int(fd))
		}
		return heldExec{}, fmt.Errorf("fanotify event mask %#x", mask)
	}
	return heldExec{fd: fd, PID: pid}, nil
}

// allow lets a parked exec continue.
func (h *holder) allow(e heldExec) error {
	resp := make([]byte, 8)
	binary.LittleEndian.PutUint32(resp[0:4], uint32(e.fd))
	binary.LittleEndian.PutUint32(resp[4:8], unix.FAN_ALLOW)
	_, err := unix.Write(h.fd, resp)
	unix.Close(int(e.fd))
	return err
}

// passThrough lets every later exec parked on the mark continue, until close.
func (h *holder) passThrough() {
	if h.stop != nil {
		return
	}
	h.stop, h.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(h.done)
		for {
			select {
			case <-h.stop:
				return
			default:
			}
			if next, err := h.wait(20 * time.Millisecond); err == nil {
				h.allow(next)
			}
		}
	}()
}

func (h *holder) close() {
	if h.stop != nil {
		close(h.stop)
		<-h.done
	}
	unix.Close(h.fd)
}

// killParked kills a parked exec and waits until the task is dead (a zombie
// or gone). Only then may the hold be answered: an answer racing the signal
// could let the exec run on to its next pass.
func killParked(pid uint32, timeout time.Duration) error {
	if err := unix.Kill(int(pid), unix.SIGKILL); err != nil {
		return fmt.Errorf("kill parked exec %d: %w", pid, err)
	}
	deadline := time.Now().Add(timeout)
	for {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return nil
		}
		// "<pid> (<comm>) <state> ...": the state follows the last ')'.
		if i := strings.LastIndexByte(string(b), ')'); i >= 0 && i+2 < len(b) && (b[i+2] == 'Z' || b[i+2] == 'X') {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("parked exec %d did not die", pid)
		}
		time.Sleep(time.Millisecond)
	}
}
