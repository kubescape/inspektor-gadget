// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	fence "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
)

// Keep the owner main goroutine on the group leader; thread-selfexec must
// originate on a different task and exercise de_thread explicitly.
func init() { runtime.LockOSThread() }

type memberCommand struct {
	Path     string `json:"path"`
	Identity uint64 `json:"identity"`
	Mode     uint32 `json:"mode"`
}

type command struct {
	Op        string          `json:"op"`
	Pod       uint64          `json:"pod"`
	Child     uint64          `json:"child"`
	Mode      uint32          `json:"mode"`
	Hash      uint64          `json:"hash"`
	Inc       uint64          `json:"inc"`
	Path      string          `json:"path"`
	ChildPath string          `json:"child_path"`
	Identity  uint64          `json:"identity"`
	Revision  uint64          `json:"revision"`
	Members   []memberCommand `json:"members"`
}
type reply struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Inc   uint64          `json:"incarnation,omitempty"`
	Live  uint64          `json:"live_incarnation"`
	State any             `json:"state,omitempty"`
	Pod   *fence.PodState `json:"pod,omitempty"`
}
type backendEntry struct {
	Inode uint64
	Mode  uint32
	Pad   uint32
}
type selectiveBackend struct {
	coll  *ebpf.Collection
	link  link.Link
	id    link.ID
	inode uint64
}

func openBackend(path string, inode uint64) (*selectiveBackend, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["backend_check"]})
	if err != nil {
		coll.Close()
		return nil, err
	}
	info, err := l.Info()
	if err != nil {
		l.Close()
		coll.Close()
		return nil, err
	}
	return &selectiveBackend{coll, l, info.ID, inode}, nil
}

func (b *selectiveBackend) protect(child uint64, mode uint32) error {
	want := backendEntry{Inode: b.inode, Mode: mode}
	if err := b.coll.Maps["backend_bind"].Put(child, want); err != nil {
		return err
	}
	var got backendEntry
	if err := b.coll.Maps["backend_bind"].Lookup(child, &got); err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("selective backend readback mismatch")
	}
	li, err := b.link.Info()
	if err != nil {
		return err
	}
	pi, err := b.coll.Programs["backend_check"].Info()
	if err != nil {
		return err
	}
	pid, ok := pi.ID()
	if !ok || li.ID != b.id || li.Program != pid {
		return fmt.Errorf("selective backend link attestation mismatch")
	}
	return nil
}

func (b *selectiveBackend) close() error {
	if b == nil || b.coll == nil {
		return nil
	}
	err := b.link.Close()
	b.coll.Close()
	b.coll = nil
	return err
}

func fixtureMode(mode uint32) (fence.Mode, error) {
	switch mode {
	case 1:
		return fence.Audit, nil
	case 2:
		return fence.Strict, nil
	case 3:
		return fence.Off, nil
	default:
		return 0, fmt.Errorf("unknown fixture mode %d", mode)
	}
}

func publishCensus(f *fence.Fence, c command, revision uint64) (fence.PodRef, error) {
	mode, err := fixtureMode(c.Mode)
	if err != nil {
		return fence.PodRef{}, err
	}
	podDir, err := os.Open(c.Path)
	if err != nil {
		return fence.PodRef{}, err
	}
	defer podDir.Close()
	members := c.Members
	if len(members) == 0 && c.ChildPath != "" {
		members = []memberCommand{{Path: c.ChildPath, Identity: c.Identity, Mode: c.Mode}}
	}
	var opened []*os.File
	defer func() {
		for _, fd := range opened {
			fd.Close()
		}
	}()
	var rows []fence.PodMember
	for _, m := range members {
		fd, e := os.Open(m.Path)
		if e != nil {
			return fence.PodRef{}, e
		}
		opened = append(opened, fd)
		class, e := fixtureMode(m.Mode)
		if e != nil {
			return fence.PodRef{}, e
		}
		rows = append(rows, fence.PodMember{Cgroup: fd, Identity: m.Identity, Mode: class})
	}
	return f.PublishCensus(podDir, c.Hash, revision, mode, rows)
}

func runOwner(root, object, backend string, inode uint64, mutant string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	raw, err := os.ReadFile(object)
	if err != nil {
		return err
	}
	f, err := fence.Open(root, raw)
	if err != nil {
		return err
	}
	defer f.Close()
	inc, err := f.Register()
	if err != nil {
		return err
	}
	b, err := openBackend(backend, inode)
	if err != nil {
		return err
	}
	defer b.close()
	out := json.NewEncoder(os.Stdout)
	if err := out.Encode(reply{OK: true, Inc: inc}); err != nil {
		return err
	}
	refs := make(map[uint64]fence.PodRef)
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var c command
		if err := json.Unmarshal(in.Bytes(), &c); err != nil {
			return err
		}
		r := reply{OK: true, Inc: inc}
		var opErr error
		switch c.Op {
		case "bind", "census":
			ref, exists := refs[c.Pod]
			if !exists {
				state, found, e := f.ReadPod(c.Pod)
				if e != nil {
					opErr = e
					break
				}
				if found {
					ref = state.PodRef
				}
			}
			revision := ref.Revision
			if c.Revision != 0 {
				revision = c.Revision
			}
			next, e := publishCensus(f, c, revision)
			opErr = e
			if e == nil {
				refs[c.Pod] = next
			}
		case "readpod":
			state, found, e := f.ReadPod(c.Pod)
			opErr = e
			if e == nil && !found {
				opErr = fmt.Errorf("pod absent")
			}
			if opErr == nil {
				r.Pod = &state
			}
		case "protect", "refence", "commit-withdrawal", "deactivate", "remove":
			ref, found := refs[c.Pod]
			if !found {
				state, exists, e := f.ReadPod(c.Pod)
				if e != nil {
					opErr = e
					break
				}
				if !exists {
					opErr = fmt.Errorf("pod absent")
					break
				}
				ref = state.PodRef
				refs[c.Pod] = ref
			}
			if c.Revision != 0 {
				ref.Revision = c.Revision
			}
			identity := c.Identity
			if identity == 0 {
				identity = c.Child
			}
			child := fence.ChildRef{ID: c.Child, Identity: identity}
			var next fence.PodRef
			switch c.Op {
			case "protect":
				opErr = b.protect(c.Child, c.Mode)
				if opErr == nil && mutant != "never-move" {
					next, opErr = f.MoveChild(ref, child, 1)
				}
			case "refence":
				next, opErr = f.RefenceChild(ref, child)
			case "commit-withdrawal":
				next, opErr = f.CommitPolicyWithdrawal(ref, child)
			case "deactivate":
				next, opErr = f.DeactivateExecScope(ref)
			case "remove":
				opErr = f.RemoveExited(ref)
			}
			if opErr == nil && next.ID != 0 {
				refs[c.Pod] = next
			}
		case "backend-withdraw":
			opErr = b.coll.Maps["backend_bind"].Delete(c.Child)
			if errors.Is(opErr, ebpf.ErrKeyNotExist) {
				opErr = nil
			}
		case "arm":
			opErr = f.Arm()
		case "withdraw":
			opErr = b.close()
		case "snapshot":
			state, e := f.Snapshot()
			opErr = e
			if e == nil {
				r.Live = state.LiveIncarnation
				r.State = state
			}
		case "stop":
			if mutant == "restart-lift" {
				opErr = fence.Lift(root, raw)
			} else {
				opErr = f.Arm()
			}
			if opErr == nil {
				opErr = b.close()
			}
		case "selfexec":
			runtime.LockOSThread()
			opErr = unix.Exec("/proc/self/exe", []string{"fence-oracle", "postexec"}, os.Environ())
			runtime.UnlockOSThread()
		case "thread-selfexec":
			done := make(chan error, 1)
			go func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				if unix.Gettid() == os.Getpid() {
					done <- fmt.Errorf("thread exec not on a nonleader")
					return
				}
				done <- unix.Exec("/proc/self/exe", []string{"fence-oracle", "postexec"}, os.Environ())
			}()
			opErr = <-done
		case "badexec":
			runtime.LockOSThread()
			opErr = unix.Exec(c.Path, []string{c.Path}, os.Environ())
			runtime.UnlockOSThread()
			// Failure is the stimulus; only genuine exec failure is accepted.
			if errors.Is(opErr, unix.ENOEXEC) || errors.Is(opErr, unix.ENOENT) {
				opErr = nil
			} else {
				opErr = fmt.Errorf("unexpected failed-exec result: %w", opErr)
			}
		case "reregister-refused":
			if _, e := f.Register(); e == nil {
				opErr = fmt.Errorf("armed same handle registered again")
				break
			}
			other, e := fence.Open(root, raw)
			if e != nil {
				opErr = e
				break
			}
			_, e = other.Register()
			closeErr := other.Close()
			if e == nil {
				opErr = fmt.Errorf("armed same process registered with a fresh handle")
			} else {
				opErr = closeErr
			}
		case "exit":
			return out.Encode(reply{OK: true, Inc: inc})
		default:
			opErr = fmt.Errorf("unknown owner operation %q", c.Op)
		}
		if opErr != nil {
			r.OK = false
			r.Error = opErr.Error()
		}
		if err := out.Encode(r); err != nil {
			return err
		}
	}
	return in.Err()
}

func runSpoof(inc uint64) error {
	_, _, err := unix.Syscall6(unix.SYS_PRCTL, 0x4b554246, 0x1234, 0x5678, uintptr(inc), 0, 0)
	// Original prctl returns EINVAL if no hook consumes it; do not infer trust
	// from its return value. Parent examines pinned state while we remain alive.
	if err != 0 && err != syscall.EINVAL && err != syscall.EPERM {
		return err
	}
	if e := json.NewEncoder(os.Stdout).Encode(reply{OK: true}); e != nil {
		return e
	}
	_, e := bufio.NewReader(os.Stdin).ReadByte()
	return e
}

func postExec() error {
	// No fence/library call: CLOEXEC descriptors are gone. Remain alive so the
	// controller distinguishes exec arming from a later process-exit arm.
	if err := json.NewEncoder(os.Stdout).Encode(reply{OK: true}); err != nil {
		return err
	}
	_, err := bufio.NewReader(os.Stdin).ReadByte()
	return err
}
