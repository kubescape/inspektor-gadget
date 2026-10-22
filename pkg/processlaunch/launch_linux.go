// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

// Package processlaunch holds a host-owned process before its first application
// exec so a gadget can bind it without stopping an existing application's threads.
package processlaunch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Identity identifies the bootstrap and, after Release, the application.
type Identity struct {
	Node           string
	BootID         string
	PID            uint32
	StartTimeTicks uint64
}

// Options configure the application's standard streams and environment.
// A nil Env inherits the host environment. Environment names must be valid
// POSIX shell identifiers; values travel in a sealed private memfd and are installed only after
// release, so loader and shell startup variables cannot bypass the bootstrap.
type Options struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Env    []string
	Dir    string
}

// Child owns a bootstrap, its pidfd, and the private release pipe.
// Call Close on every path to release resources and reap the child.
type Child struct {
	mu        sync.Mutex
	ctx       context.Context
	cmd       *exec.Cmd
	identity  Identity
	pidfd     int
	gate      *os.File
	attempted bool
	bound     bool
	released  bool
	exited    bool
	waitErr   error
	done      chan struct{}
}

type contextKey struct{}

// Start starts a trusted, single-threaded shell bootstrap and waits for its
// readiness handshake. Arguments are passed positionally, never as shell code.
// The bootstrap execs the application in the same process only after Release.
// Command lookup uses the host PATH, as exec.Command does; Options.Env sets the
// application environment and does not change executable lookup.
// After process exit, standard-stream pipes have one second to drain before
// Wait returns exec.ErrWaitDelay. Custom readers/writers must not block forever
// inside Read/Write; the launcher cannot cancel arbitrary user I/O methods.
func Start(ctx context.Context, argv []string, opts Options) (*Child, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("missing application command")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	executable, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, fmt.Errorf("resolving application executable: %w", err)
	}
	if !strings.HasPrefix(executable, "/") {
		return nil, errors.New("launcher requires an absolute executable path")
	}
	environment := opts.Env
	if environment == nil {
		environment = os.Environ()
	}
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || !validEnvironmentName(name) || strings.IndexByte(entry, 0) >= 0 {
			return nil, fmt.Errorf("invalid launcher environment name %q", name)
		}
	}
	envFile, err := environmentFile(environment)
	if err != nil {
		return nil, fmt.Errorf("preparing application environment: %w", err)
	}
	defer envFile.Close()
	gateR, gateW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer gateR.Close()
	readyR, readyW, err := os.Pipe()
	if err != nil {
		gateW.Close()
		return nil, err
	}
	defer readyR.Close()
	defer readyW.Close()
	const bootstrap = `printf R >&4 || exit 125
exec 4>&-
IFS= read -r token <&3 || exit 125
[ "$token" = GO ] || exit 125
exec 3<&-
. /proc/self/fd/5 || exit 125
exec 5<&-
exec "$@"`
	args := []string{"-c", bootstrap, "ig-process-launch"}
	args = append(args, executable)
	args = append(args, argv[1:]...)
	cmd := exec.CommandContext(ctx, "/bin/sh", args...)
	cmd.WaitDelay = time.Second
	cmd.Stdin, cmd.Stdout, cmd.Stderr = opts.Stdin, opts.Stdout, opts.Stderr
	// Do not let application LD_PRELOAD, ENV, etc. execute during bootstrap.
	cmd.Env, cmd.Dir = []string{}, opts.Dir
	cmd.ExtraFiles = []*os.File{gateR, readyW, envFile}
	if err := cmd.Start(); err != nil {
		gateW.Close()
		return nil, fmt.Errorf("starting process bootstrap: %w", err)
	}
	// The parent must not retain the child's ends: EOF must work on failures.
	gateR.Close()
	readyW.Close()
	c := &Child{ctx: ctx, cmd: cmd, gate: gateW, pidfd: -1, done: make(chan struct{})}
	c.pidfd, err = unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		gateW.Close()
		return nil, fmt.Errorf("opening bootstrap pidfd: %w", err)
	}
	go c.reap()
	fail := func(err error) (*Child, error) { c.Close(); return nil, err }
	var ready [1]byte
	if _, err := io.ReadFull(readyR, ready[:]); err != nil {
		return fail(fmt.Errorf("waiting for bootstrap: %w", err))
	}
	if ready[0] != 'R' {
		return fail(errors.New("invalid bootstrap readiness"))
	}
	node := os.Getenv("NODE_NAME")
	if node == "" {
		node, err = os.Hostname()
		if err != nil {
			return fail(err)
		}
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fail(err)
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", cmd.Process.Pid))
	if err != nil {
		return fail(err)
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return fail(errors.New("invalid bootstrap process stat"))
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) <= 19 {
		return fail(errors.New("incomplete bootstrap process stat"))
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return fail(err)
	}
	c.identity = Identity{Node: node, BootID: strings.TrimSpace(string(boot)), PID: uint32(cmd.Process.Pid), StartTimeTicks: ticks}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return c, nil
}

func (c *Child) reap() {
	err := c.cmd.Wait()
	c.mu.Lock()
	c.exited, c.waitErr = true, err
	unix.Close(c.pidfd)
	c.pidfd = -1
	c.gate.Close()
	c.mu.Unlock()
	close(c.done)
}

// Identity returns the exact process identity for the gadget policy.
func (c *Child) Identity() Identity { return c.identity }

// Context grants the runtime permission to bind this particular waiting child.
// Policy input alone cannot manufacture this capability.
func (c *Child) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKey{}, c)
}

// Bind invokes install with the owned pidfd while the bootstrap is waiting.
// matched is false only when ctx contains no launch capability. A mismatch or
// failed attempt must not fall back to attaching to an arbitrary process.
// install must not close or retain the borrowed pidfd.
func Bind(ctx context.Context, identity Identity, install func(int) error) (matched bool, err error) {
	c, ok := ctx.Value(contextKey{}).(*Child)
	if !ok {
		return false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return true, err
	}
	if err := c.ctx.Err(); err != nil {
		return true, err
	}
	if c.identity != identity {
		return true, errors.New("launcher process identity mismatch")
	}
	if c.exited || c.released || c.attempted {
		return true, errors.New("launcher binding is no longer available")
	}
	c.attempted = true
	if install == nil {
		return true, errors.New("missing process binding callback")
	}
	if err := install(c.pidfd); err != nil {
		return true, err
	}
	c.bound = true
	return true, nil
}

// Release permits the first application exec after binding and runtime startup.
// The caller must wait for the gadget's startup acknowledgement before calling.
func (c *Child) Release() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if c.exited || c.released {
		return errors.New("launcher is no longer waiting")
	}
	if !c.bound {
		return errors.New("launcher process has not been bound")
	}
	if _, err := io.WriteString(c.gate, "GO\n"); err != nil {
		return fmt.Errorf("releasing process: %w", err)
	}
	c.released = true
	return c.gate.Close()
}

// Wait waits for the application (or failed bootstrap) and returns its exit error.
func (c *Child) Wait() error { <-c.done; return c.waitErr }

// Close kills a remaining child and waits until it has been reaped. It is safe
// to call more than once. Application exit status is available through Wait.
func (c *Child) Close() error {
	c.mu.Lock()
	c.gate.Close()
	if !c.exited {
		_ = c.cmd.Process.Kill()
	}
	c.mu.Unlock()
	<-c.done
	return nil
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

// environmentFile keeps environment secrets out of the bootstrap command line.
// Shell quoting preserves literal values; sealing prevents either process from
// changing the script after validation and before the bootstrap sources it.
func environmentFile(environment []string) (*os.File, error) {
	fd, err := unix.MemfdCreate("ig-process-environment", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "ig-process-environment")
	fail := func(err error) (*os.File, error) { file.Close(); return nil, err }
	if err := file.Chmod(0o600); err != nil {
		return fail(err)
	}
	for _, entry := range environment {
		quoted := strings.ReplaceAll(entry, "'", "'\\''")
		if _, err := io.WriteString(file, "export '"+quoted+"' || exit 125\n"); err != nil {
			return fail(err)
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return fail(err)
	}
	return file, nil
}
