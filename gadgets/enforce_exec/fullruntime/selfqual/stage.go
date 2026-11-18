// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package selfqual

import (
	"bufio"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

//go:embed helper/probe-amd64
var helperBinary []byte

// HelperSHA256 is the pinned digest of the embedded probe helper.
func HelperSHA256() string { return helperSHA256 }

// sealedHelper verifies the embedded helper against its pinned digest and
// returns it as a sealed memfd: after this point nobody, the agent included,
// can change the bytes that will run.
func sealedHelper(image []byte) (*os.File, error) {
	sum := sha256.Sum256(image)
	if got := hex.EncodeToString(sum[:]); got != helperSHA256 {
		return nil, fmt.Errorf("probe helper sha256 %s, pinned %s", got, helperSHA256)
	}
	fd, err := unix.MemfdCreate("ee-selfqual-probe", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("probe helper memfd: %w", err)
	}
	f := os.NewFile(uintptr(fd), "ee-selfqual-probe")
	if _, err := f.Write(image); err != nil {
		f.Close()
		return nil, fmt.Errorf("probe helper write: %w", err)
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); err != nil {
		f.Close()
		return nil, fmt.Errorf("probe helper seal: %w", err)
	}
	return f, nil
}

// stage is the running probe stage: the helper in its private mount
// namespace, with the fixtures built.
type stage struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	pid    int
	dir    string // fixture directory inside the stage's mount namespace
	files  map[string]FileID
	binfmt bool
	memfd  *os.File
}

type tokenResult struct {
	Token string
	Code  int
	PID   uint32
}

type stormLine struct {
	Worker int
	File   string
	PID    uint32
	Code   int
}

type stageOutput struct {
	Results []tokenResult
	Ran     map[uint32]bool // pids whose exec target image ran ("T" lines)
	Storm   []stormLine
	Done    int
}

func startStage(image []byte) (*stage, error) {
	memfd, err := sealedHelper(image)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(fmt.Sprintf("/proc/self/fd/%d", memfd.Fd()), "ee-selfqual-stage")
	cmd.Env = []string{"PATH=/nonexistent"}
	cmd.Stderr = os.Stderr
	// A private mount namespace: the fixtures live on a tmpfs nobody else can
	// see, and joining the namespace needs CAP_SYS_ADMIN over it (host root).
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		memfd.Close()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		memfd.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		memfd.Close()
		return nil, fmt.Errorf("start probe stage: %w", err)
	}
	st := &stage{cmd: cmd, stdin: stdin, lines: make(chan string, 65536), pid: cmd.Process.Pid, files: map[string]FileID{}, memfd: memfd}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 65536), 1<<20)
		for sc.Scan() {
			st.lines <- sc.Text()
		}
		close(st.lines)
	}()
	deadline := time.After(20 * time.Second)
	for {
		var line string
		var ok bool
		select {
		case line, ok = <-st.lines:
		case <-deadline:
			st.kill()
			return nil, errors.New("probe stage: timeout building fixtures")
		}
		if !ok {
			st.kill()
			return nil, errors.New("probe stage exited while building fixtures")
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 5 && f[0] == "FILE":
			major, e1 := strconv.ParseUint(f[2], 10, 32)
			minor, e2 := strconv.ParseUint(f[3], 10, 32)
			ino, e3 := strconv.ParseUint(f[4], 10, 64)
			if e1 != nil || e2 != nil || e3 != nil {
				st.kill()
				return nil, fmt.Errorf("probe stage: bad manifest line %q", line)
			}
			st.files[f[1]] = FileID{Dev: major<<20 | minor, Ino: ino}
		case len(f) >= 2 && f[0] == "BINFMT":
			st.binfmt = f[1] == "1"
		case len(f) == 2 && f[0] == "READY":
			st.dir = f[1]
			if err := st.verifyFixtures(); err != nil {
				st.kill()
				return nil, err
			}
			return st, nil
		default:
			st.kill()
			return nil, fmt.Errorf("probe stage: %s", line)
		}
	}
}

// hostPath is a fixture's path as the agent reaches it: through the stage's
// root, since the tmpfs exists only in the stage's mount namespace.
func (st *stage) hostPath(name string) string {
	return filepath.Join("/proc", strconv.Itoa(st.pid), "root", st.dir, name)
}

// verifyFixtures re-derives every fixture identity from the agent's side: the
// helper's manifest is a claim, the stat through /proc/<pid>/root is the
// agent's own read.
func (st *stage) verifyFixtures() error {
	if len(st.files) == 0 {
		return errors.New("probe stage: empty manifest")
	}
	for name, id := range st.files {
		var s unix.Stat_t
		if err := unix.Stat(st.hostPath(name), &s); err != nil {
			return fmt.Errorf("probe fixture %s: %w", name, err)
		}
		got := FileID{Dev: uint64(unix.Major(s.Dev))<<20 | uint64(unix.Minor(s.Dev)), Ino: s.Ino}
		if got != id {
			return fmt.Errorf("probe fixture %s: stage says %+v, agent sees %+v", name, id, got)
		}
	}
	return nil
}

func (st *stage) readLine(timeout time.Duration) (string, error) {
	select {
	case line, ok := <-st.lines:
		if !ok {
			return "", errors.New("probe stage exited")
		}
		return line, nil
	case <-time.After(timeout):
		return "", errors.New("probe stage: timeout")
	}
}

// spawn forks a probe root, moved into cgroupDir ("-": left where the stage
// is), and returns its pid. The root does nothing until release.
func (st *stage) spawn(cgroupDir string, tokens []string) (uint32, error) {
	for _, t := range tokens {
		if strings.ContainsAny(t, " \n") {
			return 0, fmt.Errorf("bad token %q", t)
		}
	}
	if _, err := fmt.Fprintf(st.stdin, "SPAWN %s %s\n", cgroupDir, strings.Join(tokens, " ")); err != nil {
		return 0, err
	}
	line, err := st.readLine(10 * time.Second)
	if err != nil {
		return 0, err
	}
	f := strings.Fields(line)
	if len(f) != 2 || f[0] != "PID" {
		return 0, fmt.Errorf("probe stage: %s", line)
	}
	pid, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("probe stage: %s", line)
	}
	return uint32(pid), nil
}

func (st *stage) release() error {
	_, err := io.WriteString(st.stdin, "GO\n")
	return err
}

// collect reads the probe root's output up to its DONE line.
func (st *stage) collect(timeout time.Duration) (stageOutput, error) {
	out := stageOutput{Ran: map[uint32]bool{}}
	deadline := time.Now().Add(timeout)
	for {
		line, err := st.readLine(time.Until(deadline))
		if err != nil {
			return out, err
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 4 && f[0] == "R":
			code, e1 := strconv.Atoi(f[2])
			pid, e2 := strconv.ParseUint(f[3], 10, 32)
			if e1 != nil || e2 != nil {
				return out, fmt.Errorf("probe stage: %s", line)
			}
			out.Results = append(out.Results, tokenResult{Token: f[1], Code: code, PID: uint32(pid)})
		case len(f) == 2 && f[0] == "T":
			pid, err := strconv.ParseUint(f[1], 10, 32)
			if err != nil {
				return out, fmt.Errorf("probe stage: %s", line)
			}
			out.Ran[uint32(pid)] = true
		case len(f) == 5 && f[0] == "S":
			w, e1 := strconv.Atoi(f[1])
			pid, e2 := strconv.ParseUint(f[3], 10, 32)
			code, e3 := strconv.Atoi(f[4])
			if e1 != nil || e2 != nil || e3 != nil {
				return out, fmt.Errorf("probe stage: %s", line)
			}
			out.Storm = append(out.Storm, stormLine{Worker: w, File: f[2], PID: uint32(pid), Code: code})
		case len(f) == 2 && f[0] == "DONE":
			out.Done, err = strconv.Atoi(f[1])
			if err != nil {
				return out, fmt.Errorf("probe stage: %s", line)
			}
			return out, nil
		default:
			return out, fmt.Errorf("probe stage: %s", line)
		}
	}
}

func (st *stage) kill() {
	st.cmd.Process.Kill()
	st.cmd.Wait()
	st.memfd.Close()
}

// stop asks the stage to clean up (its binfmt_misc entry) and exit.
func (st *stage) stop() error {
	io.WriteString(st.stdin, "QUIT\n")
	st.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- st.cmd.Wait() }()
	select {
	case err := <-done:
		st.memfd.Close()
		return err
	case <-time.After(5 * time.Second):
		st.kill()
		return errors.New("probe stage did not exit")
	}
}

// TamperedHelperForTest returns the embedded helper with one byte flipped.
// Negative controls only: Run must refuse it before anything executes.
func TamperedHelperForTest() []byte {
	b := append([]byte(nil), helperBinary...)
	b[len(b)/2] ^= 1
	return b
}
