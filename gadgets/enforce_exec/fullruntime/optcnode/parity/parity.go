// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package parity is the G004 verdict-parity scenario table: the same
// fullpolicy policies and the same shell steps, run once through the
// product shared node (fullruntime, test file g004_optc_parity_attached_test.go)
// and once through the option C node (optcnode, parity_attached_test.go).
// Each step is run by a bound container-like init (a shell reading command
// lines from a pipe); its exit status and the engine's verdicts for it are
// printed as one "PARITY ..." line, and compare.sh diffs the two engines.
package parity

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// Dir holds the fixtures (a tmpfs on every guest: /run).
const Dir = "/run/g004p"

// Container is the container name both nodes compile the policies for.
const Container = "g004"

// P is a fixture path.
func P(name string) string { return filepath.Join(Dir, name) }

// Step is one command line the bound init runs. Publish > 0 publishes
// revision Publish of the scenario's policies first.
type Step struct {
	Label, Cmd string
	Publish    int
}

// Scenario is one policy (with revisions) and its steps.
type Scenario struct {
	Name     string
	Policies func(fullpolicy.Mode) []fullpolicy.Policy
	Steps    []Step
}

// Verdict is one engine decision of a step.
type Verdict struct {
	Path                   string
	Deny, Blocked, Unknown bool
}

// Line is the comparable record of one step.
func Line(engine, scenario string, mode fullpolicy.Mode, step string, code int, vs []Verdict) string {
	var parts []string
	for _, v := range vs {
		f := "allow"
		if v.Deny {
			f = "deny"
		}
		if v.Unknown {
			f += "?"
		}
		parts = append(parts, v.Path+"="+f)
	}
	sort.Strings(parts)
	return fmt.Sprintf("PARITY engine=%s scenario=%s mode=%s step=%s code=%d verdicts=%s", engine, scenario, mode, step, code, strings.Join(parts, ","))
}

// Refused is the record of a mode whose policy the engine refused to
// publish (no steps run).
func Refused(engine, scenario string, mode fullpolicy.Mode) string {
	return fmt.Sprintf("PARITY engine=%s scenario=%s mode=%s step=publish code=-1 verdicts=refused", engine, scenario, mode)
}

// Keep selects the verdicts a step is compared on: those of fixtures, of an
// unknown path, and every deny (the init's own shell execs are allowed and
// left out).
func Keep(v Verdict) bool {
	return v.Deny || v.Unknown || v.Path == "" || strings.HasPrefix(v.Path, Dir+"/") || strings.HasPrefix(v.Path, "/lib64/ld-linux")
}

// Modes are both policy modes.
var Modes = []fullpolicy.Mode{fullpolicy.Enforce, fullpolicy.Audit}

func policy(id string, m fullpolicy.Mode, def fullpolicy.Action, rules ...fullpolicy.Rule) fullpolicy.Policy {
	return fullpolicy.Policy{ID: id, Revision: "1", Mode: m, RootRole: "app", Default: def, Rules: rules}
}

func deny(name string, t fullpolicy.Target, a fullpolicy.Actor) fullpolicy.Rule {
	return fullpolicy.Rule{Name: name, Action: fullpolicy.Deny, Target: t, Actor: a}
}

func allow(name string, paths ...string) fullpolicy.Rule {
	return fullpolicy.Rule{Name: name, Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: paths}}
}

func paths(names ...string) []string {
	var out []string
	for _, n := range names {
		out = append(out, P(n))
	}
	return out
}

// shells: every path the init's "/bin/sh -c" and the role shells resolve to
// (an allow-list policy must allow them).
var shells = []string{"/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/dash", "/usr/bin/dash"}

// Scenarios is the table. Fixture names: ok-binaries (static, exit 0)
// allow, deny, target, gl_a, ünï, root/run/g004p/allow (chroot spoof);
// shells (bash copies) setter, setter2, setter3, interp; scripts s_interp
// (#! interp), s_denied (#! /bin/sh); deny_dyn (a dynamic binary for the
// ld.so step); link_to_deny (symlink to deny).
func Scenarios() []Scenario {
	t := func(names ...string) fullpolicy.Target { return fullpolicy.Target{Path: paths(names...)} }
	no := fullpolicy.Actor{}
	yes := true
	single := func(f func(m fullpolicy.Mode) fullpolicy.Policy) func(fullpolicy.Mode) []fullpolicy.Policy {
		return func(m fullpolicy.Mode) []fullpolicy.Policy { return []fullpolicy.Policy{f(m)} }
	}
	return []Scenario{
		{"path_deny", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-path", m, fullpolicy.Allow, deny("deny", t("deny"), no))
		}), []Step{{Label: "allow", Cmd: P("allow")}, {Label: "deny", Cmd: P("deny")}}},
		{"allow_list", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-list", m, fullpolicy.Deny, allow("shells", shells...), allow("ok", P("allow")))
		}), []Step{{Label: "listed", Cmd: P("allow")}, {Label: "unlisted", Cmd: P("target")}}},
		{"symlink_to_denied", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-link", m, fullpolicy.Allow, deny("deny", t("deny"), no))
		}), []Step{{Label: "via_link", Cmd: P("link_to_deny")}}},
		{"glob", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-glob", m, fullpolicy.Allow, deny("gl", fullpolicy.Target{Path: []string{P("gl_*")}}, no))
		}), []Step{{Label: "match", Cmd: P("gl_a")}, {Label: "miss", Cmd: P("allow")}}},
		{"utf8_path", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-utf8", m, fullpolicy.Allow, deny("utf8", t("ünï"), no))
		}), []Step{{Label: "utf8", Cmd: P("ünï")}}},
		{"script_interpreter_denied", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-interp", m, fullpolicy.Allow, deny("interp", t("interp"), no))
		}), []Step{{Label: "script", Cmd: P("s_interp")}}},
		{"script_denied", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-script", m, fullpolicy.Allow, deny("script", t("s_denied"), no))
		}), []Step{{Label: "script", Cmd: P("s_denied")}}},
		{"ldso_direct", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-ldso", m, fullpolicy.Allow, deny("dyn", t("deny_dyn"), no))
		}), []Step{{Label: "exec", Cmd: P("deny_dyn")}, {Label: "via_ldso", Cmd: "/lib64/ld-linux-x86-64.so.2 " + P("deny_dyn")}}},
		{"role_set_then_denied", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-role", m, fullpolicy.Allow,
				fullpolicy.Rule{Name: "taint", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: paths("setter"), SetRole: "tainted"}},
				deny("tainted-target", t("target"), fullpolicy.Actor{Role: []string{"tainted"}}))
		}), []Step{{Label: "clean", Cmd: P("target")}, {Label: "tainted", Cmd: P("setter") + " -c " + P("target")},
			{Label: "tainted_child", Cmd: P("setter") + " -c '" + P("target") + "; " + P("target") + "'"}}},
		{"actor_path", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-actor", m, fullpolicy.Allow, deny("from-setter2", t("target"), fullpolicy.Actor{Path: paths("setter2")}))
		}), []Step{{Label: "other_actor", Cmd: "/usr/bin/bash -c '" + P("target") + "; exit $?'"}, {Label: "actor", Cmd: P("setter2") + " -c '" + P("target") + "; exit $?'"}}},
		{"ancestor", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-anc", m, fullpolicy.Allow, deny("under-setter3", t("target"), fullpolicy.Actor{Ancestor: &fullpolicy.Ancestor{Path: paths("setter3"), Depth: 4}}))
		}), []Step{{Label: "no_ancestor", Cmd: P("target")},
			// Review C6: two commands per shell, so neither exec-optimises:
			// setter3 forks bash, bash forks target (setter3 is an ancestor).
			{Label: "ancestor", Cmd: P("setter3") + " -c \"/usr/bin/bash -c '" + P("target") + "; exit \\$?'; exit \\$?\""}}},
		{"kleene_unknown_then_known_false", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			// Review C6: a step where Kleene AND decides. On the tmpfs
			// target the memfd class is UNKNOWN on both engines (no
			// marking); the ancestor conjunct is KNOWN false. Kleene
			// (option C): known false, no match, allowed. The product's
			// ab57bdda6 evaluator stops at the UNKNOWN: an error (Strict
			// denies).
			return policy("g004-kleene", m, fullpolicy.Allow, deny("memfd-under-x", fullpolicy.Target{Path: paths("target"), FSType: []string{"memfd"}},
				fullpolicy.Actor{Ancestor: &fullpolicy.Ancestor{Path: []string{"/nonexistent/x"}, Depth: 1}}))
		}), []Step{{Label: "target", Cmd: P("target")}}},
		{"uid", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-uid", m, fullpolicy.Allow, deny("uid1000", t("target"), fullpolicy.Actor{UID: []int64{1000}}))
		}), []Step{{Label: "root", Cmd: P("target")}, {Label: "uid1000", Cmd: "setpriv --reuid=1000 --regid=1000 --clear-groups " + P("target")}}},
		{"argv", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-argv", m, fullpolicy.Allow, deny("evil", fullpolicy.Target{Path: paths("target"), Argv: &fullpolicy.Argv{Contains: []string{"--evil"}}}, no))
		}), []Step{{Label: "plain", Cmd: P("target") + " --ok"}, {Label: "evil", Cmd: P("target") + " --evil"}}},
		{"stdin_pipe", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-stdin", m, fullpolicy.Allow, deny("piped", fullpolicy.Target{Path: paths("target"), Argv: &fullpolicy.Argv{StdinIsPipe: &yes}}, no))
		}), []Step{{Label: "devnull", Cmd: P("target") + " </dev/null"}, {Label: "piped", Cmd: "echo x | " + P("target")}}},
		{"container", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-ctr", m, fullpolicy.Allow,
				deny("this-container", t("target"), fullpolicy.Actor{Container: []string{Container}}),
				deny("other-container", t("allow"), fullpolicy.Actor{Container: []string{"other"}}))
		}), []Step{{Label: "match", Cmd: P("target")}, {Label: "miss", Cmd: P("allow")}}},
		{"fstype", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-fs", m, fullpolicy.Allow, deny("tmpfs", fullpolicy.Target{Path: paths("target"), FSType: []string{"tmpfs"}}, no))
		}), []Step{{Label: "tmpfs", Cmd: P("target")}}},
		{"chroot_spoof", single(func(m fullpolicy.Mode) fullpolicy.Policy {
			return policy("g004-chroot", m, fullpolicy.Deny, allow("shells", shells...), allow("chroot", "/usr/sbin/chroot", "/sbin/chroot"), allow("ok", P("allow")))
		}), []Step{{Label: "real", Cmd: P("allow")}, {Label: "spoof", Cmd: "chroot " + P("root") + " " + P("allow")}}},
		{"generation_switch", func(m fullpolicy.Mode) []fullpolicy.Policy {
			a := policy("g004-gen", m, fullpolicy.Allow, deny("a", t("deny"), no))
			b := policy("g004-gen", m, fullpolicy.Allow, deny("b", t("target"), no))
			b.Revision = "2"
			return []fullpolicy.Policy{a, b}
		}, []Step{{Label: "a_deny", Cmd: P("deny")}, {Label: "a_target", Cmd: P("target")},
			{Label: "b_deny", Cmd: P("deny"), Publish: 1}, {Label: "b_target", Cmd: P("target")}}},
	}
}

// okELF is a minimal static x86-64 ELF: exit(0).
func okELF() []byte {
	return staticELF([]byte{0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05}) // mov eax,60; xor edi,edi; syscall
}

// WaitExecELF is a minimal static x86-64 ELF: read one byte from stdin,
// then execve(argv[1], &argv[1], envp); if that fails, exit(errno).
func WaitExecELF() []byte {
	return staticELF([]byte{
		0x48, 0x89, 0xe3, // mov rbx, rsp
		0x31, 0xff, // xor edi, edi
		0x48, 0x8d, 0x74, 0x24, 0xf0, // lea rsi, [rsp-16]
		0xba, 0x01, 0, 0, 0, // mov edx, 1
		0x31, 0xc0, // xor eax, eax (read)
		0x0f, 0x05, // syscall
		0x48, 0x8b, 0x7b, 0x10, // mov rdi, [rbx+16] (argv[1])
		0x48, 0x8d, 0x73, 0x10, // lea rsi, [rbx+16] (&argv[1])
		0x48, 0x8b, 0x03, // mov rax, [rbx] (argc)
		0x48, 0x8d, 0x54, 0xc3, 0x10, // lea rdx, [rbx+rax*8+16] (envp)
		0xb8, 0x3b, 0, 0, 0, // mov eax, 59 (execve)
		0x0f, 0x05, // syscall
		0x89, 0xc7, // mov edi, eax
		0xf7, 0xdf, // neg edi
		0xb8, 0x3c, 0, 0, 0, // mov eax, 60 (exit)
		0x0f, 0x05, // syscall
	})
}

// ChrootExecELF (review N1 fixture) is a minimal static x86-64 ELF: write
// "ready\n" to stdout, read one byte from stdin, chroot(argv[1]),
// chdir("/"), then execve(argv[2], &argv[2], envp); if that fails,
// exit(errno).
func ChrootExecELF() []byte {
	var code []byte
	var fix []struct {
		at, end int
		data    int
	}
	emit := func(b ...byte) { code = append(code, b...) }
	// lea reg,[rip+data]: patched below (data offsets into the trailer).
	lea := func(modrm byte, data int) {
		emit(0x48, 0x8d, modrm, 0, 0, 0, 0)
		fix = append(fix, struct {
			at, end int
			data    int
		}{len(code) - 4, len(code), data})
	}
	emit(0x48, 0x89, 0xe3)             // mov rbx, rsp
	emit(0xbf, 1, 0, 0, 0)             // mov edi, 1
	lea(0x35, 0)                       // lea rsi, [rip+"ready\n"]
	emit(0xba, 6, 0, 0, 0)             // mov edx, 6
	emit(0xb8, 1, 0, 0, 0)             // mov eax, 1 (write)
	emit(0x0f, 0x05)                   // syscall
	emit(0x31, 0xff)                   // xor edi, edi
	emit(0x48, 0x8d, 0x74, 0x24, 0xf0) // lea rsi, [rsp-16]
	emit(0xba, 1, 0, 0, 0)             // mov edx, 1
	emit(0x31, 0xc0)                   // xor eax, eax (read)
	emit(0x0f, 0x05)                   // syscall
	emit(0x48, 0x8b, 0x7b, 0x10)       // mov rdi, [rbx+16] (argv[1])
	emit(0xb8, 161, 0, 0, 0)           // mov eax, 161 (chroot)
	emit(0x0f, 0x05)                   // syscall
	lea(0x3d, 6)                       // lea rdi, [rip+"/"]
	emit(0xb8, 80, 0, 0, 0)            // mov eax, 80 (chdir)
	emit(0x0f, 0x05)                   // syscall
	emit(0x48, 0x8b, 0x7b, 0x18)       // mov rdi, [rbx+24] (argv[2])
	emit(0x48, 0x8d, 0x73, 0x18)       // lea rsi, [rbx+24] (&argv[2])
	emit(0x48, 0x8b, 0x03)             // mov rax, [rbx] (argc)
	emit(0x48, 0x8d, 0x54, 0xc3, 0x10) // lea rdx, [rbx+rax*8+16] (envp)
	emit(0xb8, 59, 0, 0, 0)            // mov eax, 59 (execve)
	emit(0x0f, 0x05)                   // syscall
	emit(0x89, 0xc7)                   // mov edi, eax
	emit(0xf7, 0xdf)                   // neg edi
	emit(0xb8, 60, 0, 0, 0)            // mov eax, 60 (exit)
	emit(0x0f, 0x05)                   // syscall
	trailer := len(code)
	code = append(code, []byte("ready\n/\x00")...)
	for _, f := range fix {
		binary.LittleEndian.PutUint32(code[f.at:], uint32(int32(trailer+f.data-f.end)))
	}
	return staticELF(code)
}

// FifoInitELF (review R3-C1 fixture) is a minimal static x86-64 ELF that
// behaves like a runtime's container init waiting at exec.fifo:
// fd = open(argv[1], O_PATH) (kept), then open(argv[1], O_WRONLY), which
// blocks until the runtime (here the test) opens the fifo for reading; then
// execve(argv[2], &argv[2], envp); if that fails, exit(errno). pad is
// appended after the code (a different image, same behaviour: the
// content-hash mutant's fixture).
func FifoInitELF(pad int) []byte {
	code := []byte{
		0x48, 0x89, 0xe3, // mov rbx, rsp
		0x48, 0x8b, 0x7b, 0x10, // mov rdi, [rbx+16] (argv[1])
		0xbe, 0x00, 0x00, 0x20, 0x00, // mov esi, O_PATH
		0x31, 0xd2, // xor edx, edx
		0xb8, 2, 0, 0, 0, // mov eax, 2 (open)
		0x0f, 0x05, // syscall
		0x48, 0x8b, 0x7b, 0x10, // mov rdi, [rbx+16]
		0xbe, 0x01, 0, 0, 0, // mov esi, O_WRONLY
		0x31, 0xd2, // xor edx, edx
		0xb8, 2, 0, 0, 0, // mov eax, 2 (open): blocks until a reader
		0x0f, 0x05, // syscall
		0x48, 0x8b, 0x7b, 0x18, // mov rdi, [rbx+24] (argv[2])
		0x48, 0x8d, 0x73, 0x18, // lea rsi, [rbx+24]
		0x48, 0x8b, 0x03, // mov rax, [rbx]
		0x48, 0x8d, 0x54, 0xc3, 0x10, // lea rdx, [rbx+rax*8+16]
		0xb8, 59, 0, 0, 0, // mov eax, 59 (execve)
		0x0f, 0x05, // syscall
		0x89, 0xc7, // mov edi, eax
		0xf7, 0xdf, // neg edi
		0xb8, 60, 0, 0, 0, // mov eax, 60 (exit)
		0x0f, 0x05, // syscall
	}
	return staticELF(append(code, make([]byte, pad)...))
}

// OkELF is okELF, exported for node-level fixtures.
func OkELF() []byte { return okELF() }

func staticELF(code []byte) []byte {
	const base, hdr = 0x400000, 64 + 56
	b := make([]byte, hdr+len(code))
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2)    // ET_EXEC
	le.PutUint16(b[18:], 0x3e) // x86-64
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[24:], base+hdr) // entry
	le.PutUint64(b[32:], 64)       // phoff
	le.PutUint16(b[52:], 64)       // ehsize
	le.PutUint16(b[54:], 56)       // phentsize
	le.PutUint16(b[56:], 1)        // phnum
	p := b[64:]
	le.PutUint32(p[0:], 1) // PT_LOAD
	le.PutUint32(p[4:], 5) // R+X
	le.PutUint64(p[16:], base)
	le.PutUint64(p[24:], base)
	le.PutUint64(p[32:], uint64(len(b)))
	le.PutUint64(p[40:], uint64(len(b)))
	le.PutUint64(p[48:], 0x1000)
	copy(b[hdr:], code)
	return b
}

// Setup creates the fixtures under Dir (replacing any).
func Setup() error {
	if err := os.RemoveAll(Dir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(Dir, "root", strings.TrimPrefix(Dir, "/")), 0o755); err != nil {
		return err
	}
	bash, err := os.ReadFile("/usr/bin/bash")
	if err != nil {
		return err
	}
	dyn, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		return err
	}
	ok := okELF()
	files := map[string][]byte{
		"allow": ok, "deny": ok, "target": ok, "gl_a": ok, "ünï": ok,
		"root" + Dir + "/allow": ok,
		"setter":                bash, "setter2": bash, "setter3": bash, "interp": bash,
		"s_interp": []byte("#!" + P("interp") + "\nexit 0\n"),
		"s_denied": []byte("#!/bin/sh\nexit 0\n"),
		"deny_dyn": dyn,
	}
	for name, data := range files {
		if err := os.WriteFile(P(name), data, 0o755); err != nil {
			return err
		}
	}
	return os.Symlink(P("deny"), P("link_to_deny"))
}
