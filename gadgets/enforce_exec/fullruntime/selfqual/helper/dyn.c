// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Inspektor Gadget authors
//
// E1 fixture: a dynamically linked (PT_INTERP) ELF with no libraries and no
// libc, so it runs under any distro's ld.so. It prints "T <pid>" and, given
// an argument, execs that path (argv {path}); a failed exec exits with its
// errno. build.sh compiles it with a placeholder PT_INTERP that the stage
// rewrites to its own ld.so copy (the fanotify park point).

#define SYS_write 1
#define SYS_getpid 39
#define SYS_execve 59
#define SYS_exit 60

static long sys3(long n, long a, long b, long c)
{
	long r;

	__asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
	return r;
}

__asm__(".globl _start\n_start:\n\tmov %rsp, %rdi\n\tand $-16, %rsp\n\tcall e1_main\n\thlt\n");

__attribute__((used)) void e1_main(long *sp)
{
	long argc = sp[0];
	char **argv = (char **)(sp + 1);
	char **envp = argv + argc + 1;
	char buf[32], *p = buf + sizeof(buf);
	long pid = sys3(SYS_getpid, 0, 0, 0), r;

	*--p = '\n';
	do {
		*--p = '0' + pid % 10;
		pid /= 10;
	} while (pid);
	*--p = ' ';
	*--p = 'T';
	sys3(SYS_write, 1, (long)p, buf + sizeof(buf) - p);
	if (argc > 1) {
		char *next[2] = { argv[1], 0 };

		r = sys3(SYS_execve, (long)argv[1], (long)next, (long)envp);
		sys3(SYS_exit, -r, 0, 0);
	}
	sys3(SYS_exit, 0, 0, 0);
}
