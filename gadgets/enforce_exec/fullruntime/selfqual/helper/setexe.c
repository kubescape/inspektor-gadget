// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Inspektor Gadget authors
//
// G004 fixture (review E2-3): a static-pie program with no libc that copies
// its own image to an anonymous mapping, continues there, unmaps the
// original (so no VMA maps its exe any more), points its exe link at
// argv[1] with prctl(PR_SET_MM, PR_SET_MM_EXE_FILE), prints "T <pid>", then
// execs argv[2]. Exit codes: 100+errno of the prctl, 150+errno of the open,
// the exec's errno if it fails.

#define SYS_write 1
#define SYS_open 2
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_getpid 39
#define SYS_execve 59
#define SYS_exit 60
#define SYS_prctl 157

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
	long r;
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;

	__asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return r;
}

extern char __ehdr_start[], _end[];

__asm__(".globl _start\n_start:\n\tmov %rsp, %rdi\n\tand $-16, %rsp\n\tcall e1_main\n\thlt\n");

typedef void (*stage2_fn)(long *, char *, unsigned long);

__attribute__((used, noinline)) void e1_stage2(long *sp, char *old, unsigned long size)
{
	long argc = sp[0];
	char **argv = (char **)(sp + 1);
	char **envp = argv + argc + 1;
	char buf[32], *p = buf + sizeof(buf);
	long pid, fd, r;

	sys6(SYS_munmap, (long)old, size, 0, 0, 0, 0);
	if (argc < 3)
		sys6(SYS_exit, 2, 0, 0, 0, 0, 0);
	fd = sys6(SYS_open, (long)argv[1], 0, 0, 0, 0, 0);
	if (fd < 0)
		sys6(SYS_exit, 150 - fd, 0, 0, 0, 0, 0);
	r = sys6(SYS_prctl, 35 /* PR_SET_MM */, 13 /* PR_SET_MM_EXE_FILE */, fd, 0, 0, 0);
	if (r < 0)
		sys6(SYS_exit, 100 - r, 0, 0, 0, 0, 0);
	pid = sys6(SYS_getpid, 0, 0, 0, 0, 0, 0);
	*--p = '\n';
	do {
		*--p = '0' + pid % 10;
		pid /= 10;
	} while (pid);
	*--p = ' ';
	*--p = 'T';
	sys6(SYS_write, 1, (long)p, buf + sizeof(buf) - p, 0, 0, 0);
	{
		char *next[2] = { argv[2], 0 };

		r = sys6(SYS_execve, (long)argv[2], (long)next, (long)envp, 0, 0, 0);
		sys6(SYS_exit, -r, 0, 0, 0, 0, 0);
	}
}

__attribute__((used)) void e1_main(long *sp)
{
	unsigned long size = (unsigned long)(_end - __ehdr_start);
	char *copy;

	size = (size + 4095) & ~4095UL;
	copy = (char *)sys6(SYS_mmap, 0, size, 7 /* RWX */, 0x22 /* PRIVATE|ANON */, -1, 0);
	for (unsigned long i = 0; i < size; i++)
		copy[i] = __ehdr_start[i];
	((stage2_fn)(copy + ((char *)e1_stage2 - __ehdr_start)))(sp, __ehdr_start, size);
}
