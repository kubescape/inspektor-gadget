// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Inspektor Gadget authors
//
// enforce_exec self-qualification probe helper (D4 prototype).
//
// One static binary, embedded in the agent and hash-checked before use. It
// has two roles, chosen by argv[1]:
//
//   ee-selfqual-stage   the stage: runs in a private mount namespace, builds
//                       the probe fixtures on a private tmpfs, and then
//                       spawns one probe root per command read from stdin.
//   anything else       an exec target: prints "T <pid>" (unless EESQ_QUIET
//                       is set) and exits 0. Every fixture file that is an
//                       ELF image is a copy of this binary.
//
// Stage protocol (stdin -> stage, stage -> stdout), one line each:
//   SPAWN <cgroup-dir|-> <token>...   fork a probe root, move it into the
//                                     cgroup, answer "PID <pid>" and wait
//   GO                                release the probe root; its results are
//                                     "R <token> <code> <pid>" lines, then
//                                     "DONE <wait-status>"
//   QUIT                              clean up and exit
//
// A token is <creator>+<variant>:<file>. code is 0 when the image ran, the
// exec errno when it failed, 300+errno when the task could not be created,
// 1000+signal when the task was killed, 99 for a passed AT_EXECVE_CHECK.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <linux/io_uring.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dyn_elf.h" // E1: the PT_INTERP fixture (helper/dyn.c), placeholder interpreter
#include "setexe_elf.h" // G004: PR_SET_MM_EXE_FILE after unmapping its own image (helper/setexe.c)

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_EXECVE_CHECK
#define AT_EXECVE_CHECK 0x10000
#endif
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1U
#endif

extern char **environ;

static char fixture_dir[PATH_MAX];
static char binfmt_entry[PATH_MAX];

static void out(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n > (int)sizeof(buf))
		n = sizeof(buf);
	if (n > 0 && write(1, buf, n) < 0) {
	}
}

static void die(const char *what)
{
	out("ERR %s: %s\n", what, strerror(errno));
	_exit(70);
}

// ---------------------------------------------------------------- fixtures

static void write_file(const char *name, const void *data, size_t len, mode_t mode)
{
	int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
	const char *p = data;

	if (fd < 0)
		die(name);
	while (len) {
		ssize_t n = write(fd, p, len);

		if (n <= 0)
			die(name);
		p += n;
		len -= n;
	}
	if (fchmod(fd, mode))
		die(name);
	close(fd);
}

static void copy_self(const char *name)
{
	int in = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
	char buf[65536];
	ssize_t n;

	if (in < 0 || fd < 0)
		die(name);
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		char *p = buf;

		while (n) {
			ssize_t w = write(fd, p, n);

			if (w <= 0)
				die(name);
			p += w;
			n -= w;
		}
	}
	if (n < 0)
		die(name);
	close(in);
	close(fd);
}

static void script(const char *name, const char *interp)
{
	char buf[PATH_MAX + 16];
	int n;

	if (interp[0] == '/')
		n = snprintf(buf, sizeof(buf), "#!%s\n", interp);
	else
		n = snprintf(buf, sizeof(buf), "#!%s/%s\n", fixture_dir, interp);
	write_file(name, buf, n, 0755);
}

static void manifest(const char *name)
{
	struct stat st;

	if (stat(name, &st))
		die(name);
	out("FILE %s %u %u %llu\n", name, major(st.st_dev), minor(st.st_dev), (unsigned long long)st.st_ino);
}

static const char *const elf_files[] = { "allow", "deny", "hold_interp", "setter", "plain", "curl", "renamee",
					 "\xc3\xbcn\xc3\xaf" /* G004 R3: "ünï" */, NULL };

static const char *const all_files[] = {
	"allow", "deny", "hold_interp", "sh_ok", "sh_deny_interp", "sh_denied", "sh_nointerp",
	"sh_dirinterp", "sh_hold", "garbage", "garbage_denied", "noperm", "c1", "c2", "c3",
	"c4", "c5", "l1", "l2", "l3", "l4", "l5", "l6",
	// E1 (option C): role setters, a PT_INTERP binary with its ld.so copy,
	// a script whose interpreter is denied.
	"setter", "plain", "curl", "dyn", "ldso", "sh_mark_deny", "renamee", "\xc3\xbcn\xc3\xaf", "setexe", NULL,
};

#define E1_PH_PREFIX "/e1-interp-placeholder-"

// write_dyn writes the PT_INTERP fixture with its interpreter set to
// <fixture_dir>/ldso, and ldso as a copy of the distro's ld.so.
static void write_dyn(void)
{
	unsigned char *img = malloc(dyn_elf_len);
	char interp[PATH_MAX];
	size_t i, n = strlen(E1_PH_PREFIX), ph = 0;
	int in, fd;
	char buf[65536];
	ssize_t r;

	if (!img)
		die("dyn");
	memcpy(img, dyn_elf, dyn_elf_len);
	for (i = 0; i + n < dyn_elf_len; i++)
		if (!memcmp(img + i, E1_PH_PREFIX, n))
			break;
	if (i + n >= dyn_elf_len)
		die("dyn placeholder");
	ph = strlen((char *)img + i);
	snprintf(interp, sizeof(interp), "%s/ldso", fixture_dir);
	if (strlen(interp) >= ph)
		die("dyn interp too long");
	memset(img + i, 0, ph);
	memcpy(img + i, interp, strlen(interp));
	write_file("dyn", img, dyn_elf_len, 0755);
	free(img);
	in = open("/lib64/ld-linux-x86-64.so.2", O_RDONLY | O_CLOEXEC);
	fd = open("ldso", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
	if (in < 0 || fd < 0)
		die("ldso");
	while ((r = read(in, buf, sizeof(buf))) > 0)
		if (write(fd, buf, r) != r)
			die("ldso");
	close(in);
	close(fd);
}

static void setup_binfmt(void)
{
	char reg[PATH_MAX + 128], magic[64];
	unsigned int r1 = 0, r2 = 0;
	int fd, n;

	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		if (read(fd, &r1, sizeof(r1)) < 0 || read(fd, &r2, sizeof(r2)) < 0) {
		}
		close(fd);
	}
	snprintf(magic, sizeof(magic), "EESQ%08x%08x", r1, r2);
	if (mkdir("bm", 0700) || mount("binfmt_misc", "bm", "binfmt_misc", 0, NULL)) {
		out("BINFMT 0 mount: %s\n", strerror(errno));
		return;
	}
	n = snprintf(reg, sizeof(reg), ":eesq%d:M::%s::%s/allow:", getpid(), magic, fixture_dir);
	fd = open("bm/register", O_WRONLY | O_CLOEXEC);
	if (fd < 0 || write(fd, reg, n) != n) {
		out("BINFMT 0 register: %s\n", strerror(errno));
		if (fd >= 0)
			close(fd);
		return;
	}
	close(fd);
	snprintf(binfmt_entry, sizeof(binfmt_entry), "%s/bm/eesq%d", fixture_dir, getpid());
	n = snprintf(reg, sizeof(reg), "%s\n", magic);
	write_file("bm_file", reg, n, 0755);
	manifest("bm_file");
	out("BINFMT 1\n");
}

static void cleanup_binfmt(void)
{
	int fd;

	if (!binfmt_entry[0])
		return;
	fd = open(binfmt_entry, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		if (write(fd, "-1", 2) < 0) {
		}
		close(fd);
	}
	binfmt_entry[0] = 0;
}

// build_fixtures writes every fixture into fixture_dir and prints the manifest.
static void build_fixtures(void)
{
	static const char garbage[] = "this is not an executable image\n";
	char name[8], next[8];
	int i;

	if (chdir(fixture_dir))
		die("chdir");

	for (i = 0; elf_files[i]; i++)
		copy_self(elf_files[i]);
	script("sh_ok", "allow");
	script("sh_deny_interp", "deny");
	script("sh_denied", "allow");
	script("sh_nointerp", "missing");
	script("sh_dirinterp", fixture_dir);
	script("sh_hold", "hold_interp");
	script("sh_mark_deny", "deny");
	write_dyn();
	write_file("setexe", setexe_elf, setexe_elf_len, 0755);
	write_file("garbage", garbage, sizeof(garbage) - 1, 0755);
	write_file("garbage_denied", garbage, sizeof(garbage) - 1, 0755);
	write_file("noperm", garbage, sizeof(garbage) - 1, 0644);
	// c1 -> ... -> c5 -> allow: six binfmt passes, the deepest chain that runs.
	for (i = 1; i <= 5; i++) {
		snprintf(name, sizeof(name), "c%d", i);
		snprintf(next, sizeof(next), "c%d", i + 1);
		script(name, i == 5 ? "allow" : next);
	}
	// l1 -> ... -> l6 -> allow: a seventh pass, refused with ELOOP.
	for (i = 1; i <= 6; i++) {
		snprintf(name, sizeof(name), "l%d", i);
		snprintf(next, sizeof(next), "l%d", i + 1);
		script(name, i == 6 ? "allow" : next);
	}
	for (i = 0; all_files[i]; i++)
		manifest(all_files[i]);
}

static void setup_fixtures(void)
{
	static const char *const dirs[] = { "/run", "/tmp", "/mnt", "/var", "/dev/shm", NULL };
	const char *const *d;

	// Nothing mounted here may propagate to, or be seen by, anyone else.
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		die("make / private");
	for (d = dirs; *d; d++) {
		if (!mount("ee-selfqual", *d, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0700,size=64m")) {
			snprintf(fixture_dir, sizeof(fixture_dir), "%s", *d);
			break;
		}
	}
	if (!*d)
		die("mount private tmpfs");
	build_fixtures();
	setup_binfmt();
	out("READY %s\n", fixture_dir);
}

// ------------------------------------------------------------ exec variants

static char *const target_argv_tmpl[] = { NULL, NULL };

// do_exec never returns on success. On failure it returns the errno.
static int do_exec(const char *variant, const char *file)
{
	char *argv[] = { (char *)file, NULL };
	char path[64];
	int fd, mfd;

	(void)target_argv_tmpl;
	if (!strcmp(variant, "exec")) {
		execve(file, argv, environ);
		return errno;
	}
	if (!strcmp(variant, "at_empty")) {
		fd = open(file, O_PATH);
		if (fd < 0)
			return errno;
		syscall(SYS_execveat, fd, "", argv, environ, AT_EMPTY_PATH);
		return errno;
	}
	if (!strcmp(variant, "fexecve")) {
		fd = open(file, O_RDONLY);
		if (fd < 0)
			return errno;
		fexecve(fd, argv, environ);
		return errno;
	}
	if (!strcmp(variant, "fdpath")) {
		fd = open(file, O_RDONLY);
		if (fd < 0)
			return errno;
		snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
		execve(path, argv, environ);
		return errno;
	}
	if (!strcmp(variant, "dirfd")) {
		fd = open(".", O_RDONLY | O_DIRECTORY);
		if (fd < 0)
			return errno;
		syscall(SYS_execveat, fd, file, argv, environ, 0);
		return errno;
	}
	if (!strcmp(variant, "memfd")) {
		char buf[65536];
		ssize_t n;

		fd = open(file, O_RDONLY);
		mfd = syscall(SYS_memfd_create, "eesq", MFD_CLOEXEC);
		if (fd < 0 || mfd < 0)
			return errno;
		while ((n = read(fd, buf, sizeof(buf))) > 0)
			if (write(mfd, buf, n) != n)
				return errno;
		syscall(SYS_execveat, mfd, "", argv, environ, AT_EMPTY_PATH);
		return errno;
	}
	// E1: exec the file with argv {file, next} (file,next in the token).
	if (!strcmp(variant, "execarg")) {
		char copy[PATH_MAX], *next;
		char *av[3];

		snprintf(copy, sizeof(copy), "%s", file);
		next = strchr(copy, ',');
		if (!next)
			return EINVAL;
		*next++ = 0;
		av[0] = copy;
		av[1] = next;
		av[2] = NULL;
		execve(copy, av, environ);
		return errno;
	}
	// G004: exec prog with argv {prog, a1, a2} (prog;a1;a2 in the token:
	// ';', since a token nested in "rerun" cannot hold ',').
	if (!strcmp(variant, "exec2")) {
		char copy[PATH_MAX], *av[4];

		snprintf(copy, sizeof(copy), "%s", file);
		av[0] = strtok(copy, ";");
		av[1] = strtok(NULL, ";");
		av[2] = strtok(NULL, ";");
		av[3] = NULL;
		if (!av[0] || !av[1] || !av[2])
			return EINVAL;
		execve(av[0], av, environ);
		return errno;
	}
	// E1: exec the file as a helper that runs more tokens:
	// file,tok1,tok2... (a token's own ',' is not supported).
	if (!strcmp(variant, "rerun")) {
		char copy[PATH_MAX], *av[64];
		int n = 0;

		snprintf(copy, sizeof(copy), "%s", file);
		av[n++] = strtok(copy, ",");
		av[n++] = "ee-selfqual-run";
		av[n++] = fixture_dir;
		for (char *t = strtok(NULL, ","); t && n < 62; t = strtok(NULL, ","))
			av[n++] = t;
		av[n] = NULL;
		execve(av[0], av, environ);
		return errno;
	}
	// E1 scenario (a): the distro's dynamic loader runs the file; the
	// exec hook sees ld.so, not the file.
	if (!strcmp(variant, "ldso")) {
		char prog[PATH_MAX];
		char *av[] = { "/lib64/ld-linux-x86-64.so.2", prog, NULL };

		snprintf(prog, sizeof(prog), "%s/%s", fixture_dir, file);

		execve(av[0], av, environ);
		return errno;
	}
	// E1 R31: chroot into a writable directory, recreate the allowed path
	// with the denied file's content, exec it by that path.
	if (!strcmp(variant, "chroot")) {
		char jail[PATH_MAX], dir[PATH_MAX], dst[PATH_MAX], src[PATH_MAX];
		char buf[65536];
		ssize_t r;
		int in, out;

		snprintf(jail, sizeof(jail), "%s/jail%d", fixture_dir, getpid());
		snprintf(dir, sizeof(dir), "%s%s", jail, fixture_dir);
		snprintf(dst, sizeof(dst), "%s/%s", dir, file);
		snprintf(src, sizeof(src), "%s/deny", fixture_dir);
		if (mkdir(jail, 0755) || mkdir(dir, 0755))
			return 400 + errno;
		in = open(src, O_RDONLY | O_CLOEXEC);
		out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
		if (in < 0 || out < 0)
			return 400 + errno;
		while ((r = read(in, buf, sizeof(buf))) > 0)
			if (write(out, buf, r) != r)
				return 400 + errno;
		close(in);
		close(out);
		if (chroot(jail) || chdir("/"))
			return 400 + errno;
		snprintf(dst, sizeof(dst), "%s/%s", fixture_dir, file);
		argv[0] = dst;
		execve(dst, argv, environ);
		return errno;
	}
	// E1: an allowed copy of the file 70 directories deep (longer than the
	// engine's 64-step reachability walk), exec'ed by its path. The policy
	// allows that path ("deep" + "/a" x 70 + "/<file>").
	if (!strcmp(variant, "deep")) {
		char dst[PATH_MAX], buf[65536];
		ssize_t r;
		int in, out, n = snprintf(dst, sizeof(dst), "deep");

		mkdir(dst, 0755);
		for (int i = 0; i < 70; i++) {
			n += snprintf(dst + n, sizeof(dst) - n, "/a");
			mkdir(dst, 0755);
		}
		snprintf(dst + n, sizeof(dst) - n, "/%s", file);
		unlink(dst);
		in = open(file, O_RDONLY | O_CLOEXEC);
		out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
		if (in < 0 || out < 0)
			return 400 + errno;
		while ((r = read(in, buf, sizeof(buf))) > 0)
			if (write(out, buf, r) != r)
				return 400 + errno;
		close(in);
		close(out);
		argv[0] = dst;
		execve(dst, argv, environ);
		return errno;
	}
	// E1 R31: exec a deleted copy of the file through its descriptor
	// (the policy allows the copy's path, "deltmp").
	if (!strcmp(variant, "deleted")) {
		char buf[65536];
		ssize_t r;
		int in, out;

		unlink("deltmp");
		in = open(file, O_RDONLY | O_CLOEXEC);
		out = open("deltmp", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
		if (in < 0 || out < 0)
			return 400 + errno;
		while ((r = read(in, buf, sizeof(buf))) > 0)
			if (write(out, buf, r) != r)
				return 400 + errno;
		close(in);
		close(out);
		fd = open("deltmp", O_RDONLY);
		if (fd < 0 || unlink("deltmp"))
			return 400 + errno;
		syscall(SYS_execveat, fd, "", argv, environ, AT_EMPTY_PATH);
		return errno;
	}
	if (!strcmp(variant, "check")) {
		fd = open(file, O_PATH);
		if (fd < 0)
			return errno;
		if (!syscall(SYS_execveat, fd, "", argv, environ, AT_EMPTY_PATH | AT_EXECVE_CHECK))
			return 99;
		return errno;
	}
	return ENOSYS;
}

struct exec_arg {
	const char *variant, *file;
	pthread_barrier_t *barrier;
};

static void *exec_thread(void *p)
{
	struct exec_arg *a = p;

	if (a->barrier)
		pthread_barrier_wait(a->barrier);
	_exit(do_exec(a->variant, a->file));
	return NULL;
}

static void *idle_thread(void *p)
{
	(void)p;
	for (;;)
		pause();
	return NULL;
}

static int clonevm_fn(void *p)
{
	struct exec_arg *a = p;

	_exit(do_exec(a->variant, a->file));
	return 0;
}

static void spin(unsigned int max_us)
{
	struct timespec ts = { 0, (long)(rand() % (max_us + 1)) * 1000 };

	if (ts.tv_nsec)
		nanosleep(&ts, NULL);
}

static int reap(pid_t pid)
{
	int status;

	for (;;) {
		if (waitpid(pid, &status, 0) < 0) {
			if (errno == EINTR)
				continue;
			return 900;
		}
		if (WIFEXITED(status))
			return WEXITSTATUS(status);
		if (WIFSIGNALED(status))
			return 1000 + WTERMSIG(status);
	}
}

// run_token creates a task as the creator says and has it exec the file as
// the variant says. It returns the result code and the created pid.
static int run_token(const char *creator, const char *variant, const char *file, pid_t *pid_out)
{
	struct exec_arg arg = { variant, file, NULL };
	pthread_barrier_t barrier;
	pthread_t th;
	pid_t pid = 0;
	int i, rc;

	*pid_out = 0;
	if (!strcmp(creator, "self")) {
		*pid_out = getpid();
		return do_exec(variant, file);
	}
	if (!strcmp(creator, "fork")) {
		pid = fork();
		if (!pid)
			_exit(do_exec(variant, file));
	} else if (!strcmp(creator, "vfork")) {
		pid = vfork();
		if (!pid)
			_exit(do_exec(variant, file));
	} else if (!strcmp(creator, "clonevm")) {
		size_t sz = 1 << 18;
		char *stack = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);

		if (stack == MAP_FAILED)
			return 300 + errno;
		pid = clone(clonevm_fn, stack + sz, CLONE_VM | SIGCHLD, &arg);
		if (pid > 0) {
			rc = reap(pid);
			munmap(stack, sz);
			*pid_out = pid;
			return rc;
		}
	} else if (!strcmp(creator, "spawn")) {
		char *argv[] = { (char *)file, NULL };

		rc = posix_spawn(&pid, file, NULL, NULL, argv, environ);
		if (rc)
			return rc;
	} else if (!strncmp(creator, "into@", 5)) {
		struct {
			uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls, set_tid, set_tid_size, cgroup;
		} ca = { 0 };
		int cfd = open(creator + 5, O_RDONLY | O_DIRECTORY);

		if (cfd < 0)
			return 300 + errno;
		ca.flags = CLONE_INTO_CGROUP;
		ca.exit_signal = SIGCHLD;
		ca.cgroup = cfd;
		pid = syscall(SYS_clone3, &ca, sizeof(ca));
		if (!pid)
			_exit(do_exec(variant, file));
		rc = errno;
		close(cfd);
		errno = rc;
	} else if (!strcmp(creator, "thread") || !strcmp(creator, "threadrace") || !strcmp(creator, "exitrace")) {
		pid = fork();
		if (!pid) {
			if (!strcmp(creator, "thread")) {
				for (i = 0; i < 3; i++)
					if (pthread_create(&th, NULL, idle_thread, NULL))
						_exit(71);
				if (pthread_create(&th, NULL, exec_thread, &arg))
					_exit(71);
				for (;;)
					pause();
			}
			if (!strcmp(creator, "threadrace")) {
				pthread_barrier_init(&barrier, NULL, 4);
				arg.barrier = &barrier;
				for (i = 0; i < 4; i++)
					if (pthread_create(&th, NULL, exec_thread, &arg))
						_exit(71);
				for (;;)
					pause();
			}
			srand(getpid());
			if (pthread_create(&th, NULL, exec_thread, &arg))
				_exit(71);
			spin(300);
			_exit(0);
		}
	} else if (!strcmp(creator, "killrace")) {
		pid = fork();
		if (!pid)
			_exit(do_exec(variant, file));
		if (pid > 0) {
			spin(400);
			kill(pid, SIGKILL);
		}
	} else {
		return 300 + ENOSYS;
	}
	if (pid < 0)
		return 300 + errno;
	*pid_out = pid;
	return reap(pid);
}

static void storm(int workers, int iters, const char *a, const char *b)
{
	pid_t *pids = calloc(workers, sizeof(*pids));
	const char *files[2] = { a, b };
	int w, i, f;

	setenv("EESQ_QUIET", "1", 1);
	for (w = 0; w < workers; w++) {
		pids[w] = fork();
		if (pids[w] < 0) {
			out("R storm-worker %d 0\n", 300 + errno);
			continue;
		}
		if (pids[w])
			continue;
		for (i = 0; i < iters; i++) {
			for (f = 0; f < 2; f++) {
				pid_t pid = fork();
				int code;

				if (!pid)
					_exit(do_exec("exec", files[f]));
				code = pid < 0 ? 300 + errno : reap(pid);
				out("S %d %s %d %d\n", w, files[f], pid, code);
			}
		}
		_exit(0);
	}
	for (w = 0; w < workers; w++)
		if (pids[w] > 0)
			reap(pids[w]);
	unsetenv("EESQ_QUIET");
	free(pids);
}

static void run_tokens(int n, char **tok);

// G003: copy a fixture to dst (dst replaced).
static int copy_file(const char *src, const char *dst)
{
	char buf[65536];
	ssize_t r;
	int in, out;

	unlink(dst);
	in = open(src, O_RDONLY | O_CLOEXEC);
	out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
	if (in < 0 || out < 0)
		return errno;
	while ((r = read(in, buf, sizeof(buf))) > 0)
		if (write(out, buf, r) != r)
			return errno;
	close(in);
	close(out);
	return 0;
}

// G003: exec fixture bin as a helper running one more token.
static int exec_run(const char *bin, const char *next)
{
	char *av[] = { (char *)bin, "ee-selfqual-run", fixture_dir, (char *)next, NULL };

	execve(bin, av, environ);
	return errno;
}

// G003 E4: io_uring requests that block in io-wq workers (PF_IO_WORKER
// tasks: task_alloc runs, sched_process_fork does not).
static int iouring_workers(int n)
{
	struct io_uring_params p = { 0 };
	int fd = syscall(__NR_io_uring_setup, 64, &p), pfd[2];
	struct io_uring_sqe *sqes;
	unsigned int *tail, *array, mask;
	char *sq, buf[8];

	if (fd < 0)
		return errno;
	if (pipe(pfd))
		return errno;
	sq = mmap(NULL, p.sq_off.array + p.sq_entries * sizeof(unsigned int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (sq == MAP_FAILED || sqes == MAP_FAILED)
		return errno;
	tail = (unsigned int *)(sq + p.sq_off.tail);
	array = (unsigned int *)(sq + p.sq_off.array);
	mask = *(unsigned int *)(sq + p.sq_off.ring_mask);
	if (n > (int)p.sq_entries)
		n = p.sq_entries;
	for (int i = 0; i < n; i++) {
		unsigned int t = *tail, idx = t & mask;
		struct io_uring_sqe *e = &sqes[idx];

		memset(e, 0, sizeof(*e));
		e->opcode = IORING_OP_READ;
		e->fd = pfd[0];
		e->addr = (unsigned long)buf;
		e->len = 1;
		e->flags = IOSQE_ASYNC;
		array[idx] = idx;
		__atomic_store_n(tail, t + 1, __ATOMIC_RELEASE);
	}
	if (syscall(__NR_io_uring_enter, fd, n, 0, 0, NULL, 0) < 0)
		return errno;
	// The ring and its workers live until this process exits.
	return 0;
}

static void run_tokens(int n, char **tok)
{
	int i;

	for (i = 0; i < n; i++) {
		char copy[PATH_MAX], *creator = copy, *variant, *file;
		pid_t pid;
		int code;

		snprintf(copy, sizeof(copy), "%s", tok[i]);
		// G003 E2: rename:<a>><b> / replace:<a> (a's content becomes deny's).
		if (!strncmp(copy, "rename:", 7)) {
			char *b = strchr(copy + 7, '>');

			code = b ? (*b++ = 0, rename(copy + 7, b) ? errno : 0) : EINVAL;
			out("R %s %d %d\n", tok[i], code, getpid());
			continue;
		}
		if (!strncmp(copy, "replace:", 8)) {
			out("R %s %d %d\n", tok[i], copy_file("deny", copy + 8), getpid());
			continue;
		}
		// G003 E2: PR_SET_MM_EXE_FILE to a fixture.
		if (!strncmp(copy, "setexe:", 7)) {
			int fd = open(copy + 7, O_RDONLY | O_CLOEXEC);

			code = fd < 0 ? errno : prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0) ? errno : 0;
			out("R %s %d %d\n", tok[i], code, getpid());
			continue;
		}
		// G003 E4: touch:<f> / waitfile:<f> (fixture directory).
		if (!strncmp(copy, "touch:", 6)) {
			int fd = open(copy + 6, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);

			out("R %s %d %d\n", tok[i], fd < 0 ? errno : 0, getpid());
			if (fd >= 0)
				close(fd);
			continue;
		}
		if (!strncmp(copy, "waitfile:", 9)) {
			int k = 0;

			while (access(copy + 9, F_OK) && k++ < 20000)
				usleep(1000);
			out("R %s %d %d\n", tok[i], access(copy + 9, F_OK) ? ETIMEDOUT : 0, getpid());
			continue;
		}
		if (!strcmp(copy, "subreaper")) {
			out("R %s %d %d\n", tok[i], prctl(PR_SET_CHILD_SUBREAPER, 1) ? errno : 0, getpid());
			continue;
		}
		if (!strcmp(copy, "reapall")) {
			int st, k = 0;

			while (wait(&st) > 0 || errno == EINTR)
				k++;
			out("R %s %d %d\n", tok[i], 0, getpid());
			continue;
		}
		// G003 E2: via:<bin>:<t1>;<t2>...: a child execs <bin> as a helper
		// that runs the tokens (each may hold ',' and ':').
		if (!strncmp(copy, "via:", 4)) {
			char *bin = copy + 4, *rest = strchr(bin, ':'), *av[64];
			int k = 0;
			pid_t c;

			if (!rest) {
				out("R %s %d 0\n", tok[i], 300 + EINVAL);
				continue;
			}
			*rest++ = 0;
			av[k++] = bin;
			av[k++] = "ee-selfqual-run";
			av[k++] = fixture_dir;
			for (char *t = strtok(rest, ";"); t && k < 62; t = strtok(NULL, ";"))
				av[k++] = t;
			av[k] = NULL;
			c = fork();
			if (!c) {
				execve(bin, av, environ);
				_exit(errno);
			}
			code = c > 0 ? reap(c) : 300 + errno;
			out("R via:%s %d %d\n", bin, code, c);
			continue;
		}
		// G003 E2: chain:<n>:<k>:<token>: n processes, each exec'ing
		// plain (setter at level k, counted from the leaf's parent), the
		// last running <token>.
		if (!strncmp(copy, "chain:", 6)) {
			int m, k;
			char *rest;

			if (sscanf(copy, "chain:%d:%d:", &m, &k) != 2 || !(rest = strchr(strchr(copy + 6, ':') + 1, ':'))) {
				out("R %s %d 0\n", tok[i], 300 + EINVAL);
				continue;
			}
			rest++;
			if (m == 0) {
				char *one[] = { rest };

				run_tokens(1, one);
				continue;
			}
			{
				char next[PATH_MAX];
				pid_t c;

				snprintf(next, sizeof(next), "chain:%d:%d:%s", m - 1, k, rest);
				c = fork();
				if (!c)
					_exit(exec_run(m == k ? "setter" : "plain", next));
				if (c > 0)
					reap(c);
			}
			continue;
		}
		// G003 E2: orphan:<bin>:<token>: a child execs <bin>, which forks a
		// grandchild and exits at once; the grandchild waits to be
		// reparented, then runs <token>.
		if (!strncmp(copy, "orphan:", 7) || !strncmp(copy, "orphan2:", 8)) {
			if (copy[6] == ':') {
				char *bin = copy + 7, *rest = strchr(bin, ':'), next[PATH_MAX];
				pid_t c;

				if (!rest) {
					out("R %s %d 0\n", tok[i], 300 + EINVAL);
					continue;
				}
				*rest++ = 0;
				snprintf(next, sizeof(next), "orphan2:%s", rest);
				c = fork();
				if (!c)
					_exit(exec_run(bin, next));
				if (c > 0)
					reap(c);
				continue;
			}
			{
				pid_t parent = getpid(), g = fork();

				if (!g) {
					char *one[] = { copy + 8 };

					while (getppid() == parent)
						usleep(1000);
					run_tokens(1, one);
					_exit(0);
				}
				_exit(0); // the middle process exits: g is reparented
			}
		}
		// G004 R12: sleepers:<n> children alive for 3 s (reaped by reapall).
		if (!strncmp(copy, "sleepers:", 9)) {
			int z = atoi(copy + 9), made = 0;

			for (int j = 0; j < z; j++) {
				pid_t c = fork();

				if (!c) {
					sleep(3);
					_exit(0);
				}
				if (c > 0)
					made++;
			}
			out("R %s %d %d\n", tok[i], made, getpid());
			continue;
		}
		// G003 E4: zombies:<n> un-reaped children; iouring:<n> workers.
		if (!strncmp(copy, "zombies:", 8)) {
			int z = atoi(copy + 8), made = 0;

			for (int j = 0; j < z; j++) {
				pid_t c = fork();

				if (!c)
					_exit(0);
				if (c > 0)
					made++;
			}
			out("R %s %d %d\n", tok[i], made == z ? 0 : 300 + EAGAIN, getpid());
			continue;
		}
		if (!strncmp(copy, "iouring:", 8)) {
			out("R %s %d %d\n", tok[i], iouring_workers(atoi(copy + 8)), getpid());
			continue;
		}
		// E1: pin this process (and what it creates) to one CPU.
		if (!strncmp(copy, "pin:", 4)) {
			cpu_set_t set;

			CPU_ZERO(&set);
			CPU_SET(atoi(copy + 4), &set);
			out("R %s %d 0\n", tok[i], sched_setaffinity(0, sizeof(set), &set) ? 300 + errno : 0);
			continue;
		}
		if (!strncmp(copy, "storm:", 6)) {
			int w, it;
			char a[64], b[64];

			if (sscanf(copy, "storm:%d:%d:%63[^:]:%63s", &w, &it, a, b) != 4) {
				out("R %s %d 0\n", tok[i], 300 + EINVAL);
				continue;
			}
			storm(w, it, a, b);
			out("R %s 0 0\n", tok[i]);
			continue;
		}
		// <creator>+<variant>:<file>; the file part may itself hold
		// nested tokens (E1 "rerun"), so split at the first '+' and ':'.
		variant = strchr(copy, '+');
		file = variant ? strchr(variant, ':') : NULL;
		if (!file || !variant || variant > file) {
			out("R %s %d 0\n", tok[i], 300 + EINVAL);
			continue;
		}
		*file++ = 0;
		*variant++ = 0;
		code = run_token(creator, variant, file, &pid);
		out("R %s %d %d\n", tok[i], code, pid);
	}
}

// -------------------------------------------------------------------- stage

static int join_cgroup(const char *dir)
{
	char path[PATH_MAX];
	int fd, rc;

	snprintf(path, sizeof(path), "%s/cgroup.procs", dir);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	rc = write(fd, "0", 1) == 1 ? 0 : -1;
	close(fd);
	return rc;
}

static int stage(void)
{
	char line[8192], *tok[256];
	int go[2], joined[2], n, status;
	pid_t pid;
	char c;

	setup_fixtures();
	while (fgets(line, sizeof(line), stdin)) {
		n = 0;
		for (char *s = strtok(line, " \n"); s && n < 256; s = strtok(NULL, " \n"))
			tok[n++] = s;
		if (!n)
			continue;
		if (!strcmp(tok[0], "QUIT"))
			break;
		if (strcmp(tok[0], "SPAWN") || n < 3) {
			out("ERR bad command\n");
			continue;
		}
		if (pipe2(go, O_CLOEXEC) || pipe2(joined, O_CLOEXEC))
			die("pipe");
		pid = fork();
		if (pid < 0)
			die("fork");
		if (!pid) {
			close(go[1]);
			close(joined[0]);
			c = 'j';
			if (strcmp(tok[1], "-") && join_cgroup(tok[1]))
				c = 'e';
			if (write(joined[1], &c, 1) != 1 || c == 'e')
				_exit(72);
			if (read(go[0], &c, 1) != 1)
				_exit(73);
			close(go[0]);
			close(joined[1]);
			srand(getpid());
			run_tokens(n - 2, tok + 2);
			_exit(0);
		}
		close(go[0]);
		close(joined[1]);
		if (read(joined[0], &c, 1) != 1 || c != 'j') {
			out("ERR join %s\n", tok[1]);
			kill(pid, SIGKILL);
			waitpid(pid, &status, 0);
			close(go[1]);
			close(joined[0]);
			continue;
		}
		close(joined[0]);
		out("PID %d\n", pid);
		if (!fgets(line, sizeof(line), stdin) || strncmp(line, "GO", 2)) {
			kill(pid, SIGKILL);
			waitpid(pid, &status, 0);
			close(go[1]);
			out("ERR expected GO\n");
			continue;
		}
		c = 'g';
		if (write(go[1], &c, 1) != 1) {
		}
		close(go[1]);
		while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
		}
		out("DONE %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : 1000 + WTERMSIG(status));
	}
	cleanup_binfmt();
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 2 && !strcmp(argv[1], "ee-selfqual-stage"))
		return stage();
	// Product-engine adapter modes: fixtures in an existing directory (no
	// private mount, no binfmt_misc), and one token run without a stage, for
	// an engine whose probe root must descend from the binding's init.
	if (argc >= 3 && !strcmp(argv[1], "ee-selfqual-fixtures")) {
		snprintf(fixture_dir, sizeof(fixture_dir), "%s", argv[2]);
		if (chdir(fixture_dir))
			die("chdir");
		build_fixtures();
		return 0;
	}
	// E1: a script's interpreter gets argv {interp, script, args...}.
	if (argc >= 4 && !strcmp(argv[2], "ee-selfqual-run")) {
		argv++;
		argc--;
	}
	if (argc >= 3 && !strcmp(argv[1], "ee-selfqual-run")) {
		snprintf(fixture_dir, sizeof(fixture_dir), "%s", argv[2]);
		if (chdir(argv[2]))
			die("chdir");
		srand(getpid());
		run_tokens(argc - 3, argv + 3);
		return 0;
	}
	if (!getenv("EESQ_QUIET"))
		out("T %d\n", getpid());
	return 0;
}
