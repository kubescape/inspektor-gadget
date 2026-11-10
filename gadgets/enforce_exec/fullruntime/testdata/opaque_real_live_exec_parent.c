// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
// Disposable single-threaded parent. The first exec qualifies the synthetic
// charged TASK; the second exec is observed by the real opaque reader.
// SPAWN/REAP also work before that second exec for the strict TASK quota test.
#define _GNU_SOURCE
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_clone3
#define SYS_clone3 435
#endif
/* clone3 ABI (include/uapi/linux/sched.h, CLONE_ARGS_SIZE_VER2). */
struct opaque_clone_args {
	uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack,
		stack_size, tls, set_tid, set_tid_size, cgroup;
};
#define OPAQUE_CLONE_INTO_CGROUP 0x200000000ULL

/* Thread churn (opaque_thread_churn.c): each pthread birth is one real
 * task_alloc charged to this parent; the thread only proves it ran. */
static void *thread_run(void *opaque)
{
	*(int *)opaque = 1;
	return 0;
}

/* Sequential create/join of n threads; returns created count, stores the
 * first pthread_create error in *err (0: none). Exits 87 if join fails. */
static int thread_round(int n, int *err)
{
	int created = 0;
	*err = 0;
	for (int i = 0; i < n; i++) {
		pthread_t thread;
		int observed = 0;
		int rc = pthread_create(&thread, 0, thread_run, &observed);
		if (rc) {
			if (!*err)
				*err = rc;
			continue;
		}
		if (pthread_join(thread, 0) || observed != 1)
			exit(87);
		created++;
	}
	return created;
}

/* Child exec exit codes: 77 EPERM, 79 EACCES (prior LSM denial), 94 other. */
static int exec_true_exit(void)
{
	execl("/bin/true", "true", (char *)0);
	return errno == EPERM ? 77 : errno == EACCES ? 79 : 94;
}

static int64_t mono_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Reaps every exited child (blocking for the first one if block) and prints
 * its FORKED line; returns the number reaped. Exits 93 on a wait error. */
static int reap_exited(int block)
{
	int reaped = 0, status = 0;
	pid_t pid;
	while ((pid = waitpid(-1, &status, block && !reaped ? 0 : WNOHANG)) > 0) {
		printf("FORKED:%d:%d\n", pid,
		       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		reaped++;
	}
	if (pid < 0 && errno != ECHILD)
		exit(93);
	if (reaped)
		fflush(stdout);
	return reaped;
}

/* FORKP:<n>:<k>:<interval_ns>: n child births/execs paced open loop on an
 * absolute CLOCK_MONOTONIC schedule (birth i is due at t0 + i*interval). Only
 * the stream cap can delay a birth: at most k children are live, so a due
 * birth waits for one exit while k run (cap_waits). A late birth starts at
 * once; the schedule is never reset. Children are reaped on SIGCHLD, so a
 * zombie never delays the final free. One FORKED line per birth in exit order
 * (a refused fork at once), then PACED:<span_ns first..last fork>:
 * <max_late_ns>:<sum_late_ns>:<cap_waits>. */
static void forkp(int n, int k, int64_t interval)
{
	sigset_t chld, old;
	sigemptyset(&chld);
	sigaddset(&chld, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &chld, &old))
		exit(80);
	int running = 0, waits = 0;
	int64_t t0 = mono_ns(), first = 0, last = 0, max_late = 0, sum_late = 0;
	for (int i = 0; i < n; i++) {
		int64_t due = t0 + (int64_t)i * interval;
		int waited = 0;
		for (;;) {
			running -= reap_exited(0);
			int64_t now = mono_ns();
			if (now >= due && running < k)
				break;
			struct timespec ts, *timeout = 0;
			if (now < due) {
				ts.tv_sec = (due - now) / 1000000000LL;
				ts.tv_nsec = (due - now) % 1000000000LL;
				timeout = &ts;
			} else if (!waited) {
				waited = 1;
				waits++;
			}
			if (sigtimedwait(&chld, 0, timeout) < 0 && errno != EAGAIN &&
			    errno != EINTR)
				exit(80);
		}
		int64_t now = mono_ns();
		pid_t child = fork();
		int fork_errno = errno;
		if (child == 0) {
			sigprocmask(SIG_SETMASK, &old, 0);
			_exit(exec_true_exit());
		}
		if (i == 0)
			first = now;
		last = now;
		max_late = now - due > max_late ? now - due : max_late;
		sum_late += now - due;
		if (child < 0) {
			printf("FORKED:-1:%d\n", fork_errno);
			fflush(stdout);
		} else {
			running++;
		}
	}
	while (running > 0)
		running -= reap_exited(1);
	sigprocmask(SIG_SETMASK, &old, 0);
	printf("PACED:%lld:%lld:%lld:%d\n", (long long)(last - first),
	       (long long)max_late, (long long)sum_late, waits);
	fflush(stdout);
}

/* Reads at most size-1 bytes of path into buf (NUL-terminated). */
static int read_small(const char *path, char *buf, size_t size)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, size - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	return (int)n;
}

static int write_small(const char *path, const char *buf, size_t len)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	ssize_t n = write(fd, buf, len);
	close(fd);
	return n == (ssize_t)len ? 0 : -1;
}

/* One fork under pids.max == pids.current, then pids.max restored. Exits
 * 85 if the window cannot be set up and 84 if pids.max cannot be restored. */
static pid_t pids_window_fork(int *fork_errno)
{
	const char *cgroup = getenv("IG_OPAQUE_PIDS_CGROUP");
	char max_path[512], current_path[512], original[64], current[64];
	if (!cgroup ||
	    snprintf(max_path, sizeof(max_path), "%s/pids.max", cgroup) >=
		    (int)sizeof(max_path) ||
	    snprintf(current_path, sizeof(current_path), "%s/pids.current",
		     cgroup) >= (int)sizeof(current_path))
		exit(85);
	int original_len = read_small(max_path, original, sizeof(original));
	int current_len = read_small(current_path, current, sizeof(current));
	if (original_len < 0 || current_len < 0 ||
	    write_small(max_path, current, (size_t)current_len))
		exit(85);
	pid_t child = fork();
	*fork_errno = child < 0 ? errno : 0;
	if (child == 0)
		_exit(exec_true_exit());
	if (write_small(max_path, original, (size_t)original_len))
		exit(84);
	return child;
}

/* G025 step 7: the second disposable cgroup (IG_OPAQUE_MIGRATE_CGROUP).
 * Exits 85 if it is missing. */
static const char *migrate_target(char *procs, size_t size)
{
	const char *target = getenv("IG_OPAQUE_MIGRATE_CGROUP");
	if (!target ||
	    snprintf(procs, size, "%s/cgroup.procs", target) >= (int)size)
		exit(85);
	return target;
}

static int move_pid(const char *procs, pid_t pid)
{
	char text[32];
	int len = snprintf(text, sizeof(text), "%d", (int)pid);
	return write_small(procs, text, (size_t)len);
}

static int wait_exit(pid_t child)
{
	int status = 0;
	if (waitpid(child, &status, 0) != child)
		exit(93);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Mid-exec migration (G023 capsule fixture technique): hold the script
 * interpreter's FAN_OPEN_EXEC_PERM, i.e. after the script's admission and
 * before the interpreter's admission of the SAME exec, move the child to the
 * second cgroup, then allow. The child reports the script exec errno (0 when
 * the script ran) and then performs one fresh exec of /bin/true.
 * MIGRATED:<pid>:<held 1, move failed -1, never held 0>:<errno>:<exit>. */
static int migrate_mid_exec(void)
{
	char procs[512];
	(void)migrate_target(procs, sizeof(procs));
	const char *script_path = getenv("IG_OPAQUE_MIGRATE_SCRIPT");
	const char *interp = getenv("IG_OPAQUE_MIGRATE_INTERP");
	int report[2];
	if (!script_path || !interp || pipe2(report, O_CLOEXEC))
		return 85;
	int fan = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC,
				O_RDONLY | O_LARGEFILE);
	if (fan < 0 || fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN_EXEC_PERM,
				     AT_FDCWD, interp))
		return 82;
	pid_t child = fork();
	if (child < 0)
		return 95;
	if (child == 0) {
		close(report[0]);
		close(fan);
		execl(script_path, "opaque-migrate-script", (char *)0);
		int first = errno;
		if (write(report[1], &first, sizeof(first)) != sizeof(first))
			_exit(81);
		_exit(exec_true_exit());
	}
	close(report[1]);
	int held = 0, exited = 0, status = 0;
	for (int round = 0; round < 2000 && !held && !exited; round++) {
		struct pollfd p = { .fd = fan, .events = POLLIN };
		int ready = poll(&p, 1, 10);
		if (ready < 0 && errno != EINTR)
			return 80;
		if (ready > 0) {
			struct fanotify_event_metadata m;
			ssize_t n = read(fan, &m, sizeof(m));
			if (n < (ssize_t)sizeof(m) ||
			    m.vers != FANOTIFY_METADATA_VERSION)
				return 80;
			if (m.fd >= 0) {
				if ((m.mask & FAN_OPEN_EXEC_PERM) &&
				    m.pid == child)
					held = move_pid(procs, child) ? -1 : 1;
				struct fanotify_response r = {
					.fd = m.fd, .response = FAN_ALLOW
				};
				if (write(fan, &r, sizeof(r)) != sizeof(r))
					return 80;
				close(m.fd);
			}
		}
		if (!held && waitpid(child, &status, WNOHANG) == child)
			exited = 1;
	}
	/* Closing the group allows any still-pending permission event. */
	close(fan);
	int code = exited ? (WIFEXITED(status) ? WEXITSTATUS(status) : -1) :
			    wait_exit(child);
	int first = 0;
	if (read(report[0], &first, sizeof(first)) != sizeof(first))
		first = 0;
	close(report[0]);
	printf("MIGRATED:%d:%d:%d:%d\n", child, held, first, code);
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	/* The grandparent mode is reached by a real exec, not a fork-only
	 * inherited helper. Its descendant therefore exercises qualified history. */
	if (argc == 2 && !strcmp(argv[1], "grandparent")) {
		pid_t child = fork();
		if (child < 0)
			return 95;
		if (child == 0) {
			execl("/bin/true", "true", (char *)0);
			_exit(94);
		}
		int status = 0;
		if (waitpid(child, &status, 0) != child)
			return 93;
		return WIFEXITED(status) ? WEXITSTATUS(status) : 92;
	}
	const char *script = getenv("IG_OPAQUE_SCRIPT_PATH");
	int interpreted = argc == 2 && script && !strcmp(argv[1], script);
	if (argc > 2 || (argc == 2 && strcmp(argv[1], "after") && !interpreted))
		return 99;
	puts(argc == 2 ? "AFTER" : "READY");
	fflush(stdout);
	char line[32];
	pid_t held[64] = {};
	int live = 0;
	while (fgets(line, sizeof(line), stdin)) {
		if (!strcmp(line, "DONE\n"))
			return 0;
		if (argc == 1 && !strcmp(line, "UIDS\n")) {
			const char *enabled = getenv("IG_OPAQUE_EFFECTIVE_UID_DIVERGENCE");
			if (!enabled || strcmp(enabled, "1") ||
			    setresuid(1000, 0, 0) || getuid() != 1000 || geteuid() != 0)
				return 89;
			printf("UIDS:%ld\n", (long)getpid());
			fflush(stdout);
			continue;
		}
		if (argc == 1 && !strcmp(line, "EXEC\n")) {
			execl("/proc/self/exe", "opaque-real-parent", "after", (char *)0);
			return 97;
		}
		if (argc == 1 && !strcmp(line, "SCRIPT\n")) {
			if (!script)
				return 94;
			/* Direct exec: the kernel invokes this binary as the shebang
			 * interpreter within the same exec syscall. */
			execl(script, "opaque-script", (char *)0);
			return 97;
		}
		if (!strcmp(line, "FAIL\n")) {
			const char *path = getenv("IG_OPAQUE_FAIL_EXEC_PATH");
			if (!path)
				return 94;
			execl(path, "opaque-invalid-exec", (char *)0);
			printf("FAILED:%d\n", errno);
			fflush(stdout);
			continue;
		}
		/* Verdict diagnostic: the child drops to uid 1000 before exec, so
		 * an effective-UID-0 rule does not match. Exit 77 means the exec
		 * was refused with EPERM (policy-caused in the Strict control). */
		int count = 0, threads = 0;
		/* THREADS:<n>: n sequential pthread births in this parent. */
		if (sscanf(line, "THREADS:%d\n", &count) == 1) {
			if (count < 1 || count > 1024)
				return 86;
			int err = 0;
			int created = thread_round(count, &err);
			printf("THREADED:%d:%d\n", created, err);
			fflush(stdout);
			continue;
		}
		/* PIN:<cpu>: pin this parent, and so every later child, to one
		 * CPU (physical-reuse test: SLUB per-CPU freelists are LIFO);
		 * PIN:-1 restores the mask saved by the first PIN.
		 * PINNED:<cpu>:<errno>. */
		int cpu = 0;
		if (sscanf(line, "PIN:%d\n", &cpu) == 1) {
			static cpu_set_t saved;
			static int have_saved;
			int err = 0;
			if (cpu >= CPU_SETSIZE || cpu < -1) {
				err = EINVAL;
			} else if (cpu >= 0) {
				cpu_set_t one;
				CPU_ZERO(&one);
				CPU_SET(cpu, &one);
				if (!have_saved &&
				    sched_getaffinity(0, sizeof(saved), &saved))
					err = errno;
				else if (sched_setaffinity(0, sizeof(one), &one))
					err = errno;
				else
					have_saved = 1;
			} else if (!have_saved) {
				err = EINVAL;
			} else if (sched_setaffinity(0, sizeof(saved), &saved)) {
				err = errno;
			}
			printf("PINNED:%d:%d\n", cpu, err);
			fflush(stdout);
			continue;
		}
		/* FORKE: one child that exits at once without exec: exactly one
		 * TASK and one birth WORK, no evaluation and no terminal. */
		if (!strcmp(line, "FORKE\n")) {
			pid_t child = fork();
			if (child < 0) {
				printf("FORKED:-1:%d\n", errno);
				fflush(stdout);
				continue;
			}
			if (child == 0)
				_exit(0);
			printf("FORKED:%d:%d\n", child, wait_exit(child));
			fflush(stdout);
			continue;
		}
		long long interval = 0;
		if (sscanf(line, "FORKP:%d:%d:%lld\n", &count, &threads,
			   &interval) == 3) {
			/* waitpid(-1) must only see paced children. */
			if (count < 1 || count > 65536 || threads < 1 ||
			    threads > 8 || interval < 1000 ||
			    interval > 1000000000LL || live)
				return 86;
			forkp(count, threads, interval);
			continue;
		}
		/* FORKN:<k>:<t>[:<f>]: k racing child births/execs, then t thread
		 * births while those children run. A refused fork reports pid -1
		 * and its errno instead of an exit code. With f=1, one extra fork
		 * runs while the k children are still unreaped (they hold their
		 * pids charge) under pids.max == pids.current of this cgroup
		 * (IG_OPAQUE_PIDS_CGROUP), so it fails in cgroup_can_fork after
		 * security_task_alloc; pids.max is restored before anything else
		 * forks. It reports FAILBIRTH:<pid or -1>:<errno or exit>. */
		int failing = 0;
		int fields = sscanf(line, "FORKN:%d:%d:%d\n", &count, &threads,
				    &failing);
		if (fields == 2)
			failing = 0;
		if (fields >= 2) {
			if (count < 1 || count > 8 || threads < 0 || threads > 8 ||
			    failing < 0 || failing > 1)
				return 86;
			pid_t kids[8];
			int fork_errno[8];
			for (int k = 0; k < count; k++) {
				kids[k] = fork();
				fork_errno[k] = kids[k] < 0 ? errno : 0;
				if (kids[k] == 0)
					_exit(exec_true_exit());
			}
			pid_t failed = 0;
			int failed_errno = 0;
			if (failing)
				failed = pids_window_fork(&failed_errno);
			int err = 0;
			int created = thread_round(threads, &err);
			for (int k = 0; k < count; k++) {
				if (kids[k] < 0) {
					printf("FORKED:-1:%d\n", fork_errno[k]);
					continue;
				}
				int status = 0;
				if (waitpid(kids[k], &status, 0) != kids[k])
					return 93;
				printf("FORKED:%d:%d\n", kids[k],
				       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
			}
			if (failing && failed < 0) {
				printf("FAILBIRTH:-1:%d\n", failed_errno);
			} else if (failing) {
				int status = 0;
				if (waitpid(failed, &status, 0) != failed)
					return 93;
				printf("FAILBIRTH:%d:%d\n", failed,
				       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
			}
			printf("THREADED:%d:%d\n", created, err);
			fflush(stdout);
			continue;
		}
		/* FORKA: a fork the test expects to fail after task_alloc (pids.max);
		 * a refusal reports FORKED:-1:<errno>. */
		if (!strcmp(line, "FORKA\n")) {
			pid_t child = fork();
			if (child < 0) {
				printf("FORKED:-1:%d\n", errno);
				fflush(stdout);
				continue;
			}
			if (child == 0)
				_exit(exec_true_exit());
			int status = 0;
			if (waitpid(child, &status, 0) != child)
				return 93;
			printf("FORKED:%d:%d\n", child,
			       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
			fflush(stdout);
			continue;
		}
		/* Two concurrently racing child births and execs. */
		if (!strcmp(line, "FORK2\n")) {
			pid_t kids[2];
			for (int k = 0; k < 2; k++) {
				kids[k] = fork();
				if (kids[k] < 0)
					return 95;
				if (kids[k] == 0) {
					execl("/bin/true", "true", (char *)0);
					/* 77 = EPERM (policy or fail-closed refusal); 94
					 * = any other errno, distinguished in G025. */
					_exit(errno == EPERM ? 77 : 94);
				}
			}
			for (int k = 0; k < 2; k++) {
				int status = 0;
				if (waitpid(kids[k], &status, 0) != kids[k])
					return 93;
				printf("FORKED:%d:%d\n", kids[k],
				       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
			}
			fflush(stdout);
			continue;
		}
		/* Child exec of an invalid image: exit 78 means ENOEXEC. */
		if (!strcmp(line, "FORKF\n")) {
			const char *path = getenv("IG_OPAQUE_FAIL_EXEC_PATH");
			if (!path)
				return 94;
			pid_t child = fork();
			if (child < 0)
				return 95;
			if (child == 0) {
				execl(path, "opaque-invalid-exec", (char *)0);
				_exit(errno == ENOEXEC ? 78 : 94);
			}
			int status = 0;
			if (waitpid(child, &status, 0) != child)
				return 93;
			printf("FORKED:%d:%d\n", child,
			       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
			fflush(stdout);
			continue;
		}
		if (!strcmp(line, "FORKU\n")) {
			pid_t child = fork();
			if (child < 0)
				return 95;
			if (child == 0) {
				if (setresuid(1000, 1000, 1000))
					_exit(88);
				execl("/bin/true", "true", (char *)0);
				_exit(errno == EPERM ? 77 : 94);
			}
			int status = 0;
			if (waitpid(child, &status, 0) != child)
				return 93;
			printf("FORKED:%d:%d\n", child,
			       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
			fflush(stdout);
			continue;
		}
		/* The staged bprm diagnostic keeps the original qualified parent
		 * unquarantined while each forked child performs its own exec. */
		if (!strcmp(line, "FORK\n") || !strcmp(line, "GRAND\n")) {
			pid_t child = fork();
			if (child < 0)
				return 95;
			if (child == 0) {
				if (!strcmp(line, "GRAND\n")) {
					execl("/proc/self/exe", "opaque-real-parent", "grandparent", (char *)0);
					_exit(94);
				}
				_exit(exec_true_exit());
			}
			int status = 0;
			if (waitpid(child, &status, 0) != child)
				return 93;
			printf("FORKED:%d:%d\n", child,
			       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
			fflush(stdout);
			continue;
		}
		/* FORKMIX:<k>: k racing children; even ones exec as euid 0 (the
		 * matching rule), odd ones as uid 1000 (the policy fallback). */
		if (sscanf(line, "FORKMIX:%d\n", &count) == 1) {
			if (count < 1 || count > 8)
				return 86;
			pid_t kids[8];
			int fork_errno[8];
			for (int k = 0; k < count; k++) {
				kids[k] = fork();
				fork_errno[k] = kids[k] < 0 ? errno : 0;
				if (kids[k] == 0) {
					if ((k & 1) && setresuid(1000, 1000, 1000))
						_exit(88);
					_exit(exec_true_exit());
				}
			}
			for (int k = 0; k < count; k++) {
				if (kids[k] < 0)
					printf("FORKED:-1:%d\n", fork_errno[k]);
				else
					printf("FORKED:%d:%d\n", kids[k],
					       wait_exit(kids[k]));
			}
			fflush(stdout);
			continue;
		}
		/* MIGRATEF: the child is born here, moved to the second cgroup
		 * between fork and exec, then execs /bin/true. */
		if (!strcmp(line, "MIGRATEF\n")) {
			char procs[512];
			int gate[2];
			(void)migrate_target(procs, sizeof(procs));
			if (pipe2(gate, O_CLOEXEC))
				return 85;
			pid_t child = fork();
			if (child < 0)
				return 95;
			if (child == 0) {
				char go = 0;
				close(gate[1]);
				if (read(gate[0], &go, 1) != 1 || go != 'G')
					_exit(83);
				_exit(exec_true_exit());
			}
			close(gate[0]);
			int moved = !move_pid(procs, child);
			if (write(gate[1], moved ? "G" : "X", 1) != 1)
				return 91;
			close(gate[1]);
			printf("FORKED:%d:%d\n", child, wait_exit(child));
			fflush(stdout);
			continue;
		}
		/* MIGRATEB: migration during birth. clone3(CLONE_INTO_CGROUP)
		 * runs security_task_alloc on this parent (first cgroup), then
		 * places the child in the second cgroup in cgroup_can_fork. */
		if (!strcmp(line, "MIGRATEB\n")) {
			char procs[512];
			const char *target = migrate_target(procs, sizeof(procs));
			int fd = open(target, O_DIRECTORY | O_PATH | O_CLOEXEC);
			if (fd < 0)
				return 85;
			struct opaque_clone_args args = {
				.flags = OPAQUE_CLONE_INTO_CGROUP,
				.exit_signal = SIGCHLD,
				.cgroup = (uint64_t)fd,
			};
			long child = syscall(SYS_clone3, &args, sizeof(args));
			if (child == 0)
				_exit(exec_true_exit());
			int clone_errno = errno;
			close(fd);
			if (child < 0)
				printf("FORKED:-1:%d\n", clone_errno);
			else
				printf("FORKED:%ld:%d\n", child,
				       wait_exit((pid_t)child));
			fflush(stdout);
			continue;
		}
		if (!strcmp(line, "MIGRATEX\n")) {
			int failed = migrate_mid_exec();
			if (failed)
				return failed;
			continue;
		}
		if (!strcmp(line, "SPAWN\n")) {
			if (live >= 64)
				return 92;
			pid_t child = fork();
			if (child < 0) {
				printf("SPAWNFAIL:%d\n", errno);
				fflush(stdout);
				continue;
			}
			if (child == 0) {
				for (;;)
					pause();
			}
			held[live++] = child;
			printf("SPAWNED:%d\n", child);
			fflush(stdout);
			continue;
		}
		if (!strcmp(line, "REAP\n")) {
			for (int i = 0; i < live; i++) {
				if (kill(held[i], SIGTERM))
					return 91;
				int status = 0;
				if (waitpid(held[i], &status, 0) != held[i] ||
				    !WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM)
					return 90;
			}
			printf("REAPED:%d\n", live);
			fflush(stdout);
			live = 0;
			continue;
		}
		return 96;
	}
	return 98;
}
