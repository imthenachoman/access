/*
 * access -- authenticator for Unix systems.
 *
 * access is copyrighted:
 * Copyright (C) 2014-2018 Andrey Rys. All rights reserved.
 *
 * access is licensed to you under the terms of std. MIT/X11 license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "access.h"

static int xexecvpe(const char *file, char *const argv[], char *const envp[])
{
	int r;
	char **svenv = environ;

	environ = (char **)envp;
	r = execvp(file, argv);
	if (r == -1) environ = svenv;
	return r;
}

int forkexec(int vp, const char *path, char *const argv[], char *const envp[], pid_t *svpid, int *pfd, char *progmsg, size_t pmsgl)
{
	pid_t pid;
	int epfd[2];
	int x, y;
	size_t n;

	if (!path || str_empty(path)) return -1;

	if (pipe(epfd) != 0) return -1;
	fcntl(epfd[0], F_SETFD, fcntl(epfd[0], F_GETFD) | FD_CLOEXEC);
	fcntl(epfd[1], F_SETFD, fcntl(epfd[1], F_GETFD) | FD_CLOEXEC);

	pid = fork();
	switch (pid) {
		case -1:
			close(epfd[0]);
			close(epfd[1]);
			return -1;
			break;
		case 0:
			if (pfd) close(pfd[0]);
			clear_environ();
			close(epfd[0]);
			if (vp) x = xexecvpe(path, argv, envp);
			else x = execve(path, argv, envp);
			if (x == -1) write(epfd[1], &errno, sizeof(errno));
			close(epfd[1]);
			if (pfd) close(pfd[1]);
			exit(127);
			break;
		default:
			if (svpid) *svpid = pid;
			signal(SIGCHLD, SIG_DFL);
			x = 0;
			close(epfd[1]);
			while (read(epfd[0], &x, sizeof(errno)) != -1)
				if (errno != EAGAIN && errno != EINTR) break;
			close(epfd[0]);
			if (x) {
				close(pfd[0]);
				close(pfd[1]);
				errno = x;
				return -1;
			}
			x = y = -1;
			if (pfd) {
				close(pfd[1]);
				while (1) {
					n = (size_t)read(pfd[0], progmsg, pmsgl);
					if (n == NOSIZE || n == 0) break;
				}
				close(pfd[0]);
			}
			if (waitpid(pid, &x, 0) == -1) return -1;
			if (WIFEXITED(x)) y = WEXITSTATUS(x);
			signal(SIGCHLD, SIG_IGN);
			if (y) return y;
			break;
	}
	return 0;
}

int dexecve(const char *path, char *const argv[], pid_t *pid)
{
	pid_t idp;
	int pfd[2];
	int x;

	if (!path || str_empty(path)) return -1;

	if (pipe(pfd) != 0) return -1;
	fcntl(pfd[0], F_SETFD, fcntl(pfd[0], F_GETFD) | FD_CLOEXEC);
	fcntl(pfd[1], F_SETFD, fcntl(pfd[1], F_GETFD) | FD_CLOEXEC);

	idp = fork();
	switch (idp) {
		case -1:
			goto _fail;
			break;
		case 0:
			if (setsid() < 0) goto _fail;
			close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDWR);
			open("/dev/null", O_RDWR);
			open("/dev/null", O_RDWR);
			close(pfd[0]);
			if (execve(path, argv, environ) == -1)
				write(pfd[1], &errno, sizeof(errno));
			close(pfd[1]);
			exit(127);

			break;
		default:
			x = 0;
			if (pid) *pid = idp;
			close(pfd[1]);
			while (read(pfd[0], &x, sizeof(errno)) != -1)
				if (errno != EAGAIN && errno != EINTR) break;
			close(pfd[0]);
			if (x) {
				errno = x;
				return -1;
			}
			break;
	}

	return 0;

_fail:
	close(pfd[0]);
	close(pfd[1]);
	return -1;
}

/*
 * Our endpoint replacer: after all work is done,
 * and uids are changed, I (in a completely new environment)
 * can safely replace ourself with target program (if it exists)
 *
 * The only exception here is dexecve(), which returns.
 */

int execute(const char *p, char *const argv[], pid_t *bgpid)
{
	int r;

	if (isflag(argflags, ARG_b)) {
		r = dexecve(p, argv, bgpid);
		signal(SIGCHLD, SIG_IGN); /* Have I a chance to escape quicker
					 than spawned process exits?
					 Even if not, signal_handler() will acs_exit() on CHLD */
	}
	else r = execve(p, argv, environ);
	return r;
}
