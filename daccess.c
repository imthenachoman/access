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

#ifdef WITH_DACCESS_PROG

/*
 * daccess - helper daemon to ease access life on setuid crippled systems.
 * daccess can be either a (master) server, which spawns setuid program
 * specified by the cmdline, and the rest of cmdline is added by client,
 * or a client, which drops setuid privileges if any and tries to connect
 * to server, send all it's args/environ/file descriptors opened and
 * server spawns the program in the transferred environment then.
 * daccess can accept multiple clients, locally, from different user privileges,
 * if access to a socket is permitted of course to them.
 *
 * Original purpose of daccess was to run on such systems where plain setuid
 * filesystem bit was disabled either for security reasons or just no setuid
 * binaries are existing on the system (or the underlying FS does not support them).
 * An example of such system is android 4.3 and laters, where devs decided to
 * use SELinux for some stupid reason. On such (rooted) system, a server is
 * required which will spawn setuid program manually.
 * Other systems of interest are mainly those where no presence of setuid binaries
 * is desired, or where FS does not support even this ancient access bit.
 */

#ifndef WITH_SKEIN_CRYPT
#error Skein is required by daccess!
#endif
#include "tf1024.h"

static int daccess_serverfd = -1, daccess_clfd = -1;
static int daccess_retval;
static char *daccess_sockname;
static int daccess_nargc;
static char **daccess_nargv, **daccess_orig_argv;
static int daccess_server;
static int daccess_nodaemon;
static int daccess_nostatus;

static char *daccess_password;

static void daccess_closefd(int fd);

static void daccess_daemonise(void)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) xerror("daemonise: fork");
	if (pid > 0) acs_exit(0);

	if (setsid() == -1) xerror("daemonise: setsid");

	close(0);
	close(1);
	close(2);
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);
}

static void daccess_server_exit(int status)
{
	daccess_closefd(daccess_clfd);
	daccess_closefd(daccess_serverfd);
	unlink(daccess_sockname);
	acs_exit(status);
}

static void daccess_closefd(int fd)
{
	shutdown(fd, SHUT_RDWR);
	close(fd);
}

struct ptsinfo {
	int ptsfd;
	char *ptsname;
};

static int daccess_getpts(struct ptsinfo *ptsi)
{
	char *s;

	ptsi->ptsfd = open(ptsi->ptsname, O_RDWR | O_NOCTTY);
	if (ptsi->ptsfd != -1) {
		grantpt(ptsi->ptsfd);
		unlockpt(ptsi->ptsfd);
		s = ptsname(ptsi->ptsfd);
		if (s) ptsi->ptsname = acs_strdup(s);
		else {
			close(ptsi->ptsfd);
			ptsi->ptsfd = -1;
			return 0;
		}
	}
	else return 0;

	return 1;
}

static void daccess_closestd(int *start)
{
	if (!start) {
		close(0);
		close(1);
		close(2);
	}
	else {
		close(*(start));
		close(*(start+1));
		close(*(start+2));
	}
}

static int daccess_valid_fd(int fd)
{
	if (fcntl(fd, F_GETFD) == -1
	&& errno == EBADF) return 0;
	return 1;
}

static int daccess_fdtofd(int *from, int *to, int n)
{
	int x;

	for (x = 0; x < n; x++) {
		/* do nothing */
		if (*(from+x) == *(to+x)) continue;
		/* already exists? */
		if (daccess_valid_fd(*(to+x))) return 0;
		if (dup2(*(from+x), *(to+x)) == -1) return 0;
		close(*(from+x));
	}

	return 1;
}

static int daccess_randfd(int fd)
{
	int newfd, maxfd;

	maxfd = sysconf(_SC_OPEN_MAX);
_again:	newfd = (int)acs_randrange(fd+1, maxfd);
	if (daccess_valid_fd(newfd)) goto _again;
	if (!daccess_fdtofd(&fd, &newfd, 1)) return -1;

	return newfd;
}

struct pidcreds {
	uid_t ruid, euid;
	gid_t rgid, egid;
	int ngids;
	gid_t *gids;
};

static void freepidcreds(struct pidcreds *pcred)
{
	if (pcred->gids) pfree(pcred->gids);
	memset(pcred, 0, sizeof(struct pidcreds));
}

static int getpidcreds(pid_t pid, struct pidcreds *pcred)
{
	FILE *f = NULL;
	int uidread = 0, gidread = 0, groupsread = 0;
	size_t x;
	char *str = NULL;
	int r = 0;

	/* read /proc/pid/status and fill struct */
	acs_asprintf(&str, "/proc/%u/status", pid);
	f = fopen(str, "rb");
	str = acs_realloc(str, ACS_ALLOC_SMALL);
	if (!f) {
		if (errno == ENOENT) errno = ESRCH;
		goto _err;
	}
	while (1) {
		if (uidread && gidread && groupsread) break;
		if (acs_fgets(str, ACS_ALLOC_SMALL, f) == NOSIZE) break;
		if (!strncmp(str, "Uid:", 4)) {
			x = sscanf(str+4, "\t%u\t%u", &pcred->ruid, &pcred->euid);
			if (x < 2) goto _err;
			uidread = 1;
			r += x;
		}
		if (!strncmp(str, "Gid:", 4)) {
			x = sscanf(str+4, "\t%u\t%u", &pcred->rgid, &pcred->egid);
			if (x < 2) goto _err;
			gidread = 1;
			r += x;
		}
		if (!strncmp(str, "Groups:", 7)) {
			char *s, *d, *t;
			s = d = str+8;
			x = 0;

			if (str_empty(s)) {
				groupsread = 1;
				pcred->gids = NULL;
				pcred->ngids = 0;
				break;
			}

			pcred->gids = NULL;
			while ((s = acs_strtok_r(d, " ", &t))) {
				if (d) d = NULL;

				x = DYN_ARRAY_SZ(pcred->gids);
				pcred->gids = acs_realloc(pcred->gids, (x+1) * sizeof(gid_t));
				pcred->gids[x] = (gid_t)atoi(s);
			}

			groupsread = 1;
			x = DYN_ARRAY_SZ(pcred->gids);
			pcred->ngids = x;
			r += x;
		}
	}

	if (!uidread || !gidread || !groupsread) goto _err;
	if (f) fclose(f);
	pfree(str);

	return r;

_err:
	if (f) fclose(f);
	freepidcreds(pcred);
	pfree(str);

	return -1;
}

static void defuse_pcreds(struct pidcreds *pcred)
{
	pcred->euid = pcred->ruid;
	pcred->egid = pcred->rgid;
}

static void setpidcreds(struct pidcreds *pcred)
{
	if (setgroups(pcred->ngids, pcred->gids) == -1) xerror("setgroups");
#ifdef HAVE_SETRESID
	if (setresgid(pcred->rgid, pcred->egid, pcred->egid) == -1) xerror("setresgid");
	if (setresuid(pcred->ruid, pcred->euid, pcred->euid) == -1) xerror("setresuid");
#else
	if (setregid(pcred->rgid, pcred->egid) == -1) xerror("setregid");
	if (setreuid(pcred->ruid, pcred->euid) == -1) xerror("setreuid");
#endif
}

static void daccess_cloexec(int fd)
{
	if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC) == -1)
		xerror("cloexec on %d", fd);
}

static void daccess_reap_children(int s)
{
	if (s == SIGCHLD) waitpid(-1, NULL, WNOHANG);
}

static int create_serv_socket(const char *sockname)
{
	struct sockaddr_un sun;
	int svfd;

	acs_memzero(&sun, sizeof(struct sockaddr_un));
	sun.sun_family = AF_UNIX;
	unlink(sockname);
	acs_strlcpy(sun.sun_path, sockname, sizeof(sun.sun_path));
	svfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (svfd == -1) xerror("socket of %s", sockname);
	if (bind(svfd, (struct sockaddr *) &sun, sizeof(struct sockaddr_un)) == -1)
		xerror("bind to %s", sockname);
	if (listen(svfd, 128) == -1) xerror("listen on %s", sockname);
	chmod(sockname, 0666);

	return svfd;
}

static int create_client_socket(const char *sockname)
{
	struct sockaddr_un sun;
	int clfd;

	acs_memzero(&sun, sizeof(struct sockaddr_un));
	sun.sun_family = AF_UNIX;
	acs_strlcpy(sun.sun_path, sockname, sizeof(sun.sun_path));
	clfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (clfd == -1) xerror("socket of %s", sockname);
	if (connect(clfd, (struct sockaddr *) &sun, sizeof(struct sockaddr_un)) == -1)
		xerror("connect on %s", sockname);

	return clfd;
}

#define DACCESS_EINT_PAD 2
#define DACCESS_EINT_SZ ((sizeof(int)*2)+2+DACCESS_EINT_PAD)
#define DACCESS_ESIZE_PAD 2
#define DACCESS_ESIZE_SZ ((sizeof(size_t)*2)+2+DACCESS_ESIZE_PAD)

static size_t daccess_encode_int(int x, char *ex)
{
	return (size_t)acs_snprintf(ex, DACCESS_EINT_SZ, "I%0*x", sizeof(int)*2, x) + 1;
}

static int daccess_decode_int(const char *ex)
{
	int r;
	char *stoi;

	if (*ex != 'I') return -1;
	r = (int)strtoul(ex+1, &stoi, 16);
	if (!str_empty(stoi)) return -1;
	return r;
}

static size_t daccess_encode_size(size_t x, char *ex)
{
	return (size_t)acs_snprintf(ex, DACCESS_ESIZE_SZ, "Z%0*x", sizeof(size_t)*2, x) + 1;
}

static size_t daccess_decode_size(const char *ex)
{
	size_t r;
	char *stoi;

	if (*ex != 'Z') return NOSIZE;
	r = (size_t)strtoull(ex+1, &stoi, 16);
	if (!str_empty(stoi)) return NOSIZE;
	return r;
}

static size_t daccess_receive(int fd, void *ptr, size_t l)
{
	return (size_t)recv(fd, ptr, l, 0);
}

static size_t daccess_send(int fd, const void *ptr, size_t l)
{
	size_t r;

	r = send(fd, ptr, l, MSG_NOSIGNAL);
	if (r == NOSIZE) return NOSIZE;

	return r;
}

static int daccess_receive_fd(int fd)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char control[sizeof(struct cmsghdr) + sizeof(int)];
	char data[DACCESS_EINT_SZ];
	int real_fd_number, received_fd;

	acs_memzero(control, sizeof(control));
	acs_memzero(data, sizeof(data));
	iov.iov_base = data;
	iov.iov_len = sizeof(data);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = msg.msg_controllen;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	if (recvmsg(fd, &msg, 0) == -1) return -1;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (msg.msg_flags & MSG_CTRUNC) return -1;
	for (; cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
		if (cmsg->cmsg_type == SCM_RIGHTS) break;
	memmove(&received_fd, CMSG_DATA(cmsg), sizeof(int));

	real_fd_number = daccess_decode_int(data);
	if (real_fd_number == -1) return -1;
	daccess_fdtofd(&received_fd, &real_fd_number, 1);

	return real_fd_number;
}

static int daccess_receive_fds(int fd, int *fds, int nfds)
{
	int x;

	for (x = 0; x < nfds; x++) {
		*(fds+x) = daccess_receive_fd(fd);
		if (*(fds+x) == -1) return -1;
	}
	return x;
}

static int daccess_send_fd(int fd, const int sendfd)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char control[sizeof(struct cmsghdr) + sizeof(int)];
	char data[DACCESS_EINT_SZ];

	acs_memzero(control, sizeof(control));
	acs_memzero(data, sizeof(data));

	iov.iov_base = data;
	iov.iov_len = daccess_encode_int(sendfd, data);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = msg.msg_controllen;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memmove(CMSG_DATA(cmsg), &sendfd, sizeof(int));
	if (sendmsg(fd, &msg, 0) == -1) return -1;

	return 1;
}

static int daccess_send_fds(int fd, const int *fds, int nfds)
{
	int x;

	for (x = 0; x < nfds; x++) {
		if (daccess_send_fd(fd, *(fds+x)) != 1) return -1;
	}
	return x;
}

static int daccess_receive_int(int fd)
{
	char t[DACCESS_EINT_SZ];

	acs_memzero(t, sizeof(t));
	daccess_receive(fd, t, sizeof(t)-DACCESS_EINT_PAD);
	return daccess_decode_int(t);
}

static int daccess_send_int(int fd, int x)
{
	size_t l, n;
	char s[DACCESS_EINT_SZ];

	n = daccess_encode_int(x, s);
	l = daccess_send(fd, s, n);
	if (l < n) return -1;
	return x;
}

static size_t daccess_receive_size(int fd)
{
	char t[DACCESS_ESIZE_SZ];

	acs_memzero(t, sizeof(t));
	daccess_receive(fd, t, sizeof(t)-DACCESS_ESIZE_PAD);
	return daccess_decode_size(t);
}

static size_t daccess_send_size(int fd, size_t x)
{
	size_t l, n;
	char s[DACCESS_ESIZE_SZ];

	n = daccess_encode_size(x, s);
	l = daccess_send(fd, s, n);
	if (l < n) return NOSIZE;
	return x;
}

static size_t daccess_receive_data(int fd, void *ptr, size_t l)
{
	size_t x;

	x = daccess_receive_size(fd);
	if (x > l || x == NOSIZE) return NOSIZE;

	return daccess_receive(fd, ptr, x);
}

static size_t daccess_send_data(int fd, const void *ptr, size_t l)
{
	if (daccess_send_size(fd, l) == NOSIZE) return NOSIZE;

	return daccess_send(fd, ptr, l);
}

static int daccess_send_ack(int fd)
{
	return daccess_send_int(fd, 1);
}

static int daccess_receive_ack(int fd)
{
	if (daccess_receive_int(fd) != 1) return -1;
	return 1;
}

static int daccess_send_string(int fd, const char *s)
{
	size_t l, x = strlen(s);

	if (daccess_send_size(fd, x) == NOSIZE) return 0;

	l = daccess_send(fd, s, x);
	if (l < x) return 0;

	return 1;
}

static char *daccess_receive_string(int fd, size_t maxl)
{
	char *r = NULL;
	size_t x, sl;

	sl = daccess_receive_size(fd);
	if (sl > maxl || sl == NOSIZE) goto _err;

	r = acs_malloc(sl+1);
	x = daccess_receive(fd, r, sl);
	if (x < sl) goto _err;

	return r;

_err:
	if (r) pfree(r);
	return NULL;
}

static int daccess_server_child(int clfd, int argc, char **argv)
{
	char *data, *s, *d;
	size_t l;
	int rargc = 0;
	int nfds, *recvfds, maxfd;
	struct ptsinfo ptsi;
	struct ucred cr;
	socklen_t crl = sizeof(struct ucred);
	struct pidcreds pcr;
	pid_t execpid, ptypid;
	struct pollfd pfd[2];
	struct termios te, rte;
	struct winsize wsz;
	int Te, Wsz, x;

	if (argc == 0 || *argv == NULL) return 1;

	clear_environ();
	data = acs_malloc(ACS_ALLOC_MAX);

	acs_memzero(&cr, sizeof(struct ucred));
	signal(SIGHUP, SIG_IGN);

	if (daccess_receive_ack(clfd) != 1) return 1;
	if (getsockopt(clfd, SOL_SOCKET, SO_PEERCRED, &cr, &crl) == -1) return 1;
	if (cr.pid == 0) return 1;
	if (daccess_nostatus) {
		pcr.ruid = pcr.euid = cr.uid;
		pcr.rgid = pcr.egid = cr.gid;
		pcr.gids = acs_malloc(sizeof(gid_t));
		pcr.gids[0] = cr.gid;
		pcr.ngids = 1;
	}
	else {
		if (getpidcreds(cr.pid, &pcr) == -1) return 1;
	}
	defuse_pcreds(&pcr);
	if (pcr.ruid != cr.uid) return 1;
	if (pcr.rgid != cr.gid) return 1;
	daccess_send_ack(clfd);

	access_getrandom(data, TF_KEY_SIZE);
	daccess_send_data(clfd, data, TF_KEY_SIZE);
	s = data + TF_KEY_SIZE;
	sk1024(daccess_password, acs_szalloc(daccess_password), s, TF_MAX_BITS);
	for (x = 0; x < TF_KEY_SIZE; x++) data[x] ^= s[x];
	daccess_receive_data(clfd, s, TF_KEY_SIZE);
	if (!memcmp(data, s, TF_KEY_SIZE)) {
		daccess_send_ack(clfd);
	}
	else {
		daccess_send_int(clfd, 0);
		return 1;
	}
	acs_memzero(data, ACS_ALLOC_MAX);

	/* args */
	rargc = daccess_receive_int(clfd);
	if (rargc < 0 || rargc > ACS_ALLOC_SMALL) return 1;

	daccess_nargc = argc + rargc;
	daccess_nargv = acs_malloc((daccess_nargc+1) * sizeof(char *));

	for (x = 0; x < argc; x++)
		*(daccess_nargv+x) = acs_strdup(*(argv+x));

	for (x = argc; x < daccess_nargc; x++) {
		*(daccess_nargv+x) = daccess_receive_string(clfd, ACS_ALLOC_MAX);
		if (!*(daccess_nargv+x)) return 1;
	}
	*(daccess_nargv+daccess_nargc) = NULL;
	daccess_send_ack(clfd);

	/* environ */
	rargc = daccess_receive_int(clfd);
	if (rargc < 0 || rargc > ACS_ALLOC_SMALL) return 1;

	for (x = 0; x < rargc; x++) {
		s = daccess_receive_string(clfd, ACS_ALLOC_MAX);
		if (!s) return 1;
		d = strchr(s, '=');
		if (!d) goto _badenv;
		*d = 0;
		d++;
		acs_setenv(s, d, 1);
_badenv:	pfree(s);
	}
	daccess_send_ack(clfd);

	/* fds */
	maxfd = sysconf(_SC_OPEN_MAX);
	nfds = daccess_receive_int(clfd);
	if (nfds < 0 || nfds > maxfd) return 1;
	recvfds = acs_malloc(nfds * sizeof(int));
	if (daccess_receive_fds(clfd, recvfds, nfds) == -1) xerror("recvfds");
	daccess_send_ack(clfd);

	execpid = fork();
	if (execpid == -1) xerror("fork");
	if (execpid == 0) {
		signal(SIGTERM, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		signal(SIGHUP, SIG_DFL);

		if (isatty(recvfds[0])) {
			int rem;

			Te = tcgetattr(recvfds[0], &te);
			Wsz = ioctl(recvfds[0], TIOCGWINSZ, (char *)&wsz);
			rte = te;
			cfmakeraw(&te);
			te.c_lflag &= ~ECHO;
			tcsetattr(recvfds[0], TCSAFLUSH, &te);

			ptsi.ptsname = "/dev/ptmx";
			if (!daccess_getpts(&ptsi)) xerror("daccess_getpts");

			ptypid = fork();
			if (ptypid == -1) xerror("fork");
			if (ptypid == 0) {
				close(ptsi.ptsfd);
				daccess_closestd(NULL);
				ptsi.ptsfd = open(ptsi.ptsname, O_RDWR);
				if (ptsi.ptsfd == -1) xerror("%s", ptsi.ptsname);
				if (dup2(ptsi.ptsfd, 1) == -1) xerror("dup2");
				if (dup2(ptsi.ptsfd, 2) == -1) xerror("dup2");
				if (!Te) tcsetattr(ptsi.ptsfd, TCSAFLUSH, &rte);
				if (!Wsz) ioctl(ptsi.ptsfd, TIOCSWINSZ, (char *)&wsz);

				if (setsid() == -1) xerror("setsid");
#ifdef TIOCSCTTY
				ioctl(ptsi.ptsfd, TIOCSCTTY, 0);
#endif

				pcr.euid = 0; /* <-- setuid! */
				setpidcreds(&pcr);

				execve(*daccess_nargv,
					*(argv+1) ? daccess_nargv+1 : daccess_nargv, environ);
				xerror("execve of %s", *daccess_nargv);
			}

			setpidcreds(&pcr);
			freepidcreds(&pcr);
			pfree(ptsi.ptsname);

			pfd[0].fd = ptsi.ptsfd;
			pfd[0].events = POLLIN;
			pfd[1].fd = recvfds[0];
			pfd[1].events = POLLIN;
			fcntl(ptsi.ptsfd, F_SETFL, fcntl(ptsi.ptsfd, F_GETFL) | O_NONBLOCK);

			nfds = 2;
			while (nfds) {
				if (poll(pfd, nfds, -1) == -1 && errno != EINTR) break;
				if (pfd[0].revents) {
					errno = 0;
					l = read(ptsi.ptsfd, data, ACS_ALLOC_MAX);
					if (l == NOSIZE && errno != EAGAIN) break;
					write(recvfds[1], data, l);
				}
				if (pfd[1].revents) {
					l = read(recvfds[0], data, ACS_ALLOC_MAX);
					if (l == NOSIZE) {
						pfd[1].revents = 0;
						nfds--;
					}
					else write(ptsi.ptsfd, data, l);
				}
			}

			rem = 100;
			while (rem > 0) {
				l = read(ptsi.ptsfd, data, ACS_ALLOC_MAX);
				if (l == NOSIZE) break;
				write(recvfds[1], data, l);
				rem--;
			}

			if (!Te) tcsetattr(recvfds[0], TCSAFLUSH, &rte);

			waitpid(ptypid, &daccess_retval, 0);
			daccess_retval = WEXITSTATUS(daccess_retval);
			acs_exit(daccess_retval);
		}
		else {
			if (setsid() == -1) xerror("setsid");

			pcr.euid = 0; /* <-- setuid! */
			setpidcreds(&pcr);

			execve(*daccess_nargv,
				*(argv+1) ? daccess_nargv+1 : daccess_nargv, environ);
			xerror("execve of %s", *daccess_nargv);
		}
	}

	daccess_closestd(recvfds);

	setpidcreds(&pcr);
	freepidcreds(&pcr);

	waitpid(execpid, &daccess_retval, 0);
	daccess_retval = WEXITSTATUS(daccess_retval);
	daccess_send_int(clfd, daccess_retval);
	if (daccess_receive_ack(clfd) != 1) return 1;

	daccess_closefd(clfd);
	return 0;
}

static int start_server(const char *sockname, int argc, char **argv)
{
	int newclfd;

	signal(SIGCHLD, daccess_reap_children);
	signal(SIGTERM, daccess_server_exit);
	signal(SIGINT, daccess_server_exit);
	signal(SIGQUIT, daccess_server_exit);
	signal(SIGHUP, daccess_server_exit);

	daccess_serverfd = create_serv_socket(sockname);
	daccess_cloexec(daccess_serverfd);
	daccess_sockname = acs_strdup(sockname);

	daccess_closestd(NULL);

_accept:
	daccess_clfd = accept(daccess_serverfd, NULL, 0);
	newclfd = daccess_randfd(daccess_clfd);
	if (newclfd == -1) xerror("randfd");
	daccess_clfd = newclfd;
	if (daccess_clfd != -1) {
		daccess_cloexec(daccess_clfd);
		switch (fork()) {
			case -1: xerror("fork"); break;
			case 0: goto _recv; break;
			default: close(daccess_clfd); goto _accept; break;
		}
	}
	else xerror("accept");

_recv:
	close(daccess_serverfd);
	signal(SIGCHLD, SIG_DFL);
	return daccess_server_child(daccess_clfd, argc, argv);
}

static int client_connect(const char *sockname, int argc, char **argv)
{
	size_t l;
	int x, *sendfds, maxfd;
	char *sdata, *udata;

	daccess_retval = 1;

	sdata = acs_malloc(TF_KEY_SIZE);
	udata = acs_malloc(TF_KEY_SIZE);

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);

	daccess_clfd = create_client_socket(sockname);
	daccess_cloexec(daccess_clfd);
	daccess_sockname = acs_strdup(sockname);

	daccess_send_ack(daccess_clfd);
	if (daccess_receive_ack(daccess_clfd) != 1) goto _fail;

	l = daccess_receive_data(daccess_clfd, sdata, TF_KEY_SIZE);
	if (l != TF_KEY_SIZE) goto _fail;
	sk1024(daccess_password, acs_szalloc(daccess_password), udata, TF_MAX_BITS);
	for (x = 0; x < TF_KEY_SIZE; x++) sdata[x] ^= udata[x];
	daccess_send_data(daccess_clfd, sdata, TF_KEY_SIZE);
	if (daccess_receive_ack(daccess_clfd) != 1) goto _fail;
	pfree(sdata);
	pfree(udata);

	/* args */
	if (*argv) {
		daccess_send_int(daccess_clfd, argc);
		for (x = 0; *(argv+x); x++)
			daccess_send_string(daccess_clfd, *(argv+x));
		if (daccess_receive_ack(daccess_clfd) != 1) goto _fail;
	}
	else {
		daccess_send_int(daccess_clfd, 0);
		if (daccess_receive_ack(daccess_clfd) != 1) goto _fail;
	}

	/* environ */
	for (x = 0; *(environ+x); x++);
	daccess_send_int(daccess_clfd, x);
	for (x = 0; *(environ+x); x++)
		daccess_send_string(daccess_clfd, *(environ+x));
	if (daccess_receive_ack(daccess_clfd) != 1) goto _fail;

	/* fds */
	sendfds = acs_malloc(3 * sizeof(int));
	/* stdfds */
	sendfds[0] = 0;
	sendfds[1] = 1;
	sendfds[2] = 2;
	maxfd = sysconf(_SC_OPEN_MAX);
	/* brute force fds space by abusing fcntl -- HACK, but usable */
	for (x = 3; x < maxfd; x++) {
		if (daccess_valid_fd(x) && x != daccess_clfd) {
			l = DYN_ARRAY_SZ(sendfds);
			sendfds = acs_realloc(sendfds, (l+1) * sizeof(int));
			sendfds[l] = x;
		}
	}
	x = DYN_ARRAY_SZ(sendfds);
	daccess_send_int(daccess_clfd, x);
	daccess_send_fds(daccess_clfd, sendfds, x);
	if (daccess_receive_ack(daccess_clfd) != 1) goto _fail;

	/* erase all args */
	for (x = 1; *(daccess_orig_argv+x); x++) {
		l = strlen(*(daccess_orig_argv+x));
		acs_memzero(*(daccess_orig_argv+x), l);
	}

	/* server program runs, writes to our fds, we just wait */
	daccess_retval = daccess_receive_int(daccess_clfd);
	daccess_send_ack(daccess_clfd);

_fail:
	return daccess_retval;
}

static void daccess_usage(void)
{
	acs_say("usage: daccess [-scFN] [-p passwd] [-S sock] [-C sock] cmdline");
	acs_say("  helper server for setuid-crippled systems.");
	acs_say("  runs cmdline as setuid program.");
	acs_say("  -s: start server with default sock path \"%s\"", DACCESS_SOCK_PATH);
	acs_say("  -c: connect to server with default sock path \"%s\"", DACCESS_SOCK_PATH);
	acs_say("  -S sock: start server, but specify own socket path");
	acs_say("  -C sock: connect to server with specified socket path");
	acs_say("  -p passwd: set daccess control password (will be erased from args)");
	acs_say("  -F: do not daemonise the server, so errors are visible");
	acs_say("  -N: do not try to open /proc/pid/status, use basic socket credentials");
	acs_exit(1);
}

int daccess_main(int argc, char **argv, uid_t srcuid, gid_t srcgid, int srcgsz, gid_t *srcgids)
{
	char *sockname;
	int c;

	daccess_orig_argv = argv;
	sockname = acs_strdup(DACCESS_SOCK_PATH);
	daccess_password = acs_strdup(DACCESS_PASSWORD);

	if (!strcmp(progname, "daccessd")) {
		acs_optind = 1;
		daccess_server = 1;
		goto _dothings;
	}
	else if (!strcmp(progname, "daccessc")) {
		acs_optind = 1;
		daccess_server = 0;
		goto _dothings;
	}

	set_progname("daccess");

	acs_opterr = 0;
	while ((c = acs_getopt(argc, argv, "scS:C:p:FN")) != -1) {
		switch (c) {
			case 'F': daccess_nodaemon = 1; break;
			case 'N': daccess_nostatus = 1; break;
			case 's': daccess_server = 1; break;
			case 'c': daccess_server = 0; break;
			case 'S': daccess_server = 1; pfree(sockname); sockname = acs_strdup(acs_optarg); break;
			case 'C': daccess_server = 0; pfree(sockname); sockname = acs_strdup(acs_optarg); break;
			case 'p':
				daccess_password = acs_strdup(acs_optarg);
				memset(acs_optarg, 'x', strlen(acs_optarg));
				break;
			default: daccess_usage(); break;
		}
	}

_dothings:
	if (daccess_server) {
		if (!is_super_user()) xexits("only superuser can do this");
	}
	else {
		if (is_setuid()) {
			/* drop privs as early as possible */
			if (setgroups(srcgsz, srcgids) == -1) xerror("setgroups");
#ifdef HAVE_SETRESID
			if (setresgid(srcgid, srcgid, srcgid) == -1) xerror("setresgid");
			if (setresuid(srcuid, srcuid, srcuid) == -1) xerror("setresuid");
#else
			if (setregid(srcgid, srcgid) == -1) xerror("setregid");
			if (setreuid(srcuid, srcuid) == -1) xerror("setreuid");
#endif
		}
	}

	if (daccess_server) {
		if (argc-acs_optind == 0 || *(argv+acs_optind) == NULL)
			daccess_usage();
		if (!daccess_nodaemon) daccess_daemonise();
		acs_exit(start_server(sockname, argc-acs_optind, argv+acs_optind));
	}
	acs_exit(client_connect(sockname, argc-acs_optind, argv+acs_optind));

	return 0;
}
#endif
