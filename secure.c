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

int is_super_user(void)
{
#ifdef HAVE_ISSETUGID
	if (!issetugid()) return 0; /* On really safe systems with -DHAVE_ISSETUGID */
#endif
	return !!(srcuid == 0);
}

int needs_super_user(void)
{
	return !!((dstuid == 0) || (dsteuid == 0));
}

int is_setuid(void)
{
#ifdef HAVE_ISSETUGID
	if (issetugid() && geteuid() == 0) return 1;
#else
	if (geteuid() == 0) return 1;
#endif
	return 0;
}

char *get_spath(void)
{
	if (needs_super_user() && (supath && !str_empty(supath))) return supath;

	if (!spath || str_empty(spath)) {
		pfree(spath);
		spath = acs_strdup(SAFE_PATH);
	}

	return spath;
}

int cfg_permission(const struct stat *st, int dir)
{
	if (st->st_uid != 0 || st->st_gid != 0) return 0;
	if (!dir && isflag(st->st_mode, S_IXUSR)) return 0; /* --x|---|--- */
	if (isflag(st->st_mode, S_IRGRP)) return 0; /* ---|r--|--- */
	if (isflag(st->st_mode, S_IWGRP)) return 0; /* ---|-w-|--- */
	if (isflag(st->st_mode, S_IXGRP)) return 0; /* ---|--x|--- */
	if (isflag(st->st_mode, S_IROTH)) return 0; /* ---|---|r-- */
	if (isflag(st->st_mode, S_IWOTH)) return 0; /* ---|---|-w- */
	if (isflag(st->st_mode, S_IXOTH)) return 0; /* ---|---|--x */
				       /* Not allowed: --x|rwx|rwx */
					/* Allowed:    rw-|---|--- */

	return 1;
}

const char *acs_crypt(const char *key, const char *salt)
{
#ifdef HAVE_UNIX_CRYPT
	char *p = crypt(key, salt);
	return p ? p : "*";
#else
	return "*";
#endif
}

#define blamesetenv(to, fmt, ss, dd)								\
	do {											\
		size_t sz;									\
		acs_asprintf(&to, fmt, ss, dd);							\
		sz = DYN_ARRAY_SZ(tenvp);							\
		tenvp = acs_realloc(tenvp, (sz+(sz == 0 ? 2 : 1)) * sizeof(char *));		\
		if (sz) sz--;									\
		*(tenvp+sz) = acs_strdup(to);							\
	} while (0)
void blame(const char *f, ...)
{
	va_list ap;
	static char *denymsg_parsed;
	static char *reason_str;
	char *s, **targv, **tenvp, **tpp;
	struct fmtstr_args *fsa;
	size_t nr_fsa;
	struct fmtstr_state fst;

	if (!denymsg_parsed) denymsg_parsed = acs_malloc(ACS_ALLOC_SMALL);
	if (!reason_str) reason_str = acs_malloc(ACS_ALLOC_SMALL);

	va_start(ap, f);
	acs_vsnprintf(reason_str, ACS_ALLOC_SMALL, f, ap);
	va_end(ap);

	if (isflag(suflags, FLG_LOG) || isflag(suflags, FLG_LOGFAIL)) {
		s = NULL;
		if (custom_blame_str) acs_asprintf(&s, "%s (%s)", custom_blame_str, reason_str);
		else s = reason_str;
		if (!write_log_line(s)) xerror("writing log entry");
		if (custom_blame_str) pfree(s);
	}

	if (noblame) goto _out;

	/* This is where I insult invoker */
	block_tty(&ttyinfo, 1);
	usleep(delay);
	block_tty(&ttyinfo, 0);
	if (denymsg) {
		preset_fsa_full(&fsa, &nr_fsa);
		if (custom_blame_str) s = custom_blame_str;
		else s = reason_str;
		APPEND_FSA(fsa, nr_fsa, "reason", 0, "%s", s);

		acs_memzero(&fst, sizeof(struct fmtstr_state));
		fst.args = fsa;
		fst.nargs = nr_fsa;
		fst.fmt = denymsg;
		fst.result = denymsg_parsed;
		fst.result_sz = acs_szalloc(denymsg_parsed);
		parse_fmtstr(&fst);
		pfree(fsa);

		if (blamecmd) {
			s = NULL;
			tenvp = NULL;

			blamesetenv(s, "%s=%s", "PATH", auditspath ? auditspath : get_spath());
			blamesetenv(s, "%s=%s", "ACCESS_DENYMSG", fst.trunc ? denymsg : denymsg_parsed);
			blamesetenv(s, "%s=%u", "ACCESS_PID", ourpid);
			blamesetenv(s, "%s=%u", "ACCESS_PPID", parentpid);

			blamesetenv(s, "%s=%s", "ACCESS_DATETIME", curr_date);
			blamesetenv(s, "%s=%u", "ACCESS_TIMESTAMP", curr_time);

			blamesetenv(s, "%s=%u", "ACCESS_UID", srcuid);
			blamesetenv(s, "%s=%s", "ACCESS_USER", srcusr);
			blamesetenv(s, "%s=%u", "ACCESS_GID", srcgid);
			blamesetenv(s, "%s=%s", "ACCESS_GROUP", srcgrp);
			blamesetenv(s, "%s=%s", "ACCESS_GIDS", srcgidss);
			blamesetenv(s, "%s=%s", "ACCESS_GROUPS", srcgrps);

			blamesetenv(s, "%s=%u", "ACCESS_D_UID", dstuid);
			blamesetenv(s, "%s=%u", "ACCESS_D_EUID", dsteuid);
			blamesetenv(s, "%s=%s", "ACCESS_D_USER", dstusr);
			blamesetenv(s, "%s=%s", "ACCESS_D_EUSER", dsteusr);
			blamesetenv(s, "%s=%u", "ACCESS_D_GID", dstgid);
			blamesetenv(s, "%s=%u", "ACCESS_D_EGID", dstegid);
			blamesetenv(s, "%s=%s", "ACCESS_D_GROUP", dstgrp);
			blamesetenv(s, "%s=%s", "ACCESS_D_EGROUP", dstegrp);
			blamesetenv(s, "%s=%s", "ACCESS_D_GIDS", dstgidss);
			blamesetenv(s, "%s=%s", "ACCESS_D_GROUPS", dstfgrps);

			blamesetenv(s, "%s=%s", "ACCESS_FLAGS", trigflags);

			blamesetenv(s, "%s=%s", "ACCESS_LINE", trigline);

			blamesetenv(s, "%s=%s", "ACCESS_MATCH_TYPE", get_match_type(match_type));

			blamesetenv(s, "%s=%s", "ACCESS_BINPATH", execfpath);
			blamesetenv(s, "%s=%s", "ACCESS_CMDLINE", cmdline);
if (hashbang) {		blamesetenv(s, "%s=%s", "ACCESS_HASHBANG", hashbang); }

			blamesetenv(s, "%s=%s", "ACCESS_USERENV", buserenv);
			blamesetenv(s, "%s=%s", "ACCESS_ENVIRON", benviron);

			blamesetenv(s, "%s=%u", "ACCESS_FIRST_ARG", acs_optind);
			blamesetenv(s, "%s=%s", "ACCESS_ARGS", bfullargv);
			blamesetenv(s, "%s=%s", "ACCESS_PATH", get_spath());

			blamesetenv(s, "%s=%s", "ACCESS_LOCKFILE", lockfile ? lockfile : "<unset>");

if (ttyinfo.fd != -1) {
			blamesetenv(s, "%s=%s", "ACCESS_TTY", ttyinfo.ttyname);
}
			blamesetenv(s, "%s=%s", "ACCESS_CWD", cwd);
			blamesetenv(s, "%s=%s", "ACCESS_USRDIR", dstusrdir);
			blamesetenv(s, "%s=%s", "ACCESS_USRSHELL", dstusrshell);
if (isflag(argflags, ARG_D) || isflag(argflags, ARG_d)) {
			blamesetenv(s, "%s=%s", "ACCESS_CHDIR", dstdir);
}
if (schrootdir && chrootdir) {
			blamesetenv(s, "%s=%s", "ACCESS_CHROOT", chrootdir);
}

			blamesetenv(s, "%s=%s", "ACCESS_CONF", PATH_CONF);
#ifdef SYSLOG_SUPPORT
			blamesetenv(s, "%s=%s", "ACCESS_LOG", isflag(suflags, FLG_SYSLOG) ? "<syslog>" : logpath);
#else
			blamesetenv(s, "%s=%s", "ACCESS_LOG", logpath);
#endif
#ifdef _ACCESS_VERSION
			blamesetenv(s, "%s=%s", "ACCESS_VERSION", _ACCESS_VERSION);
#endif
			pfree(s);

			s = acs_strdup(blamecmd);
			targv = parse_cmdline(s);
			if (!targv) goto _out;
			tpp = targv;
			if (*(targv+1)) tpp++;
			if (is_abs_rel(*targv) != PATH_ABSOLUTE) goto _out;
			reseterr();
			extern_prog_running = 1;
			forkexec(0, *targv, tpp, tenvp, NULL, NULL, NULL, 0);
			extern_prog_running = 0;
			destroy_argv(&tenvp);
			pfree(targv);
			pfree(s);
		}
		else {
			if (fst.trunc) acs_esay("%s", denymsg);
			else acs_esay("%s", denymsg_parsed);
		}
	}

_out:
	acs_memzero(denymsg_parsed, ACS_ALLOC_SMALL);
	acs_memzero(reason_str, ACS_ALLOC_SMALL);
	acs_exit(1);
}
#undef blamesetenv

void close_fd_range(int startfd, int endfd)
{
	int x;
	for (x = startfd; x < endfd; x++) close(x);
}

int runaway(void)
{
	gid_t t = 0;

#ifdef HAVE_SETRESID
	if (setresuid(0, 0, 0) == -1) goto _err;
	if (setresgid(0, 0, 0) == -1) goto _err;
#else
	if (setreuid(0, 0) == -1) goto _err;
	if (setregid(0, 0) == -1) goto _err;
#endif
	setgroups(1, &t);

	return 1;

_err:
	return 0;
}

/*
 * This one probably requires more attention, but
 * that's probably will make code unportable.
 */

void ttydetach(void)
{
	int fd;

	if (setpgid(0, 0) == -1) xerror("ttydetach");
#ifdef TIOCNOTTY
	if ((fd = open("/dev/tty", O_RDWR)) != -1) {
		ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}
#else
#warning TIOCNOTTY is missing, ttydetach will not work!
	acs_esay("WARNING: TIOCNOTTY is MISSING!");
#endif
}

int grab_tty(struct tty_info *ttyi)
{
	struct stat st;

	if (ttyi->fd != -1) return 1;

	reseterr();

	if (!ttyi->ttyname || str_empty(ttyi->ttyname)) {
		seterr("ttyname is NULL!");
		return -1;
	}

	ttyi->fd = open(ttyi->ttyname, O_RDWR|O_NOCTTY);
	if (ttyi->fd == -1) return -1;

	if (fstat(ttyi->fd, &st) == -1) {
		if (ttyi->fd != -1) close(ttyi->fd);
		return -1;
	}

	if (fchown(ttyi->fd, 0, 0) == -1) goto _fail;
	if (fchmod(ttyi->fd, 0600) == -1) goto _fail;
	if (tcgetattr(ttyi->fd, &ttyi->ttyconf) == -1) goto _fail;

	ttyi->mode = st.st_mode;
	ttyi->uid = st.st_uid;
	ttyi->gid = st.st_gid;

	return 1;

_fail:
	fchmod(ttyi->fd, ttyi->mode);
	fchown(ttyi->fd, st.st_uid, st.st_gid);
	if (ttyi->fd != -1) close(ttyi->fd);

	return -1;
}

int put_tty(struct tty_info *ttyi)
{
	if (fchown(ttyi->fd, ttyi->uid, ttyi->gid) == -1) return -1;
	if (fchmod(ttyi->fd, ttyi->mode) == -1) return -1;
	if (tcsetattr(ttyi->fd, TCSANOW, &ttyi->ttyconf) == -1) return -1;

	close(ttyi->fd);
	pfree(ttyi->ttyname);
	acs_memzero(&ttyi->ttyconf, sizeof(struct termios));
	acs_memzero(ttyi, sizeof(struct tty_info));
	ttyi->fd = -1;

	return 1;
}

int block_tty(const struct tty_info *ttyi, int block)
{
	struct termios t;

	if (ttyi->fd == -1) return 0;

	if (block) acs_cfmakeraw(&t);
	else memcpy(&t, &ttyi->ttyconf, sizeof(struct termios));
	if (tcsetattr(ttyi->fd, TCSAFLUSH, &t) == -1) return -1;

	return 1;
}

static int warnusr_filt(struct getpasswd_state *getps, char c, size_t pos)
{
	static int warned;

	if (c == 'y' || c == 'Y' || c == 'n' || c == 'N') {
		warned = 0;
		write(getps->efd, &c, sizeof(char));
		return 1;
	}

	if (!warned) {
		acs_nesay("Please answer [yY/nN] ");
		warned = 1;
	}
	return 0;
}

void warnusr(void)
{
	struct getpasswd_state getps;
	char c[2];
	size_t err;

	if (!cmdline) return;

	acs_memzero(&getps, sizeof(struct getpasswd_state));
	c[0] = c[1] = 0;
	if (ttyinfo.fd != -1) getps.fd = getps.efd = ttyinfo.fd;
	else getps.fd = getps.efd = -1;
	getps.passwd = c;
	getps.pwlen = 1;
	getps.charfilter = warnusr_filt;
	getps.flags = GETP_NOINTERP;

	acs_esay("You are about to execute this:");
	acs_esay("`%s`,", cmdline);
	acs_esay("as: %s(%u),%s(%u):%s(%u),%s(%u),",
		dstusr, dstuid, dsteusr, dsteuid,
		dstgrp, dstgid, dstegrp, dstegid);
	acs_esay("groups: %s;", dstfgrps);
	acs_esay("gids: %s.", dstgidss);
	acs_nesay("Continue? ");

	err = acs_getpasswd(&getps);

	if (err == NOSIZE && getps.error)
		blame("reading warnusr answer: %s", acs_strerror(getps.error));

	if (c[0] == 'Y' || c[0] == 'y') return;
	else {
		acs_esay("Aborted by user.");
		noblame = 1;
		blame("aborted by user");
	}
}

#ifdef _POSIX_MEMLOCK
int lockpages(void)
{
	if (mlockall(MCL_CURRENT|MCL_FUTURE) == -1) return 0;
	return 1;
}
#endif

/* Install new execpath and execfpath. */
void find_new_exec(const char *spathspec, const char *progname, const char *chroot)
{
	size_t n;

	if (execpath == execfpath)
		execpath = NULL;
	else pfree(execpath);
	pfree(execfpath);

	execfpath = acs_which(spathspec, progname, chroot);
	if (!execfpath) return;

	if (chroot) {
		n = acs_strnlen(chroot, ACS_ALLOC_MAX);
		execpath = acs_strdup(execfpath+n);
	}
	else execpath = execfpath;
}
