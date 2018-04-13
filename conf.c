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

int refind_exec;

char *get_conf_line(void)
{
	static char *confline;
	size_t x;
	char *s, *d;

	if (!confline) confline = acs_malloc(ACS_ALLOC_MAX);

	if (!conffile || ferror(conffile) || feof(conffile)) return NULL;

_again:
	x = acs_fgets(confline, ACS_ALLOC_MAX-1, conffile);
	if (x == NOSIZE) return NULL;
	if (!x || iscomment(confline)) goto _again;

	s = confline+(x-1);

_again3:
	/* fetch the remaining from next line(s) */
	if (*s == '\\') {
		/* cleanup of trailing tabs */
		d = s-1;
		while (*d && d-confline > 0) {
			if (*d == '\t') *d = 0;
			else break;
			d--;
		}
		s = d+1;

		/* get line remainder */
_again2:	x = acs_fgets(s, ACS_ALLOC_MAX-1-(s-confline), conffile);
		if (x == NOSIZE) {
			*s = 0;
			goto _done;
		}
		if (!x) goto _again2;

		/* cleanup of leading tabs */
		d = s;
		while (*d) {
			if (*d == '\t') *d = 0;
			else break;
			d++;
		}
		/* This is comment? Get a new one! */
		if (iscomment(d)) goto _again2;
		if (d-s) {
			/* move string to beginning, erasing NULs */
			memmove(s, d, x);
			x -= d-s;
		}

		/* check and repeat again for next ones */
		s += x-1;
		goto _again3;
	}

_done:	return confline;
}

int open_conf(void)
{
	struct stat st;

	if (lstat(PATH_CONF, &st) == -1) return 0;
	if (!cfg_permission(&st)) {
		seterr("wrong mode");
		return 0;
	}
	conffile = fopen(PATH_CONF, "rb");
	if (!conffile) return 0;

	return 1;
}

void reset_conf(long to)
{
	if (conffile) {
		if (fseek(conffile, 0L, SEEK_SET) == -1) xerror("rewinding config file failed");
		if (to) if (fseek(conffile, to, SEEK_SET) == -1) xerror("rewinding config file failed");
	}
}

#define xsetflag(x, y) do { setflag(x, y); if (single) goto _ret; } while (0)
#define xunsetflag(x, y) do { unsetflag(x, y); if (single) goto _ret; } while (0)
#define xnotargflag(z, x, y) do { z ? unsetflag(x, y) : setflag(x, y); if (single) goto _ret; } while (0)
void resolve_flags(const char *sflags, int single, flagtype *suflags_p, flagtype *argflags_p, flagtype *notargflags_p)
{
	char *s, *d, *t;
	flagtype suflags_l = 0, argflags_l = 0, notargflags_l = 0;
	int notarg; char carg;
	static char *flags_tmp;

	if (!flags_tmp) flags_tmp = acs_malloc(ACS_ALLOC_MAX);

	if (!strcmp(sflags, "pw")) return;

	if (suflags_p) suflags_l = *suflags_p;
	if (argflags_p) argflags_l = *argflags_p;
	if (notargflags_p) notargflags_l = *notargflags_p;

	acs_strlcpy(flags_tmp, sflags, ACS_ALLOC_MAX);
	s = d = flags_tmp; t = NULL;
	while ((s = acs_strtok_r(d, ",", &t))) {
		if (d) d = NULL;

		if (!strcmp(s, "log")) xsetflag(&suflags_l, FLG_LOG);
		if (!strcmp(s, "nolog")) xunsetflag(&suflags_l, FLG_LOG);
		if (!strcmp(s, "logfail")) xsetflag(&suflags_l, FLG_LOGFAIL);
		if (!strcmp(s, "nologfail")) xunsetflag(&suflags_l, FLG_LOGFAIL);
		if (!strcmp(s, "tty")) xsetflag(&suflags_l, FLG_TTY);
		if (!strcmp(s, "notty")) xunsetflag(&suflags_l, FLG_TTY);
		if (!strcmp(s, "pw")) xsetflag(&suflags_l, FLG_PW);
		if (!strcmp(s, "nopw")) {
			unsetflag(&suflags_l, FLG_PW);
			unsetflag(&suflags_l, FLG_DSTPW);
			if (single) goto _ret;
		}
		if (!strcmp(s, "dstpw")) xsetflag(&suflags_l, FLG_DSTPW);
		if (!strcmp(s, "supw")) xsetflag(&suflags_l, FLG_SUPW);
		if (!strcmp(s, "pwinval")) xsetflag(&suflags_l, FLG_PWINVALOPT);
		if (!strcmp(s, "false")) xsetflag(&suflags_l, FLG_FALSE);
#ifdef SYSLOG_SUPPORT
		if (!strcmp(s, "syslog")) xsetflag(&suflags_l, FLG_SYSLOG);
#endif
		if (!strcmp(s, "minenv")) xsetflag(&suflags_l, FLG_CLRENV);
		if (!strcmp(s, "nominenv") || !strcmp(s, "userenv")) xunsetflag(&suflags_l, FLG_CLRENV);
		if (!strcmp(s, "keepenv")) xsetflag(&argflags_l, ARG_P);
		if (!strcmp(s, "euid")) xunsetflag(&suflags_l, FLG_NOEUID);
		if (!strcmp(s, "noeuid")) xsetflag(&suflags_l, FLG_NOEUID);
		if (!strcmp(s, "egid")) xunsetflag(&suflags_l, FLG_NOEGID);
		if (!strcmp(s, "noegid")) xsetflag(&suflags_l, FLG_NOEGID);
		if (!strcmp(s, "nonumid")) xsetflag(&suflags_l, FLG_NONUMID);
		if (!strcmp(s, "numid")) xunsetflag(&suflags_l, FLG_NONUMID);
		if (!strcmp(s, "usronly")) {
			setflag(&suflags_l, FLG_USRONLY);
			setflag(&suflags_l, FLG_NOEUID);
			setflag(&suflags_l, FLG_NOEGID);
			setflag(&suflags_l, FLG_NONUMID);
			if (single) goto _ret;
		}
		if (!strcmp(s, "nousronly")) {
			unsetflag(&suflags_l, FLG_USRONLY);
			unsetflag(&suflags_l, FLG_NOEUID);
			unsetflag(&suflags_l, FLG_NOEGID);
			unsetflag(&suflags_l, FLG_NONUMID);
			if (single) goto _ret;
		}

		if (!is_super_user() && (!strncmp(s, "noopt_", 6) || !strncmp(s, "opt_", 4))) {
			notarg = !!(!strncmp(s, "no", 2)); /* if begin with "no" -> notarg = 1 */
			carg = notarg ? *(s+6) : *(s+4);

			switch (carg) {
				case 'd': xnotargflag(notarg, &notargflags_l, ARG_d); break;
				case 'D': xnotargflag(notarg, &notargflags_l, ARG_D); break;
				case 'e': xnotargflag(notarg, &notargflags_l, ARG_e); break;
				case 'S': xnotargflag(notarg, &notargflags_l, ARG_S); break;
				case 'a': xnotargflag(notarg, &notargflags_l, ARG_a); break;
				case 'A': xnotargflag(notarg, &notargflags_l, ARG_A); break;
				case 'P': xnotargflag(notarg, &notargflags_l, ARG_P); break;
				case 'I': xnotargflag(notarg, &notargflags_l, ARG_I); break;
				case 'b': xnotargflag(notarg, &notargflags_l, ARG_b); break;
				case 'B': xnotargflag(notarg, &notargflags_l, ARG_B); break;
				case 'x': xnotargflag(notarg, &notargflags_l, ARG_x); break;
				case 'n': xnotargflag(notarg, &notargflags_l, ARG_n); break;
				case 'F': xnotargflag(notarg, &notargflags_l, ARG_F); break;
				case 'C': xnotargflag(notarg, &notargflags_l, ARG_C); break;
				case 'L': xnotargflag(notarg, &notargflags_l, ARG_L); break;
#ifdef HAVE_SETPRIORITY
				case 'Q': xnotargflag(notarg, &notargflags_l, ARG_Q); break;
#endif
				case 'p': xnotargflag(notarg, &notargflags_l, ARG_p); break;
				case 'v': xnotargflag(notarg, &notargflags_l, ARG_v); break;
				case 'w': xnotargflag(notarg, &notargflags_l, ARG_w); break;
				case 'N': xnotargflag(notarg, &notargflags_l, ARG_N); break;
				case 'l': xnotargflag(notarg, &notargflags_l, ARG_l); break;
				default: break;
			}
		}
		if (!is_super_user() && !strcmp(s, "nologin")) xnotargflag(1, &notargflags_l, ARG_l);

		if (!strcmp(s, "ttydt")) xsetflag(&argflags_l, ARG_B);
		if (!strcmp(s, "nottydt")) xunsetflag(&argflags_l, ARG_B);
		if (!strcmp(s, "nolock")) xsetflag(&suflags_l, FLG_NOLOCK);
		if (!strcmp(s, "warnusr")) xsetflag(&suflags_l, FLG_WARNUSR);
		if (!strcmp(s, "nowarnusr")) xunsetflag(&suflags_l, FLG_WARNUSR);
	}

_ret:	if (suflags_p) *suflags_p = suflags_l;
	if (argflags_p) *argflags_p = argflags_l;
	if (notargflags_p) *notargflags_p = notargflags_l;
}

void readin_default_settings(void)
{
	char *ln, *s;

	reset_conf(0);

	while ((ln = get_conf_line())) {
		/*
		 * Explicit start of rules section.
		 * Why? Because no need to rewind.
		 */
		if (!strcmp(ln, "%rules")) return;
		/* No %unset really. Init stuff only! */
		else if (!strncmp(ln, "%set ", 5))
			set_variable(ln+5, 1);
		else if (!strncmp(ln, "%setenv ", 8)) {
			s = acs_strchr(ln+8, '=');
			if (!s) continue;
			*s = 0;

			if (is_envvar_exists(ln+8, EVC_CONF_UNSET)) continue;

			if (is_super_user()
			&& (is_envvar_exists(ln+8, EVC_OPTE_SET)
			|| is_envvar_exists(ln+8, EVC_OPTE_UNSET))) continue;

			add_envvar(ln+8, s+1, EVC_CONF_SET);
		}
		else if (!strncmp(ln, "%delenv ", 8)) {
			if (is_super_user()
			&& (is_envvar_exists(ln+8, EVC_OPTE_SET)
			|| is_envvar_exists(ln+8, EVC_OPTE_UNSET))) continue;

			delete_envvars(ln+8, EVC_CONF_SET, 1);
			delete_envvars(ln+8, EVC_CONF_UNSET, 1);
		}
		else if (!strncmp(ln, "%unsetenv ", 10)) {
			if (is_super_user()
			&& (is_envvar_exists(ln+10, EVC_OPTE_SET)
			|| is_envvar_exists(ln+10, EVC_OPTE_UNSET))) continue;

			delete_envvars(ln+10, EVC_CONF_SET, 1);
			add_envvar(ln+10, NULL, EVC_CONF_UNSET);
		}
		else if (!strncmp(ln, "%keepenv ", 9)) {
			if (is_super_user()
			&& (is_envvar_exists(ln+9, EVC_OPTE_SET)
			|| is_envvar_exists(ln+9, EVC_OPTE_UNSET))) continue;

			if (!is_envvar_exists(ln+9, EVC_KEEP_SET))
				add_envvar(ln+9, NULL, EVC_KEEP_SET);
		}
		else if (!strncmp(ln, "%unbanenv ", 10)) {
			embedded_variable_setstate(scary_envvars, scary_envvars_sz, ln+10, 0);
		}
		else if (!strncmp(ln, "%unkeepenv ", 11)) {
			if (!embedded_variable_setstate(trusted_envvars, trusted_envvars_sz, ln+11, 0))
				delete_envvars(ln+11, EVC_KEEP_SET, 1);
		}
		else if (!strncmp(ln, "%user ", 6)) continue; /* usermap stuff */
		else {
			size_t x = acs_strnlen(ln, ACS_ALLOC_MAX);
			long y = ftell(conffile);
			y -= x; y--;
			reset_conf(y > 0 ? y : 0);
			return;
		}
	}
}

void readin_usermaps(void)
{
	char *ln, *s;
	char *user, *hash, *udir, *shell;
	uid_t u; gid_t g;
	size_t sz;

	reset_conf(0);

	while ((ln = get_conf_line())) {
		user = hash = udir = shell = NULL;
		u = NOUID; g = NOGID;
		if (!strncmp(ln, "%user ", 6)) {
			ln += 6;
			if (acs_strchr(ln, ':')) { /* new passwd format (omitting gecos) */
				char *ss, *dd, *tt = NULL;
				int x = 0;
				ss = dd = ln;
				while ((ss = acs_strtok_r(dd, ":", &tt))) {
					if (dd) dd = NULL;
					switch (x) {
						case 0:
							user = ss;
							break;
						case 1:
							hash = ss;
							break;
						case 2:
							u = (uid_t)atoi(ss);
							break;
						case 3:
							g = (gid_t)atoi(ss);
							break;
						case 4:
							udir = ss;
							break;
						case 5:
							shell = ss;
							break;
					}
					x++;
				}
			}
			else if ((s = acs_strchr(ln, ' '))) { /* old "user hash" format */
				*s = 0; s++;
				hash = s;
				user = ln;
			}
			else continue;

			sz = DYN_ARRAY_SZ(usermaps);
			usermaps = acs_realloc(usermaps, (sz+1) * sizeof(struct usermap));
			usermaps[sz].uid = NOUID;
			usermaps[sz].gid = NOGID;

			usermaps[sz].user = acs_strdup(user);
			usermaps[sz].hash = acs_strdup(hash);
			if (u != NOUID) usermaps[sz].uid = u;
			if (g != NOGID) usermaps[sz].gid = g;
			if (udir) usermaps[sz].udir = acs_strdup(udir);
			if (shell) usermaps[sz].shell = acs_strdup(shell);
		}
		else if (!strcmp(ln, "%rules")) return;
		else if (ln[0] == '%') continue;
		else return;
	}
}

/* handle %set/%unset specification */
void set_variable(const char *spec, int init)
{
	char *s, *d;
	static char *setvar_tmp, *setvar_tmp2;
	size_t sz;
	struct fmtstr_args *fsa;
	size_t nr_fsa;
	struct fmtstr_state fst;

	if (!setvar_tmp) setvar_tmp = acs_malloc(ACS_ALLOC_MAX);
	if (!setvar_tmp2) setvar_tmp2 = acs_malloc(ACS_ALLOC_MAX);

	if (!spec || str_empty(spec)) return;

	acs_strlcpy(setvar_tmp, spec, ACS_ALLOC_MAX);
	s = setvar_tmp;

	if (!strcmp(s, "nocommands")) {
		nocommands = 1;
		return;
	}

	if (!strcmp(s, "pwecho")) {
		getp_flags &= ~GETP_NOECHO;
		return;
	}

	if (!strcmp(s, "fullinfo")) {
		fullinfo = 1;
		return;
	}

/* configurable ones. */
	d = acs_strchr(s, '=');
	if (!d) {
		/* no any? try to read it as flag. */
		resolve_flags(s, 1, &suflags, &argflags, &notargflags);
		return;
	}
	*d = 0;
	d++;

	/* Logs should be always parsed at end. */
	if (!strcmp(s, "logfmt")) init = 1;

	/* parse embedded format templates, if any */
	if (!init) preset_fsa_full(&fsa, &nr_fsa);
	else preset_fsa_basic(&fsa, &nr_fsa);
	acs_memzero(&fst, sizeof(struct fmtstr_state));
	fst.args = fsa;
	fst.nargs = nr_fsa;
	fst.fmt = d;
	fst.result = setvar_tmp2;
	fst.result_sz = ACS_ALLOC_MAX;

	parse_fmtstr(&fst);
	pfree(fsa);

	if (fst.trunc) return;
	parse_escapes(setvar_tmp2, acs_szalloc(setvar_tmp2));
	d = setvar_tmp2;

	if (!strcmp(s, "delay")) {
		delay = acs_atoll(d);
		return;
	}

	if (!strcmp(s, "spath")) {
		pfree(spath);
		spath = acs_strdup(d);
		if (!init) refind_exec = 1;
		return;
	}

	if (!strcmp(s, "supath")) {
		pfree(supath);
		supath = acs_strdup(d);
		if (!init) refind_exec = 1;
		return;
	}

	if (!strcmp(s, "logfile")) {
		pfree(logpath);
		logpath = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "prompt")) {
		pfree(prompt);
		prompt = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "minfd") && !isflag(argflags, ARG_C)) {
		minfd = atoi(d);
		return;
	}

	if (!strcmp(s, "maxfd")) {
		maxfd = atoi(d);
		return;
	}

	if (!strcmp(s, "denymsg")) {
		pfree(denymsg);
		denymsg = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "timefmt")) {
		pfree(timefmt);
		timefmt = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "logfmt")) {
		pfree(logfmt);
		logfmt = acs_strdup(d);
		return;
	}

#ifdef WITH_SKEIN_CRYPT
	if (!strcmp(s, "sk_localid")) {
		acs_strlcpy(sk_localid, d, sizeof(sk_localid));
		skein_configured = 1;
		return;
	}

	if (!strcmp(s, "sk_offset")) {
		sk_offset = atoi(d);
		skein_configured = 1;
		return;
	}

	if (!strcmp(s, "sk_passes")) {
		sk_passes = atoi(d);
		skein_configured = 1;
		return;
	}

	if (!strcmp(s, "sk_saltlen")) {
		sk_saltlen = atoi(d);
		skein_configured = 1;
		return;
	}

	if (!strcmp(s, "sk_datalen")) {
		sk_datalen = atoi(d);
		skein_configured = 1;
		return;
	}
#endif

	if (!strcmp(s, "pw")) {
		pfree(linepw);
		linepw = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "umask")) {
		if (sscanf(d, "%o", (unsigned int *)&dumask) < 1)
			dumask = DEFAULT_UMASK;
		return;
	}

	if (!strcmp(s, "fromtty")) {
		pfree(fromtty);
		fromtty = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "cwd")) {
		pfree(scwd);
		scwd = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "lockpath")) {
		pfree(lockpath);
		lockpath = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "audit")) {
		pfree(auditcmd);
		auditcmd = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "auditspath")) {
		pfree(auditspath);
		auditspath = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "auditret")) {
		if (sscanf(d, "%d", (int *)&auditret) < 1)
			auditret = 0;
		return;
	}

	if (!strcmp(s, "pwask")) {
		pfree(pwaskcmd);
		pwaskcmd = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "root")) {
		pfree(schrootdir);
		schrootdir = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "dir")) {
		pfree(sdstdir);
		sdstdir = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "blame")) {
		pfree(custom_blame_str);
		custom_blame_str = acs_strdup(d);
		return;
	}

	if (!strcmp(s, "blamecmd")) {
		pfree(blamecmd);
		blamecmd = acs_strdup(d);
		return;
	}

#ifdef WITH_REGEX
	if (!strcmp(s, "regex")) {
		if (yes_or_no(d) == YESNO_YES) match_type = MATCH_REGEX;
		return;
	}
#endif

	if (!strcmp(s, "fnmatch")) {
		if (yes_or_no(d) == YESNO_YES) match_type = MATCH_FNMATCH;
		else match_type = MATCH_STRCMP;
		return;
	}

#ifdef HAVE_SETPRIORITY
	if (!strcmp(s, "taskprio")) {
		taskprio_conf = atoi(d);
		return;
	}
#endif

	if (!strcmp(s, "rlimit")) {
		add_rlimspec(d);
		return;
	}

	/* user variable */
	sz = DYN_ARRAY_SZ(setvars);
	setvars = acs_realloc(setvars, (sz+2) * sizeof(char *));
	setvars[sz] = acs_strdup(s);
	setvars[sz+1] = acs_strdup(d);
}

void unset_variable(const char *name)
{
	size_t x, sz;

	if (!name || str_empty(name)) return;

	if (!strcmp(name, "pwecho")) {
		getp_flags |= GETP_NOECHO;
		return;
	}

	if (!strcmp(name, "nocommands")) {
		nocommands = 0;
		return;
	}

	if (!strcmp(name, "delay")) {
		delay = DELAY_WRPASS;
		return;
	}

	if (!strcmp(name, "spath")) {
		pfree(spath);
		spath = acs_strdup(SAFE_PATH);
		return;
	}

	if (!strcmp(name, "supath")) {
		pfree(supath);
		return;
	}

	if (!strcmp(name, "logfile")) {
		pfree(logpath);
		logpath = acs_strdup(PATH_LOG);
		return;
	}

	if (!strcmp(name, "prompt")) {
		pfree(prompt);
		prompt = acs_strdup(PASSWORD_PROMPT);
		return;
	}

	if (!strcmp(name, "minfd") && !isflag(argflags, ARG_C)) {
		minfd = 3;
		return;
	}

	if (!strcmp(name, "maxfd")) {
		maxfd = -1;
		return;
	}

	if (!strcmp(name, "denymsg")) {
		pfree(denymsg);
		return;
	}

	if (!strcmp(name, "timefmt")) {
		pfree(timefmt);
		return;
	}

	if (!strcmp(name, "logfmt")) {
		pfree(logfmt);
		return;
	}

#ifdef WITH_SKEIN_CRYPT
	if (!strncmp(name, "sk_", 3)
	&& (!strcmp(name+3, "localid")
	|| !strcmp(name+3, "offset")
	|| !strcmp(name+3, "passes")
	|| !strcmp(name+3, "saltlen")
	|| !strcmp(name+3, "datalen"))) {
		skein_configured = 0;
		return;
	}
#endif

	if (!strcmp(name, "pw")) {
		pfree(linepw);
		return;
	}

	if (!strcmp(name, "umask")) {
		dumask = DEFAULT_UMASK;
		return;
	}

	if (!strcmp(name, "fromtty")) {
		pfree(fromtty);
		return;
	}

	if (!strcmp(name, "cwd")) {
		pfree(scwd);
		return;
	}

	if (!strcmp(name, "lockpath")) {
		pfree(lockpath);
		return;
	}

	if (!strcmp(name, "audit")) {
		pfree(auditcmd);
		return;
	}

	if (!strcmp(name, "auditspath")) {
		pfree(auditspath);
		return;
	}

	if (!strcmp(name, "auditret")) {
		auditret = 0;
		return;
	}

	if (!strcmp(name, "pwask")) {
		pfree(pwaskcmd);
		return;
	}

	if (!strcmp(name, "root")) {
		pfree(schrootdir);
		return;
	}

	if (!strcmp(name, "dir")) {
		pfree(sdstdir);
		return;
	}

	if (!strcmp(name, "blame")) {
		pfree(custom_blame_str);
		return;
	}

	if (!strcmp(name, "blamecmd")) {
		pfree(blamecmd);
		return;
	}

#ifdef WITH_REGEX
	if (!strcmp(name, "regex")) {
		match_type = MATCH_FNMATCH;
		return;
	}
#endif

	if (!strcmp(name, "fnmatch")) {
		match_type = MATCH_STRCMP;
		return;
	}

#ifdef HAVE_SETPRIORITY
	if (!strcmp(name, "taskprio")) {
		taskprio_conf = taskprio_arg;
		return;
	}
#endif

	if (!strncmp(name, "rlimit", 6) && *(name+6) == '=') {
		remove_rlimspec(name+7);
		return;
	}

	sz = DYN_ARRAY_SZ(setvars);
	for (x = 0; x < sz; x += 2) {
		if (!setvars[x]) continue;
		if (!strcmp(name, setvars[x])) {
			pfree(setvars[x]);
			pfree(setvars[x+1]);
			return;
		}
	}
}

void close_conf(void)
{
	if (conffile) {
		fclose(conffile);
		conffile = NULL;
	}
}

#define UPDATEVAR(var)					\
	do {						\
		if (var) {				\
			s = var;			\
			var = preset_parse_fmtstr(var);	\
			pfree(s);			\
		}					\
	} while (0)
void update_vars(void)
{
	char *s;

	UPDATEVAR(spath);
	UPDATEVAR(supath);
	UPDATEVAR(fromtty);
	UPDATEVAR(scwd);
	UPDATEVAR(blamecmd);
	UPDATEVAR(auditcmd);
	UPDATEVAR(auditspath);
	UPDATEVAR(pwaskcmd);
	UPDATEVAR(schrootdir);
	UPDATEVAR(sdstdir);
}
#undef UPDATEVAR
