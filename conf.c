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

struct conf_stack {
	char *path; /* fs path */
	void *cfg; /* confdata handle */
};

static struct conf_stack *config_stack;

static struct conf_stack *get_cur_conf(void)
{
	size_t sz;

	sz = DYN_ARRAY_SZ(config_stack);
	if (sz == 0) return NULL;
	return &config_stack[sz-1];
}

static void *get_cur_conf_data(void)
{
	struct conf_stack *cfs;

	cfs = get_cur_conf();
	if (!cfs) return NULL;
	return cfs->cfg;
}

char *get_cur_conf_name(void)
{
	struct conf_stack *cfs;

	cfs = get_cur_conf();
	if (!cfs) return NULL;
	return cfs->path;
}

int *pget_cur_conf_lnum(void)
{
	struct conf_stack *cfs;

	cfs = get_cur_conf();
	if (!cfs) return NULL;
	return config_current_line_number(cfs->cfg);
}

int get_cur_conf_lnum(void)
{
	int *r = pget_cur_conf_lnum();
	if (!r) return 0;
	return *r;
}

static void add_conf_to_stack(const char *path, void *cfg)
{
	size_t sz;

	sz = DYN_ARRAY_SZ(config_stack);
	config_stack = acs_realloc(config_stack, (sz+1) * sizeof(struct conf_stack));
	config_stack[sz].path = acs_strdup(path);
	config_stack[sz].cfg = cfg;
}

int free_conf(void)
{
	size_t sz;

	sz = DYN_ARRAY_SZ(config_stack);
	if (sz == 0) return 0;
	pfree(config_stack[sz-1].path);
	free_config(config_stack[sz-1].cfg);
	config_stack = acs_realloc(config_stack, (sz-1) * sizeof(struct conf_stack));
	return 1;
}

void free_conf_all(void)
{
	while (1) if (!free_conf()) return;
}

char *get_conf_line(void)
{
	static char *confline;
	size_t x;
	char *line, *s, *d;
	void *cfg;

	if (!confline) confline = acs_malloc(ACS_ALLOC_MAX);

	cfg = get_cur_conf_data();
	if (!cfg) return NULL;

_again:
	line = get_config_line(cfg);
	if (!line) return NULL;
	if (is_comment(line)) goto _again;

	x = acs_strlcpy(confline, line, ACS_ALLOC_MAX-1);
	if (x == 0) goto _again;

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
_again2:	line = get_config_line(cfg);
		if (!line) {
			*s = 0;
			goto _done;
		}
		x = acs_strlcpy(s, line, ACS_ALLOC_MAX-1-(s-confline));
		if (x == 0) goto _again2;

		/* cleanup of leading tabs */
		d = s;
		while (*d) {
			if (*d == '\t') *d = 0;
			else break;
			d++;
		}
		/* This is comment? Get a new one! */
		if (is_comment(d)) goto _again2;
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

int open_conf(const char *path)
{
	struct stat st;
	int fd;
	void *cfg;

	if (lstat(path, &st) == -1) return 0;
	if (!cfg_permission(&st, 0)) {
		seterr("wrong mode");
		return 0;
	}

	fd = open(path, O_RDONLY);
	if (fd == -1) return 0;

	cfg = load_config(fd);
	if (!cfg) {
		close(fd);
		seterr("load_config failed");
		return 0;
	}

	close(fd);
	add_conf_to_stack(path, cfg);
	return 1;
}

#define xsetflag(x, y) do { setflag(x, y); if (single) goto _ret; } while (0)
#define xunsetflag(x, y) do { unsetflag(x, y); if (single) goto _ret; } while (0)
#define xnotargflag(z, x, y) do { z ? unsetflag(x, y) : setflag(x, y); if (single) goto _ret; } while (0)
void resolve_flags(const char *sflags, int single, acs_flag *suflags_p, acs_flag *argflags_p, acs_flag *notargflags_p)
{
	char *s, *d, *t;
	acs_flag suflags_l = 0, argflags_l = 0, notargflags_l = 0;
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
		if (!strcmp(s, "-log")) xunsetflag(&suflags_l, FLG_LOG);
		if (!strcmp(s, "logfail")) xsetflag(&suflags_l, FLG_LOGFAIL);
		if (!strcmp(s, "-logfail")) xunsetflag(&suflags_l, FLG_LOGFAIL);
		if (!strcmp(s, "tty")) xsetflag(&suflags_l, FLG_TTY);
		if (!strcmp(s, "-tty")) xunsetflag(&suflags_l, FLG_TTY);
		if (!strcmp(s, "pw")) xsetflag(&suflags_l, FLG_PW);
		if (!strcmp(s, "-pw")) {
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
		if (!strcmp(s, "clearenv")) xsetflag(&suflags_l, FLG_CLRENV);
		if (!strcmp(s, "userenv")) xunsetflag(&suflags_l, FLG_CLRENV);
		if (!strcmp(s, "keepenv")) xsetflag(&suflags_l, FLG_KEEPENV);
		if (!strcmp(s, "euid")) xunsetflag(&suflags_l, FLG_NOEUID);
		if (!strcmp(s, "-euid")) xsetflag(&suflags_l, FLG_NOEUID);
		if (!strcmp(s, "egid")) xunsetflag(&suflags_l, FLG_NOEGID);
		if (!strcmp(s, "-egid")) xsetflag(&suflags_l, FLG_NOEGID);
		if (!strcmp(s, "numid")) xunsetflag(&suflags_l, FLG_NONUMID);
		if (!strcmp(s, "-numid")) xsetflag(&suflags_l, FLG_NONUMID);
		if (!strcmp(s, "usronly")) {
			setflag(&suflags_l, FLG_USRONLY);
			setflag(&suflags_l, FLG_NOEUID);
			setflag(&suflags_l, FLG_NOEGID);
			setflag(&suflags_l, FLG_NONUMID);
			if (single) goto _ret;
		}
		if (!strcmp(s, "-usronly")) {
			unsetflag(&suflags_l, FLG_USRONLY);
			unsetflag(&suflags_l, FLG_NOEUID);
			unsetflag(&suflags_l, FLG_NOEGID);
			unsetflag(&suflags_l, FLG_NONUMID);
			if (single) goto _ret;
		}

		if (!is_super_user() && acs_strnlen(s, ACS_ALLOC_MAX) == 2
		&& ((*s == '+') || (*s == '-'))) {
			notarg = !!(*s == '-');
			carg = *(s+1);

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
				case 'L': xnotargflag(notarg, &notargflags_l, ARG_L); break;
#ifdef HAVE_SETPRIORITY
				case 'Q': xnotargflag(notarg, &notargflags_l, ARG_Q); break;
#endif
				case 'p': xnotargflag(notarg, &notargflags_l, ARG_p); break;
				case 'v': xnotargflag(notarg, &notargflags_l, ARG_v); break;
				case 'w': xnotargflag(notarg, &notargflags_l, ARG_w); break;
				case 'N': xnotargflag(notarg, &notargflags_l, ARG_N); break;
				case 'W': xnotargflag(notarg, &notargflags_l, ARG_W); break;
				case 'l': xnotargflag(notarg, &notargflags_l, ARG_l); break;
				default: break;
			}
		}
		if (!is_super_user() && !strcmp(s, "-login")) xnotargflag(1, &notargflags_l, ARG_l);

		if (!strcmp(s, "ttydt")) xsetflag(&suflags_l, FLG_TTYDETACH);
		if (!strcmp(s, "-ttydt")) xunsetflag(&suflags_l, FLG_TTYDETACH);
		if (!strcmp(s, "-lock")) xsetflag(&suflags_l, FLG_NOLOCK);
		if (!strcmp(s, "warnusr")) xsetflag(&suflags_l, FLG_WARNUSR);
		if (!strcmp(s, "-warnusr")) xunsetflag(&suflags_l, FLG_WARNUSR);
	}

_ret:	if (suflags_p) *suflags_p = suflags_l;
	if (argflags_p) *argflags_p = argflags_l;
	if (notargflags_p) *notargflags_p = notargflags_l;
}

void readin_default_settings(void)
{
	char *ln, *lnarg, *s;

	reset_config(get_cur_conf_data());

	while ((ln = get_conf_line())) {
		if (*ln == '%') {
			lnarg = acs_strchr(ln, ' ');
			if (lnarg) {
				*lnarg = 0;
				lnarg++;
			}
			else lnarg = ln;
		}
		else lnarg = ln;

		/*
		 * Explicit start of rules section.
		 * Why? Because no need to rewind.
		 */
		if (!strcmp(ln, "%rules")) {
			return;
		}
		/* No %unset really. Init stuff only! */
		else if (!strcmp(ln, "%set")) {
			set_variable(lnarg, 1);
		}
		else if (!strcmp(ln, "%setenv")) {
			s = acs_strchr(lnarg, '=');
			if (!s) continue;
			*s = 0; s++;

			if (is_envvar_exists(lnarg, EVC_CONF_UNSET)) continue;

			if (is_super_user()
			&& (is_envvar_exists(lnarg, EVC_OPTE_SET)
			|| is_envvar_exists(lnarg, EVC_OPTE_UNSET))) continue;

			add_envvar(lnarg, s, EVC_CONF_SET);
		}
		else if (!strcmp(ln, "%delenv")) {
			if (is_super_user()
			&& (is_envvar_exists(lnarg, EVC_OPTE_SET)
			|| is_envvar_exists(lnarg, EVC_OPTE_UNSET))) continue;

			if (builtin_envvar_enable(scary_envvars, scary_envvars_sz, lnarg, 0))
				continue;
			if (builtin_envvar_enable(trusted_envvars, trusted_envvars_sz, lnarg, 0))
				continue;

			delete_envvars(lnarg, EVC_KEEP_SET, 1);
			delete_envvars(lnarg, EVC_CONF_SET, 1);
			delete_envvars(lnarg, EVC_CONF_UNSET, 1);
		}
		else if (!strcmp(ln, "%unsetenv")) {
			if (is_super_user()
			&& (is_envvar_exists(lnarg, EVC_OPTE_SET)
			|| is_envvar_exists(lnarg, EVC_OPTE_UNSET))) continue;

			delete_envvars(lnarg, EVC_CONF_SET, 1);
			add_envvar(lnarg, NULL, EVC_CONF_UNSET);
		}
		else if (!strcmp(ln, "%keepenv")) {
			if (is_super_user()
			&& (is_envvar_exists(lnarg, EVC_OPTE_SET)
			|| is_envvar_exists(lnarg, EVC_OPTE_UNSET))) continue;

			if (!is_envvar_exists(lnarg, EVC_KEEP_SET))
				add_envvar(lnarg, NULL, EVC_KEEP_SET);
		}
		else if (!strcmp(ln, "%user")) continue; /* usermap stuff */
		else return;
	}
}

void readin_usermaps(void)
{
	char *ln, *lnarg, *s;
	char *user, *hash, *udir, *shell;
	uid_t u; gid_t g;
	size_t sz;

	reset_config(get_cur_conf_data());

	while ((ln = get_conf_line())) {
		user = hash = udir = shell = NULL;
		u = NOUID; g = NOGID;

		if (*ln == '%') {
			lnarg = acs_strchr(ln, ' ');
			if (lnarg) {
				*lnarg = 0;
				lnarg++;
			}
			else lnarg = ln;
		}
		else lnarg = ln;

		if (!strcmp(ln, "%user")) {
			if (acs_strchr(lnarg, ':')) { /* new passwd format (omitting gecos) */
				char *ss, *dd, *tt = NULL;
				int x = 0;
				ss = dd = lnarg;
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
			else if ((s = acs_strchr(lnarg, ' '))) { /* old "user hash" format */
				*s = 0; s++;
				hash = s;
				user = lnarg;
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

	if (!strcmp(s, "minfd")) {
		if (minfd == -1) return;
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

	if (!strcmp(s, "regexusers")) {
		if (yes_or_no(d) == YESNO_YES) regexusers = 1;
		else regexusers = 0;
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

	if (!strcmp(name, "minfd")) {
		if (minfd == -1) return;
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

	if (!strcmp(name, "regexusers")) {
		regexusers = 0;
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

#ifdef WITH_DACCESS_PROG
char *parse_client_conf(void)
{
	int fd;
	void *cfg;
	char *s, *d, *t;
	char *r = NULL;

	fd = open(CLIENT_PATH_CONF, O_RDONLY);
	if (fd != -1) {
		cfg = load_config(fd);
		if (!cfg) {
			close(fd);
			return NULL;
		}
		close(fd);

		while ((s = get_config_line(cfg))) {
			d = strchr(s, ' ');
			if (!d) continue;
			*d = 0; d++;

			if (!strcmp(s, "%spath")) {
				pfree(spath);
				spath = acs_strdup(d);
			}
			else if (!strcmp(s, "%setenv")) {
				t = strchr(d, '=');
				if (!t) continue;
				*t = 0; t++;
				acs_setenv(d, t, 1);
			}
			else if (!strcmp(s, "%unsetenv")) {
				acs_unsetenv(d);
			}
			else if (!strcmp(s, "%call")) {
				pfree(r);
				r = acs_strdup(d);
			}
		}

		free_config(cfg);
	}

	return r;
}
#endif
