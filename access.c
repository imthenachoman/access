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

extern char *matched_dir;
extern int refind_exec;

int askpass_filter(struct getpasswd_state *getps, char chr, size_t pos)
{
	if (chr == '\x03') { /* ^C */
		getps->retn = NOSIZE;
		getps->error = -1;
		return 6;
	}
	return 1;
}

#define pwasksetenv(to, fmt, ss, dd)								\
	do {											\
		size_t sz;									\
		acs_asprintf(&to, fmt, ss, dd);							\
		sz = DYN_ARRAY_SZ(tenvp);							\
		tenvp = acs_realloc(tenvp, (sz+(sz == 0 ? 2 : 1)) * sizeof(char *));		\
		if (sz) sz--;									\
		*(tenvp+sz) = acs_strdup(to);							\
	} while (0)
static void access_askpass(void)
{
	char *s, *passwd = NULL;
	struct fmtstr_args *fsa;
	size_t nr_fsa;
	struct fmtstr_state fst;
	struct getpasswd_state getps;
	size_t err;
	static char *prompt_parsed;

	if (!prompt_parsed) prompt_parsed = acs_malloc(ACS_ALLOC_SMALL);
	if (is_super_user()) return;

	if (isflag(suflags, FLG_PW)) {
		if (isflag(argflags, ARG_n)) blame("password required");

		passwd = acs_malloc(ACS_PASSWD_MAX);

		if (isflag(argflags, ARG_F)) {
			if (!fdgetstring(passwdfd, passwd, ACS_PASSWD_MAX))
				blame("wrong password fd %d", passwdfd);
		}
		else {
			char *pwusr;

			preset_fsa_full(&fsa, &nr_fsa);
			if (isflag(suflags, FLG_DSTPW))
				pwusr = dstusr;
			else if (isflag(suflags, FLG_SUPW))
				pwusr = suusr;
			else pwusr = srcusr;
			APPEND_FSA(fsa, nr_fsa, "pwusr", 0, "%s", pwusr);

			acs_memzero(&fst, sizeof(struct fmtstr_state));
			fst.args = fsa;
			fst.nargs = nr_fsa;
			fst.fmt = prompt;
			fst.result = prompt_parsed;
			fst.result_sz = acs_szalloc(prompt_parsed);
			parse_fmtstr(&fst);
			pfree(fsa);
			if (fst.trunc) xexits("bad prompt= parse state");

			/*
			 * Run external password asking program.
			 * Note that this program just asks user for password,
			 * and runs as superuser (the code is really the same as for audit program).
			 * It sets some envvars to help underlying code to setup environment.
			 *
			 * The protocol is simple: program runs, asks for password and
			 * writes it in plain to fd set in ACCESS_PWDFD envvar.
			 * Then it must return 0 to indicate success.
			 * If it returns something other than 0, this condition
			 * is interpreted as immediate failure -- user is blamed for that, reason
			 * string is set from the value written to fd instead, so be careful.
			 *
			 * ACCESS_PROMPT is set to parsed "%set prompt=" string.
			 *
			 * ACCESS_USERENV is to help a GUI program to orient itself.
			 *
			 * ACCESS{,_D}_USER/UID/GROUP(S)/GIDS are to identify who is who.
			 *
			 * ACCESS_PWUSR indicates for whom this password is asked.
			 *
			 * If one does not want to run password asking program as superuser,
			 * he can freely run it again with access as different user from already
			 * spawned password asking process (shell script wrapper).
			 */
			if (pwaskcmd && !isflag(argflags, ARG_N)) {
				int pwdfd[2];
				char **tpp, **targv, **tenvp;
				int x;

				if (pipe(pwdfd) != 0) xerror("pipe for %s failed", pwaskcmd);

				s = NULL;
				targv = tenvp = NULL;
				pwasksetenv(s, "%s=%s", "PATH", auditspath ? auditspath : get_spath());
				pwasksetenv(s, "%s=%d", "ACCESS_PWDFD", pwdfd[1]);
				pwasksetenv(s, "%s=%s", "ACCESS_PROMPT", prompt_parsed);
				pwasksetenv(s, "%s=%u", "ACCESS_UID", srcuid);
				pwasksetenv(s, "%s=%s", "ACCESS_USER", srcusr);
				pwasksetenv(s, "%s=%u", "ACCESS_GID", srcgid);
				pwasksetenv(s, "%s=%s", "ACCESS_GROUP", srcgrp);
				pwasksetenv(s, "%s=%s", "ACCESS_GIDS", srcgidss);
				pwasksetenv(s, "%s=%s", "ACCESS_GROUPS", srcgrps);
				pwasksetenv(s, "%s=%u", "ACCESS_D_UID", dstuid);
				pwasksetenv(s, "%s=%u", "ACCESS_D_EUID", dsteuid);
				pwasksetenv(s, "%s=%s", "ACCESS_D_USER", dstusr);
				pwasksetenv(s, "%s=%s", "ACCESS_D_EUSER", dsteusr);
				pwasksetenv(s, "%s=%u", "ACCESS_D_GID", dstgid);
				pwasksetenv(s, "%s=%u", "ACCESS_D_EGID", dstegid);
				pwasksetenv(s, "%s=%s", "ACCESS_D_GROUP", dstgrp);
				pwasksetenv(s, "%s=%s", "ACCESS_D_EGROUP", dstegrp);
				pwasksetenv(s, "%s=%s", "ACCESS_D_GIDS", dstgidss);
				pwasksetenv(s, "%s=%s", "ACCESS_D_GROUPS", dstfgrps);
				pwasksetenv(s, "%s=%s", "ACCESS_PWUSR", pwusr);
				pwasksetenv(s, "%s=%s", "ACCESS_USERENV", buserenv);
				pfree(s);

				s = acs_strdup(pwaskcmd);
				targv = parse_cmdline(s);
				if (!targv) xexits("pwask= is empty");
				tpp = targv;
				if (*(targv+1)) tpp++;
				if (is_abs_rel(*targv) != PATH_ABSOLUTE)
					xexits("%s: must be absolute path! Check the config.", *targv);
				reseterr();
				extern_prog_running = 1;
				x = forkexec(0, *targv, tpp, tenvp, NULL, pwdfd, passwd, ACS_PASSWD_MAX);
				if (errno) xerror("running password asking program \"%s\" failed", acs_basename(*targv));
				extern_prog_running = 0;
				destroy_argv(&tenvp);
				pfree(targv);
				pfree(s);
				if (x != 0) {
					if (acs_strnlen(passwd, ACS_ALLOC_MAX))
						blame("%s", passwd);
					else blame("user aborted password asking program: %d", x);
				}
			}
			else {
				acs_memzero(&getps, sizeof(struct getpasswd_state));
				if (ttyinfo.fd != -1) getps.fd = getps.efd = ttyinfo.fd;
				else getps.fd = getps.efd = -1;
				getps.passwd = passwd;
				getps.pwlen = ACS_PASSWD_MAX;
				getps.echo = prompt_parsed;
				getps.charfilter = askpass_filter;
				getps.maskchar = 'x';
				getps.flags = getp_flags;

				err = acs_getpasswd(&getps);

				if (err == NOSIZE) {
					if (getps.error != -1)
						blame("reading password: %s",
						acs_strerror(getps.error));

					blame("password input rejected by user");
				}
			}

			acs_memzero(prompt_parsed, acs_szalloc(prompt_parsed));
		}

		if (block_tty(&ttyinfo, 1) == -1) xerror("blocking tty");

		if (linepw) { /* pw=$U$salt$hash */
			if (strcmp(acs_crypt(passwd, linepw), linepw) != 0)
				blame("wrong line password");
		}
		else if (isflag(suflags, FLG_DSTPW)) { /* destination user password? */
			if (!match_password(dstusr, passwd))
				blame("wrong password for %s", dstusr);
		}
		else if (isflag(suflags, FLG_SUPW)) { /* superuser password? */
			if (!match_password(suusr, passwd))
				blame("wrong superuser password");
		}
		else { /* No, invoker user password. */
			if (!match_password(srcusr, passwd))
				blame("wrong password");
		}

		pfree(passwd);
	}

	if (block_tty(&ttyinfo, 0) == -1) xerror("unblocking tty");
}
#undef pwasksetenv

#define first_arg argv[acs_optind]

int main(int argc, char **argv)
{
	int x, c;
	size_t n;
	char *s, *d, *t, *T;
	char *loginshell = NULL;
	char **tpp;
	int usage_long_req = 0;
	char *c_arg = NULL, *d_arg = NULL;
	flagtype pui_flags = 0;
	pid_t bgpid;
	gid_t tgid, *tgids;
	int tgsz;

	/* Ignore most signals at the init time, install SIGSEGV handler. */
	install_signals(SIG_IGN);

	if (*argv) set_progname(*argv);
	else set_progname(PROGRAM_NAME);

	ourpid = getpid();
	parentpid = getppid();

	/* Init required variables */
	spath = acs_strdup(SAFE_PATH);
	logpath = acs_strdup(PATH_LOG);
	prompt = acs_strdup(PASSWORD_PROMPT);
	denymsg = acs_strdup(DENY_MSG);

#ifdef WITH_RESETRLIMITS
	if (is_setuid()
	&& !(!strcmp(progname, "daccess")
	|| !strcmp(progname, "daccessc")
	|| !strcmp(progname, "daccessd"))) {
		/* save current user limits before ANY code runs */
		preserve_user_limits();
		reset_user_limits();
	}
#endif

	acs_opterr = 0;

/* Get info about asking user */
	srcuid = getuid();
	srcgid = getgid();
	srcgsz = getgroups(0, NULL);
	if (srcgsz == -1) srcgsz = ACS_ALLOC_SMALL;
	srcgids = acs_malloc(srcgsz * sizeof(gid_t));
	srcgsz = getgroups(srcgsz, srcgids);

#ifdef WITH_SU_PROG
	if (!strcmp(progname, "su")) return su_main(argc, argv, srcuid, srcgid, srcgsz, srcgids);
#endif
#ifdef WITH_ACSMATCH_PROG
	if (!strcmp(progname, "acsmatch")) return acsmatch_main(argc, argv, srcuid, srcgid, srcgsz, srcgids);
#endif
#ifdef WITH_DACCESS_PROG
	if (!strcmp(progname, "daccess")
	|| !strcmp(progname, "daccessc")
	|| !strcmp(progname, "daccessd")) return daccess_main(argc, argv, srcuid, srcgid, srcgsz, srcgids);
#endif

/* |--^,--^,--^,--^,-- invoker - access border line --^,--^,--^,--^,--^,--^,--^,--^,--^,--^,--^,--^,--| */

/*
 * Raise any privilege to maximum:
 * don't let invoker to kill us without leaving a note in log
 * blame for every mistake
 * parse opts in protected environment
 */
#ifdef HAVE_ISSETUGID
	if (!issetugid()) {
#ifdef WITH_DACCESS_PROG
		s = parse_client_conf();
		if (s) {
			d = find_access_exec(s);
			if (!d) goto _notfoundiss;
			argv[0] = s;
			if (execv(d, argv) == -1) xerror_status(127, "execv");
_notfoundiss:		acs_exit(127);
		}
#endif
		xexits("is not marked as setuid executable");
	}
#endif
	if (!runaway()) {
#ifdef WITH_DACCESS_PROG
		int sverrno = errno;

		s = parse_client_conf();
		if (s) {
			d = find_access_exec(s);
			if (!d) goto _notfoundrun;
			argv[0] = s;
			if (execv(d, argv) == -1) xerror_status(127, "execv");
_notfoundrun:		acs_exit(127);
		}
		errno = sverrno;
#endif
		acs_perror("becoming superuser");
		xexits("is not marked as setuid executable, or otherwise did not\n"
		"permitted to have it's euid set to be superuser to do it's\n"
		"routine privileged work. The message(s) above explain why.");
	}
#ifdef WITH_RESETRLIMITS
	if (prsvrlims_fail) {
		xexits("failed resetting resource limits to sane values or setting them back.");
	}
#endif
#ifdef _POSIX_MEMLOCK
	if (!lockpages()) xexits("locking pages into memory failed");
#endif
/* Ignore any signals at this point, I do not want garbage in the logs */
	install_signals(SIG_IGN);

#ifdef WITH_RESETRLIMITS
	/* do that again */
	reset_user_limits();
#endif

	cwd = acs_getcwd();
	if (!cwd) xerror("getting working directory");

	tty_init();

	dstuid = dsteuid = NOUID;
	dstgid = dstegid = NOGID;
	dstgids = acs_malloc(sizeof(gid_t));
	dstgids[0] = NOGID;

	suusr = namebyuid(0);
	srcusr = namebyuid(srcuid);
	srcgrp = namebygid(srcgid);
	srcgrps = build_usergroups(srcgsz, srcgids, 0, 0);
	srcgidss = build_usergroups(srcgsz, srcgids, 0, 1);

/* Open our configuration */
	if (!open_conf(PATH_CONF)) if (!is_super_user()) xerror("%s", PATH_CONF);
/*
 * So I need to do that early, because of extended virtual user format
 * THIS can affect REAL user information, but only when extended %user is used!
 */
	readin_usermaps();

#ifdef WITH_ACSMKPWD_PROG
	if (!strcmp(progname, "acsmkpwd")) return acsmkpwd_main(argc, argv, srcuid, srcgid, srcgsz, srcgids);
#endif
#ifdef WITH_ACSTESTAUTH_PROG
	if (!strcmp(progname, "acstestauth")) return acstestauth_main(argc, argv, srcuid, srcgid, srcgsz, srcgids);
#endif

/* Support setuid scripts and others who pass all args as single argv cell */
	if (argc >= 3 && acs_strchr(*(argv+1), ' ')) {
		hashbang = acs_strdup(*(argv+1));
		refine_argv(&argc, &argv, 1);
	}

/* remaining s_getopt chars: */
/* 'ijkmoqrz' */
/* 'HJKMOYZ' */
	acs_optind = 1;
	while ((c = acs_getopt(argc, argv, "u:U:g:G:s:S:e:Ec:C:a:AbBfF:hIlL:nNPQ:R:d:DtTpvVwWxXy")) != -1) {
		switch (c) {
			case 'b':
				setflag(&argflags, ARG_b);
				break;
			case 'B':
				setflag(&argflags, ARG_B);
				break;
			case 'f':
				if (!is_super_user()) xexits("only superuser can do this.");
				free_conf_all();
				break;
			case 'F':
				setflag(&argflags, ARG_F);
				if (is_number(acs_optarg, 0)) passwdfd = atoi(acs_optarg);
				else xexits("%s: invalid fd number", acs_optarg);
				break;
			case 'C':
				setflag(&argflags, ARG_C);
				if (!strcmp(acs_optarg, "noclose")) {
					if (!is_super_user()) xexits("only superuser can do this.");
					minfd = -1;
				}
				else {
					if (is_number(acs_optarg, 0)) minfd = atoi(acs_optarg);
					else xexits("%s: invalid fd number", acs_optarg);
				}
				break;
			case 'c':
				pfree(c_arg);
				c_arg = acs_strdup(acs_optarg);
				break;
			case 'u':
				setflag(&pui_flags, UARG_u);
				pfree(dstusr);
				dstusr = acs_strdup(acs_optarg);
				dstuid = uidbyname(dstusr);
				if (dstuid == NOUID) xerror("%s", dstusr);
				dstgid = gidbyuid(dstuid);
				if (dstgid == NOGID) dstgid = (gid_t)dstuid;
				break;
			case 'U':
				pfree(dsteusr);
				dsteusr = acs_strdup(acs_optarg);
				dsteuid = uidbyname(dsteusr);
				if (dsteuid == NOUID) xerror("%s", dsteusr);
				break;
			case 'g':
				setflag(&pui_flags, UARG_g);
				pfree(dstgrp);
				dstgrp = acs_strdup(acs_optarg);
				dstgid = gidbyname(dstgrp);
				if (dstgid == NOGID) xerror("%s", dstgrp);
				break;
			case 'G':
				pfree(dstegrp);
				dstegrp = acs_strdup(acs_optarg);
				dstegid = gidbyname(dstegrp);
				if (dstegid == NOGID) xerror("%s", dstegrp);
				break;
			case 's':
				if (dstgrps) xexits("-s and -S are mutually exclusive");
				pfree(dstgrps);
				dstgrps = acs_strdup(acs_optarg);
				if (acs_strchr(dstgrps, '+') || acs_strchr(dstgrps, '-'))
					xexits("-s sets absolute grouplist, not relative to existing one");

				T = acs_strdup(acs_optarg);
				s = d = T; t = NULL;
				while ((s = acs_strtok_r(d, ",", &t))) {
					if (d) d = NULL;
					tgid = gidbyname(s);
					if (tgid == NOGID) xerror("%s", s);
					dstgids = acs_realloc(dstgids, (dstgsz+1) * sizeof(gid_t));
					dstgids[dstgsz] = tgid;
					dstgsz++;
				}
				pfree(T);
				break;
			case 'S':
				setflag(&argflags, ARG_S);
				if (dstgrps) xexits("-s and -S are mutually exclusive");
				pfree(dstgrps);
				dstgrps = acs_strdup(acs_optarg);

				if (!dstusr) {
					if (isflag(argflags, ARG_x)) {
						if (dstuid == NOUID) dstuid = srcuid;
						if (dstgid == NOGID) dstgid = srcgid;
					}
					else {
						if (dstuid == NOUID) dstuid = 0;
						if (dstgid == NOGID) dstgid = 0;
					}
					dstusr = namebyuid(dstuid);
				}

				tgids = acs_malloc(sizeof(gid_t));
				tgsz = 1;
				if (getugroups(dstusr, dstgid, tgids, &tgsz) == -1) {
					tgids = acs_realloc(tgids, tgsz * sizeof(gid_t));
					if (getugroups(dstusr, dstgid, tgids, &tgsz) == -1)
						xerror("%s", dstusr);
				}

				T = acs_strdup(acs_optarg);
				s = d = T; t = NULL;
				while ((s = acs_strtok_r(d, ",", &t))) {
					if (d) d = NULL;

					if ((*s == '+')
					|| (is_super_user() && (*s != '+' && *s != '-'))) {
						if (*s == '+') s++;
						tgid = gidbyname(s);
						if (tgid == NOGID) xerror("%s", s);
						tgids = acs_realloc(tgids, (tgsz+1) * sizeof(gid_t));
						tgids[tgsz] = tgid;
						tgsz++;
					}
					else if (*s == '-') {
						s++;
						tgid = gidbyname(s);
						if (tgid == NOGID) xerror("%s", s);
						for (x = 0; x < tgsz; x++)
							if (tgid == tgids[x]) tgids[x] = NOGID;
					}
					else xexits("usage: -S +gid,+group,-gid,...");
				}
				for (x = 0, dstgsz = 0; x < tgsz; x++) {
					if (tgids[x] != NOGID) {
						dstgids = acs_realloc(dstgids, (dstgsz+1) * sizeof(gid_t));
						dstgids[dstgsz] = tgids[x];
						dstgsz++;
					}
				}
				pfree(tgids); tgsz = 0;
				pfree(T);
				break;
			case 't':
				dsteuid = 0;
				dsteusr = namebyuid(dsteuid);
				break;
			case 'T':
				dstegid = 0;
				dstegrp = namebygid(dstegid);
				break;
			case 'a':
				setflag(&argflags, ARG_a);
				pfree(renamed_first_arg);
				renamed_first_arg = acs_strdup(acs_optarg);
				break;
			case 'A':
				setflag(&argflags, ARG_A);
				break;
			case 'P':
				setflag(&argflags, ARG_P);
				break;
			case 'I':
			case 'l':
				setflag(&argflags, ARG_l);
				if (c == 'I') setflag(&argflags, ARG_I);
				break;
			case 'L':
				setflag(&argflags, ARG_L);
				add_rlimspec(acs_optarg);
				break;
			case 'Q':
#ifdef HAVE_SETPRIORITY
				setflag(&argflags, ARG_Q);
				if (is_number(acs_optarg, 1))
					taskprio_arg = taskprio_conf = atoi(acs_optarg);
				else xexits("%s: invalid priority number", acs_optarg);
#else
				xexits("priority adjusting is not available");
#endif
				break;
			case 'e':
				setflag(&argflags, ARG_e);
				if (is_scary_envvar(acs_optarg)) break;
				if (acs_strchr(acs_optarg, '=')) {
					add_envvar_pair(acs_optarg, EVC_OPTE_SET);
				}
				else {
					delete_envvars(acs_optarg, EVC_OPTE_SET, 0);
					add_envvar_pair(acs_optarg, EVC_OPTE_UNSET);
				}
				break;
			case 'E':
				setflag(&argflags, ARG_E);
				break;
			case 'D':
				setflag(&argflags, ARG_D);
				break;
			case 'd':
				setflag(&argflags, ARG_d);
				if (isflag(argflags, ARG_D)
				&& is_abs_rel(acs_optarg) != PATH_ABSOLUTE) {
					d_arg = acs_strdup(acs_optarg);
				}
				else {
					pfree(dstdir);
					dstdir = acs_realpath(acs_optarg);
					if (!dstdir) {
						if (chrootdir) {
							s = NULL;
							acs_asprintf(&s, "%s%s", chrootdir, acs_optarg);
							d = acs_realpath(s);
							if (d) {
								dstdir = acs_strdup(acs_optarg);
								pfree(d);
								pfree(s);
								break;
							}
						}
						if (is_super_user()) {
							acs_perror("%s", acs_optarg);
							dstdir = acs_strdup(default_root);
						}
						else xerror("%s", acs_optarg);
					}
				}
				break;
			case 'n':
				setflag(&argflags, ARG_n);
				break;
			case 'N':
				setflag(&argflags, ARG_N);
				break;
			case 'R':
				pfree(chrootdir);
				chrootdir = acs_realpath(acs_optarg);
				if (!chrootdir) xerror("%s", acs_optarg);
				pfree(dstdir);
				dstdir = acs_strdup(default_root);
				if (!strcmp(chrootdir, default_root)) pfree(chrootdir);
				break;
			case 'p':
				setflag(&argflags, ARG_p);
				break;
			case 'v':
				setflag(&argflags, ARG_v);
				break;
#ifdef _ACCESS_VERSION
			case 'V':
				arg_V_cnt++;
				if (arg_V_cnt > 2) arg_V_cnt = 2;
				break;
#endif
			case 'w':
				setflag(&argflags, ARG_w);
				break;
			case 'x':
				setflag(&argflags, ARG_x);
				arg_x_cnt++;
				if (arg_x_cnt > 2) arg_x_cnt = 2;
				break;
			case 'X':
				setflag(&argflags, ARG_x);
				setflag(&argflags, ARG_X);
				break;
			case 'y':
				setflag(&argflags, ARG_y);
				break;
			case 'W':
				setflag(&argflags, ARG_W);
				break;
			case 'h':
			default: usage_long_req = 1; break;
		}
	}

	notargflags = argflags;
/* Set default flags */
	resolve_flags(DEFAULT_FLAGS, 0, &suflags, &argflags, &notargflags);
/* Try to read "defaults" (former %def) before any first rule will be met */
	readin_default_settings();
/* Kill all the scary envvars. */
	kill_scary_envvars(is_super_user());
/* Init datestamps, with defaults applied already */
	init_datetime();

	if (usage_long_req) usage_long();
#ifdef _ACCESS_VERSION
	if (arg_V_cnt) show_version();
#endif

	if ((!first_arg || str_empty(first_arg))
	&& !isflag(argflags, ARG_l) && !c_arg) usage();

	if (!isflag(argflags, ARG_l)) {
		cmdline = build_cmdline(argc-acs_optind, argv+acs_optind);
		if (fullinfo) bcmdline = build_protected_cmdline(argc-acs_optind, argv+acs_optind);
	}

	if (isflag(argflags, ARG_x)) {
		if (dstuid == NOUID) dstuid = srcuid;
		if (dstgid == NOGID) dstgid = srcgid;
		if (arg_x_cnt == 2) {
			dstgids = acs_realloc(dstgids, srcgsz * sizeof(gid_t));
			for (dstgsz = 0; dstgsz < srcgsz; dstgsz++)
				dstgids[dstgsz] = srcgids[dstgsz];
			dstgrps = dstfgrps = build_usergroups(dstgsz, dstgids, 0, 0);
		}
	}
	else {
		if (dstuid == NOUID) dstuid = 0;
		if (dstgid == NOGID) dstgid = 0;
	}
	if (isflag(argflags, ARG_X)) {
		if (dstgids[0] == NOGID) {
			dstgsz = 1;
			dstgids = acs_realloc(dstgids, dstgsz * sizeof(gid_t));
			dstgids[0] = dstgid;
			dstgrps = dstfgrps = build_usergroups(dstgsz, dstgids, 0, 0);
		}
	}
	if (dsteuid == NOUID) dsteuid = dstuid;
	if (dstegid == NOGID) dstegid = dstgid;

	if (!dstusr) dstusr = namebyuid(dstuid);
	if (!dsteusr) dsteusr = dstusr;
	if (!dstgrp) dstgrp = namebygid(dstgid);
	if (!dstgrp) dstgrp = dstusr;
	if (!dstegrp) dstegrp = dstgrp;
	if (!dstgrps) {
		dstgsz = DYN_ARRAY_SZ(dstgids);
		if (getugroups(dstusr, dstgid, dstgids, &dstgsz) == -1) {
			dstgids = acs_realloc(dstgids, dstgsz * sizeof(gid_t));
			if (getugroups(dstusr, dstgid, dstgids, &dstgsz) == -1)
				xerror("%s", dstusr);
		}
		dstgrps = dstfgrps = build_usergroups(dstgsz, dstgids, 0, 0);
	}
	else dstfgrps = build_usergroups(dstgsz, dstgids, 0, 0);
	dstgidss = build_usergroups(dstgsz, dstgids, 0, 1);

	dstusrdir = udirbyname(dstusr);
	if (d_arg) {
		s = NULL;
		acs_asprintf(&s, "%s/%s", dstusrdir, d_arg);
		pfree(dstdir);
		dstdir = acs_realpath(s);
		if (!dstdir) {
			if (chrootdir) {
				d = NULL;
				acs_asprintf(&d, "%s%s/%s", chrootdir, dstusrdir, d_arg);
				t = acs_realpath(d);
				if (t) {
					dstdir = acs_strdup(s);
					pfree(t);
					pfree(d);
					goto _d_arg_out;
				}
			}
			if (is_super_user()) {
				acs_perror("%s", s);
				dstdir = acs_strdup(dstusrdir);
			}
			else xerror("%s", s);
		}
_d_arg_out:	pfree(s);
		pfree(d_arg);
	}
	if (!dstdir) {
		if (isflag(argflags, ARG_l)
		|| isflag(argflags, ARG_D)) s = dstusrdir;
		else s = cwd;
		dstdir = acs_strdup(s);
	}

	if (isflag(argflags, ARG_I)) dstusrshell = acs_strdup(default_shell);
	else dstusrshell = shellbyname(dstusr);
	if (isflag(argflags, ARG_l)) {
		cmdline = acs_strdup(dstusrshell);
		s = NULL;
		loginshell = acs_strdup(dstusrshell);
		s = acs_basename(loginshell);
		acs_asprintf(&renamed_first_arg, "-%s", s);
		if (fullinfo) {
			char *t[3];
			t[0] = cmdline; t[1] = renamed_first_arg; t[2] = NULL;
			bcmdline = build_protected_cmdline(2, t);
		}
	}

	if (isflag(argflags, ARG_A)
	&& !isflag(argflags, ARG_a)
	&& !isflag(argflags, ARG_l)) acs_asprintf(&renamed_first_arg, "-%s", first_arg);

	if (c_arg) print_uidinfos(c_arg, pui_flags);

	if (!cmdline || str_empty(cmdline)) usage();

	execname = acs_strdup(isflag(argflags, ARG_l) ? dstusrshell : first_arg);
	if (is_super_user()) { /* check if superuser had given "-e PATH=..." */
		x = is_envvar_exists("PATH", EVC_OPTE_SET);
		if (x) d = envvars[x-1].value;
		else d = get_spath();
	}
	else d = get_spath();
	find_new_exec(d, execname, chrootdir);

/* Start logging, read our initial configuration, if user is not access */
	if (is_super_user()) goto _bypass;

	/* Do whole rules list match. */
	while (1) {
		auth = execute_rule_match();
		if (auth == -1) {
			auth = 0;
			break;
		}
		if (auth) break;
	}

	/* in case if there was "%set timefmt=" from rules */
	update_datetime();

	/* rescan if new spath was touched */
	if (refind_exec) find_new_exec(get_spath(), execname, chrootdir);

	if (!execfpath) { /* not found */
		/* try to parse all things anyway */
		update_vars();
		if (is_abs_rel(execname)) s = execname;
		else s = acs_basename(execname);
		xexits_status(127, "%s: not found.", s);
	}

	if (matched_dir) { /* compare dirs, reject if exec is from another one */
		n = acs_strnlen(matched_dir, ACS_ALLOC_MAX);
		if (strncmp(matched_dir, execpath, n) != 0) auth = 0;

		pfree(matched_dir);
	}

	/* This comes from rules. Do not move. */
	if ((auditcmd || pwaskcmd || blamecmd) || fullinfo) {
		if (auditcmd || blamecmd) bfullargv = build_protected_cmdline(argc, argv);
		tpp = environ;
		for (x = 0; tpp[x]; x++);
		buserenv = build_protected_cmdline(x, tpp);
	}

	/* update format templates inside variables */
	update_vars();

	if (!isflag(suflags, FLG_NOLOCK) && !create_lockfile())
		blame("another " PROGRAM_NAME " is running");

	if (!auth) blame("no permission");
	if (isflag(suflags, FLG_FALSE)) blame("no permission");
	if (isflag(suflags, FLG_NONUMID)
	&& (is_number(dstusr, 0) || is_number(dsteusr, 0)
	|| is_number(dstgrp, 0) || is_number(dstegrp, 0) || is_numbergrps(dstgrps))) blame("only user names are permitted");

	if (argflags & ~notargflags) {
		/* Ask user for password if option flag is banned, instead of punishing early. */
		if (isflag(suflags, FLG_PWINVALOPT)) {
			setflag(&suflags, FLG_PW);
			/* and let admin override then for which pw type is to ask */
		}
		else blame("protected cmdline switch");
	}
	if (isflag(suflags, FLG_TTY) && ttyinfo.fd == -1) blame("not a tty");

	/* actually ask user for his password. */
	access_askpass();

_bypass: /* I am already superuser */
	if (is_super_user() && !execfpath) { /* not found in superuser mode */
		if (is_abs_rel(execname)) s = execname;
		else s = acs_basename(execname);
		xexits_status(127, "%s: not found.", s);
	}

	umask(dumask);

	/* Set all needed envvars */
	set_user_environ();

/* Jump over */
	if (is_super_user()) goto _bypassaudit;

	if ((auditcmd || blamecmd) || fullinfo) {
		tpp = environ;
		for (x = 0; tpp[x]; x++);
		benviron = build_protected_cmdline(x, tpp);
	}

/*
 * Now a big audit code goes here: pass all collected
 * precious information to external auditing program.
 * Last barrier where authentication can be aborted.
 */
#define auditsetenv(to, fmt, ss, dd)								\
	do {											\
		size_t sz;									\
		acs_asprintf(&to, fmt, ss, dd);							\
		sz = DYN_ARRAY_SZ(tenvp);							\
		tenvp = acs_realloc(tenvp, (sz+(sz == 0 ? 2 : 1)) * sizeof(char *));		\
		if (sz) sz--;									\
		*(tenvp+sz) = acs_strdup(to);							\
	} while (0)

	if (!is_super_user() && auditcmd) {
		int pfd[2];
		char **targv, **tenvp;

		if (isflag(argflags, ARG_n)) blame("auditor may ask for password");

		if (pipe(pfd) != 0) xerror("pipe for %s failed", auditcmd);

		s = T = NULL;
		targv = tenvp = NULL;
		auditsetenv(s, "%s=%d", "ACCESS_RSNFD", pfd[1]);

		auditsetenv(s, "%s=%u", "ACCESS_PID", ourpid);
		auditsetenv(s, "%s=%u", "ACCESS_PPID", parentpid);

		auditsetenv(s, "%s=%s", "ACCESS_DATETIME", curr_date);
		auditsetenv(s, "%s=%u", "ACCESS_TIMESTAMP", curr_time);

		auditsetenv(s, "%s=%u", "ACCESS_UID", srcuid);
		auditsetenv(s, "%s=%s", "ACCESS_USER", srcusr);
		auditsetenv(s, "%s=%u", "ACCESS_GID", srcgid);
		auditsetenv(s, "%s=%s", "ACCESS_GROUP", srcgrp);
		auditsetenv(s, "%s=%s", "ACCESS_GIDS", srcgidss);
		auditsetenv(s, "%s=%s", "ACCESS_GROUPS", srcgrps);

		auditsetenv(s, "%s=%u", "ACCESS_D_UID", dstuid);
		auditsetenv(s, "%s=%u", "ACCESS_D_EUID", dsteuid);
		auditsetenv(s, "%s=%s", "ACCESS_D_USER", dstusr);
		auditsetenv(s, "%s=%s", "ACCESS_D_EUSER", dsteusr);
		auditsetenv(s, "%s=%u", "ACCESS_D_GID", dstgid);
		auditsetenv(s, "%s=%u", "ACCESS_D_EGID", dstegid);
		auditsetenv(s, "%s=%s", "ACCESS_D_GROUP", dstgrp);
		auditsetenv(s, "%s=%s", "ACCESS_D_EGROUP", dstegrp);
		auditsetenv(s, "%s=%s", "ACCESS_D_GIDS", dstgidss);
		auditsetenv(s, "%s=%s", "ACCESS_D_GROUPS", dstfgrps);

		auditsetenv(s, "%s=%s", "ACCESS_FLAGS", trigflags);

		auditsetenv(s, "%s=%s", "ACCESS_CONF", get_cur_conf_name());
		auditsetenv(s, "%s=%s", "ACCESS_LINE", trigline);
		auditsetenv(s, "%s=%u", "ACCESS_LINE_NUMBER", get_cur_conf_lnum());

		auditsetenv(s, "%s=%s", "ACCESS_MATCH_TYPE", get_match_type(match_type));

		auditsetenv(s, "%s=%s", "ACCESS_BINPATH", execfpath);
		auditsetenv(s, "%s=%s", "ACCESS_CMDLINE", cmdline);
if (hashbang) {	auditsetenv(s, "%s=%s", "ACCESS_HASHBANG", hashbang); }

		auditsetenv(s, "%s=%s", "ACCESS_USERENV", buserenv);
		auditsetenv(s, "%s=%s", "ACCESS_ENVIRON", benviron);

		auditsetenv(s, "%s=%u", "ACCESS_FIRST_ARG", acs_optind);
		auditsetenv(s, "%s=%s", "ACCESS_ARGS", bfullargv);
		auditsetenv(s, "%s=%s", "PATH", auditspath ? auditspath : get_spath());
		auditsetenv(s, "%s=%s", "ACCESS_PATH", get_spath());

		auditsetenv(s, "%s=%s", "ACCESS_LOCKFILE", lockfile ? lockfile : "<unset>");

if (ttyinfo.fd != -1) {
		auditsetenv(s, "%s=%s", "ACCESS_TTY", ttyinfo.ttyname);
}
		auditsetenv(s, "%s=%s", "ACCESS_CWD", cwd);
		auditsetenv(s, "%s=%s", "ACCESS_USRDIR", dstusrdir);
		auditsetenv(s, "%s=%s", "ACCESS_USRSHELL", dstusrshell);
if (isflag(argflags, ARG_D) || isflag(argflags, ARG_d)) {
		auditsetenv(s, "%s=%s", "ACCESS_CHDIR", dstdir);
}
if (schrootdir && chrootdir) {
		auditsetenv(s, "%s=%s", "ACCESS_CHROOT", chrootdir);
}
#ifdef SYSLOG_SUPPORT
		auditsetenv(s, "%s=%s", "ACCESS_LOG", isflag(suflags, FLG_SYSLOG) ? "<syslog>" : logpath);
#else
		auditsetenv(s, "%s=%s", "ACCESS_LOG", logpath);
#endif
#ifdef _ACCESS_VERSION
		auditsetenv(s, "%s=%s", "ACCESS_VERSION", _ACCESS_VERSION);
#endif
		pfree(s);

		T = acs_malloc(ACS_PASSWD_MAX);
		s = acs_strdup(auditcmd);
		targv = parse_cmdline(s);
		if (!targv) xexits("audit= is empty");
		tpp = targv;
		if (*(targv+1)) tpp++;
		if (is_abs_rel(*targv) != PATH_ABSOLUTE)
			xexits("%s: must be absolute path! Check the config.", *targv);
		reseterr();
		extern_prog_running = 1;
		auditreturn = forkexec(0, *targv, tpp, tenvp, &auditpid, pfd, T, ACS_PASSWD_MAX);
		if (errno) xerror("running audit program \"%s\" failed", acs_basename(*targv));
		extern_prog_running = 0;
		destroy_argv(&tenvp);
		pfree(targv);
		pfree(s);
		if (auditreturn != auditret) {
			if (auditreturn >= 252 && auditreturn <= 254) {
				setflag(&suflags, FLG_PW);
				switch (auditreturn) {
					case 252: setflag(&suflags, FLG_SUPW); break;
					case 253: setflag(&suflags, FLG_DSTPW); break;
					/* 254 is catched by FLG_PW, own user password */
				}
				/* actually ask user for his password. */
				access_askpass();
			}
			else {
				newline_to_nul(T, ACS_PASSWD_MAX);
				s = d = T;
				if (!strncmp(T, "<hide>:", 7)) {
					d += 7;
					acs_memzero(denymsg, acs_szalloc(denymsg)); /* see blame() */
				}
				n = acs_strnlen(d, ACS_PASSWD_MAX - (d-s));
				blame("%s", n ? d : "denied by external auditor program");
			}
		}
		pfree(T);
	}
#undef auditsetenv

	if (isflag(suflags, FLG_WARNUSR)
	|| isflag(argflags, ARG_w)) warnusr();

	/* dry run -- part one: if successive, turn off logs, exit in part two. */
	if (isflag(argflags, ARG_W)) {
		unsetflag(&suflags, FLG_LOG);
		unsetflag(&suflags, FLG_LOGFAIL);
	}
	
	if (isflag(suflags, FLG_LOG)) {
		if (!write_log_line(NULL)) xerror("writing log entry");
	}

_bypassaudit:
	free_conf_all();

	/* dry run -- part two (for superuser). */
	if (isflag(argflags, ARG_W)) {
		acs_exit(0);
	}

	if (isflag(argflags, ARG_l)) acs_chdir(dstdir, is_super_user());

	if (isflag(suflags, FLG_TTYDETACH)
	|| isflag(argflags, ARG_B)) ttydetach();
	put_tty(&ttyinfo);
	if (!(is_super_user() && minfd == -1))
		close_fd_range(minfd, (maxfd == -1) ? sysconf(_SC_OPEN_MAX) : maxfd);
	release_lockfile();
#ifdef WITH_RESETRLIMITS
	restore_user_limits();
#endif
	process_rlimits();
#ifdef HAVE_SETPRIORITY
	if (isflag(argflags, ARG_Q) || taskprio_conf != PRIO_INVALID) {
		if (setpriority(PRIO_PROCESS, 0, taskprio_conf) == -1) xerror("setpriority failed");
	}
#endif
	if (chrootdir && (is_super_user() || schrootdir)) {
		if (chdir(chrootdir) == -1) xerror("%s", chrootdir);
		if (chroot(chrootdir) == -1) xerror("%s", chrootdir);
	}

#ifdef WITH_GROUPSLIMIT
	if (dstgsz > NGROUPS_MAX) dstgsz = NGROUPS_MAX;
#endif
/* CHANGING USER */
	if (setgroups(dstgsz, dstgids) == -1) xerror("setgroups");
#ifdef HAVE_SETRESID
	if (setresgid(dstgid, dstegid, dstegid) == -1) xerror("setresgid");
	if (setresuid(dstuid, dsteuid, dsteuid) == -1) xerror("setresuid");
#else
	if (setregid(dstgid, dstegid) == -1) xerror("setregid");
	if (setreuid(dstuid, dsteuid) == -1) xerror("setreuid");
#endif

	if (!is_super_user() && !needs_super_user() && open(PATH_CONF, O_RDONLY) != -1) xexits("failed to change uids!");
	errno = 0;

/* |--^,--^,--^,--^,-- access - target border line --^,--^,--^,--^,--^,--^,--^,--^,--^,--^,--^,--^,--| */

	install_signals(SIG_DFL);

	if (isflag(argflags, ARG_d) || isflag(argflags, ARG_D))
		acs_chdir(dstdir, is_super_user());

	if (isflag(argflags, ARG_p))
		acs_esay("%s", cmdline);
	if (isflag(argflags, ARG_v)) {
		acs_esay("Running `%s`,", cmdline);
		acs_esay("as: %s(%u),%s(%u):%s(%u),%s(%u),",
			dstusr, dstuid, dsteusr, dsteuid,
			dstgrp, dstgid, dstegrp, dstegid);
		acs_esay("groups: %s;", dstfgrps);
		acs_esay("gids: %s.", dstgidss);
	}

	mark_ptr_in_use(progname);
	mark_ptr_in_use(execname);

	if (isflag(argflags, ARG_l)) {
		char *t[2];

		unsetflag(&argflags, ARG_b);
		t[0] = renamed_first_arg; t[1] = NULL;

		mark_ptr_in_use(loginshell);
		mark_ptr_in_use(renamed_first_arg);
		access_free_memory(0);

		x = execute(loginshell, t, NULL);
		goto _done;
	}

	if (first_arg) {
		if (renamed_first_arg) first_arg = renamed_first_arg;

		mark_ptr_in_use(execpath);
		mark_ptr_in_use(argv);
		for (x = 0; x < argc; x++) mark_ptr_in_use(argv[x]);
		access_free_memory(0);

		x = execute(execpath, argv+acs_optind, &bgpid);
	}
	else usage();

_done:	if (x == -1) {
		x = errno;
		if (is_abs_rel(execname)) s = execname;
		else s = acs_basename(execname);
		xexits_status(x, "%s: %s (%d)", s, acs_strerror(errno), errno);
	}
	else {
		if (isflag(argflags, ARG_y)
		&& isflag(argflags, ARG_b))
			acs_say("%ld", (long)bgpid);
		acs_exit(x);
	}

	acs_exit(0);
	return 0;
}
