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

#ifdef WITH_SU_PROG

/*
 * Basic su(1) emulation.
 *
 * WARNING: This code MUST NOT alter or otherwise call access(8) code in any way.
 * Only util functions are permitted (memory allocation, error exit etc.)
 * It must drop privileges as early as possible and then perform as a standalone program.
 * It must call access only by a loosely knowable path in filesystem via execl()
 * which is based on a installation prefix given at compile time and only.
 *
 * This modern su(1) supports old shell script and becomes a access builtin.
 * This su(1) supports -lmp, -c cmdline, -s shell and dash.
 *
 * This is purely user su(1), which does not deal with numbers at all, leaving them to access(8).
 *
 * This code maybe buggy, but not exploitable because it drops privileges.
 */

static char *access_name;
static char *access_path;

static char *find_access(const char *name)
{
	char *r = NULL;

	acs_asprintf(&r, "%s/bin/%s", PREFIX, name ? name : PROGRAM_NAME);
	if (is_exec(r)) return r;

	pfree(r);
	return which(spath, name ? name : PROGRAM_NAME, NULL);
}

#define RES_SUSER 1
#define RES_SHELL 2

static char *su_shell;
static char *su_cmdline;
static int su_dologin, su_preserve;
static char *su_user, *su_group, *su_groups;

static void su_usage(void)
{
	acs_say("usage: su [-] [-lmpV] [-c cmdline] [-s shell] [user] [group] [groups]");
	acs_exit(1);
}

static char *ask_access(int w, const char *u)
{
	FILE *p;
	char *su_resret = NULL;
	int r;

	if (w == RES_SUSER) {
		acs_asprintf(&su_resret, "%s -c suser", access_path);
	}
	else if (w == RES_SHELL && u) {
		acs_asprintf(&su_resret, "%s -u %s -c shell", access_path, u);
	}
	else xexits("ask_access(%u, %p)\n", w, u);

	p = popen(su_resret, "r");
	if (!p) return NULL;

	su_resret = acs_realloc(su_resret, ACS_ALLOC_SMALL);
	acs_memzero(su_resret, ACS_ALLOC_SMALL);
	if (fread(su_resret, 1, ACS_ALLOC_SMALL, p) == 0) goto _out;
	remove_chars(su_resret, ACS_ALLOC_SMALL, "\r\n");

_out:	r = pclose(p);
	r = WEXITSTATUS(r);
	if (r) xexits("access returned %d.", r);

	shrink_dynstr(&su_resret);
	return su_resret;
}

static void do_login(const char *shell, const char *u, const char *g, const char *G)
{
	if (shell) { /* if access will deny you doing that then it's your fault! */
		if (u && !g && !G) execl(access_path, access_name, "-u", u, "-A", "--", shell, NULL);
		else if (u && g && !G) execl(access_path, access_name, "-u", u, "-g", g, "-A", "--", shell, NULL);
		else if (u && g && G) execl(access_path, access_name, "-u", u, "-g", g, "-s", G, "-A", "--", shell, NULL);
	}
	else {
		if (u && !g && !G) execl(access_path, access_name, "-u", u, "-l", NULL);
		else if (u && g && !G) execl(access_path, access_name, "-u", u, "-g", g, "-l", NULL);
		else if (u && g && G) execl(access_path, access_name, "-u", u, "-g", g, "-s", G, "-l", NULL);
	}
}

static void do_exec(const char *cmdline, const char *shell,
		    const char *u, const char *g, const char *G, int mp)
{
	if (u && !g && !G) {
		if (mp) execl(access_path, access_name, "-u", u, "-P", "--", shell, "-c", cmdline, NULL);
		else execl(access_path, access_name, "-u", u, "--", shell, "-c", cmdline, NULL);
	}
	else if (u && g && !G) {
		if (mp) execl(access_path, access_name, "-u", u, "-g", g, "-P", "--", shell, "-c", cmdline, NULL);
		else execl(access_path, access_name, "-u", u, "-g", g, "--", shell, "-c", cmdline, NULL);
	}
	else if (u && g && G) {
		if (mp) execl(access_path, access_name, "-u", u, "-g", g, "-s", G, "-P", "--", shell, "-c", cmdline, NULL);
		else execl(access_path, access_name, "-u", u, "-g", g, "-s", G, "--", shell, "-c", cmdline, NULL);
	}
	else su_usage();
}

#ifdef _ACCESS_VERSION
static void do_version(int arg_V_cnt)
{
	if (arg_V_cnt > 1) execl(access_path, access_name, "-V", "-V", NULL);
	else execl(access_path, access_name, "-V", NULL);
	acs_exit(127);
}
#endif

/* really used only when called like "su -c id user group groups" -- to find out tail args. */
static char *argv_find_next(int argc, char *const *argv, const char *str, int offs, int noarg)
{
	int x;

	for (x = 0; argv[x]; x++) {
		if (!strcmp(argv[x], str) && argv[x+offs]) {
			if (noarg && argv[x+offs][0] == '-') return NULL;
			if (x+offs < argc) return argv[x+offs];
		}
	}

	return NULL;
}

int su_main(int argc, char **argv, uid_t srcuid, gid_t srcgid, int srcgsz, gid_t *srcgids)
{
	int c;
	void *cfg;
	char *s, *d, *t;

	set_progname("su");

	if (is_setuid()) {
		/*
		 * su acts like an ordinary executable, but access's early main()
		 * resets limits to safe minimals - so restore them here again.
		 */
#ifdef WITH_RESETRLIMITS
		restore_user_limits();
#endif

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

	signal(SIGCHLD, SIG_DFL); /* see access's main, which ignores all signals. */

	c = open(SU_PATH_CONF, O_RDONLY);
	if (c != -1) {
		cfg = load_config(c);
		if (!cfg) {
			close(c);
			goto _cfgout;
		}
		close(c);

		while ((s = get_config_line(cfg))) {
			d = strchr(s, ' ');
			if (!d) continue;
			*d = 0; d++;

			if (!strcmp(s, "%setenv")) {
				t = strchr(d, '=');
				if (!t) continue;
				*t = 0; t++;
				acs_setenv(d, t, 1);
			}
			else if (!strcmp(s, "%unsetenv")) {
				acs_unsetenv(d);
			}
			else if (!strcmp(s, "%call")) {
				access_name = acs_strdup(d);
			}
		}

		free_config(cfg);
	}

_cfgout:
	if (!access_name) access_name = acs_strdup(PROGRAM_NAME);
	access_path = find_access(access_name);
	if (!access_path) xexits("%s was not found.", access_name);

	c = 1;
	acs_optind = 1;
	while (c) {
		if (!argv[acs_optind]) break;

		if (argv[acs_optind][0] != '-') {
			switch (acs_optind) {
				case 1: su_user = argv[acs_optind]; break;
				case 2: su_group = argv[acs_optind]; break;
				case 3: su_groups = argv[acs_optind]; break;
				default: c = 0; break;
			}
			acs_optind++;
		}
		else break;
	}

	acs_opterr = 1;
	while ((c = acs_getopt(argc, argv, "lmpc:s:V")) != -1) {
		switch (c) {
			case 'l': su_dologin = 1; break;
			case 'm':
			case 'p': su_preserve = 1; break;
			case 'c': su_cmdline = acs_optarg; break;
			case 's': su_shell = acs_optarg; break;
#ifdef _ACCESS_VERSION
			case 'V': arg_V_cnt++; break;
#endif
			default: su_usage(); break;
		}
	}

#ifdef _ACCESS_VERSION
	if (arg_V_cnt) do_version(arg_V_cnt);
#endif

	if (argv[acs_optind] && !strcmp(argv[acs_optind], "-")) {
		su_dologin = 1;
		acs_optind++;
	}

	if (su_user) goto _su_grp;

	su_user = argv[acs_optind];
	if (!su_user) {
		su_user = ask_access(RES_SUSER, NULL);
		goto _su_exec;
	}

_su_grp:
	if (su_user && !su_group) {
		s = argv_find_next(argc, argv, su_user, 1, 1);
		if (s) su_group = s;
	}
	if (su_user && su_group && !su_groups) {
		s = argv_find_next(argc, argv, su_user, 2, 1);
		if (s) su_groups = s;
	}

_su_exec:
	if (su_dologin) {
		/* if !su_shell, then do_login does access -l */
		do_login(su_shell, su_user, su_group, su_groups);
	}

	if (!su_shell) su_shell = ask_access(RES_SHELL, su_user);

	if (su_cmdline) {
		do_exec(su_cmdline, su_shell, su_user, su_group, su_groups, su_preserve);
	}

	s = NULL;
	acs_asprintf(&s, "exec %s", su_shell);
	do_exec(s, su_shell, su_user, su_group, su_groups, su_preserve);

	return 127;
}

#endif
