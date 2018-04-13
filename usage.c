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

void usage(void)
{
	acs_say("usage: %s [-uU user/uid] [-gG group/gid] [-sS gid,group,...]", progname);
	acs_say("\t[-tTxX] [-e VAR=VAL] [-a argv0] [-c vcmd] [-C minfd]");
	acs_say("\t[-d chdir] [-F fd] [-L rlimspec] [-Q prio] [-R newroot]");
#ifdef _ACCESS_VERSION
	acs_say("\t[-AbBDEfIlnNpPvVwy] [--] cmdline ...");
#else
	acs_say("\t[-AbBDEfIlnNpPvwy] [--] cmdline ...");
#endif

	acs_say("run %s with -h to see full help text", progname);
	acs_exit(1);
}

void usage_long(void)
{
	acs_say("usage: %s [opts] [--] cmdline ...", progname);
	acs_say("\n");

	acs_say("  -u uid/user: set uid to specified user or uid");
	acs_say("  -U euid/user: set euid to specified user or uid");
	acs_say("  -g gid/group: set gid to specified group or gid");
	acs_say("  -G egid/group: set egid to specified group or gid");
	acs_say("  -s grouplist: set additional groups to specified grouplist");
	acs_say("  -S grouplist: add/remove groups from grouplist");
	acs_say("  -t: set euid to superuser");
	acs_say("  -T: set egid to superuser");
	acs_say("  -x: run as current user, not target");
	acs_say("  -xx: run as current user, preserve current groups");
	acs_say("  -X: run as current user, reset grouplist to current gid");
	acs_say("\n");
	acs_say("  -a argv[0]: set target program argv[0] to this value");
	acs_say("  -A: place a '-' in beginning of argv[0] of target program");
	acs_say("  -b: run program in background, return immediately");
	acs_say("  -B: detach terminal to prevent tty hijacking");
	if (!nocommands) {
		acs_say("  -c cmd,cmd,...: execute virtual command:");
		acs_say("    id: print id(1)-formatted userid information (without setuid)");
		acs_say("    uid: prints real user id");
		acs_say("    gid: prints real group id");
		acs_say("    gids: prints all group ids");
		acs_say("    user: prints real user name");
		acs_say("    group: prints real group name");
		acs_say("    groups: prints all group names");
		acs_say("    suser: prints superuser name");
		acs_say("    udir: print user's directory");
		acs_say("    shell: print user's shell");
		acs_say("   (a list of comma separated commands may be given)");
	}
	else acs_say("  -c: option is disabled by superuser.");
	acs_say("  -C minfd: set minimal fd from which begin to close leakage fds");
	acs_say("  -d dir: change working directory to dir");
	acs_say("  -D: change working directory to user's directory");
	acs_say("  -e VAR=VAL: set environment variable");
	acs_say("  -E: start with empty environment");
	acs_say("  -f: (superuser) do not read config file");
	acs_say("  -F fd: if password is required, read it from file descriptor fd");
	acs_say("  -I: start a login shell, but always use %s as login shell", default_shell);
	acs_say("  -l: start a normal destination user login shell");
	acs_say("  -L rlimspec: set resource limits (ulimit). rlimspec: nrlim:soft:hard");
	acs_say("  -n: never ask for password. If password is required, return an error");
	acs_say("  -N: if password asking program fails, fallback to ask in tty");
	acs_say("  -p: print command line which will be run");
	acs_say("  -P: preserve provided environment");
#ifdef HAVE_SETPRIORITY
	acs_say("  -Q prio: set process priority to prio");
#else
	acs_say("  -Q prio: (unavailable on this system)");
#endif
	acs_say("  -R dir: chroot into dir");
	acs_say("  -y: with -b: print background program pid");
	acs_say("  -w: ask user about what to be run");
	acs_say("  -v: show more info about what is going to be run and as whom");
#ifdef _ACCESS_VERSION
	acs_say("  -V: show version information");
#endif
	acs_say("\n");
	acs_say(" By default, if user specified, group id and group list are set to target user is in.");
	acs_say(" ALWAYS check target permissions with %s -c id executed as target user!", progname);
	acs_say("\n");
	acs_exit(1);
}

#ifdef _ACCESS_VERSION
void print_builtin_defs(void)
{
	size_t x;

	acs_say("\n");
	acs_say("Compiled-in defaults:");
	acs_say("default flags: \"%s\"", DEFAULT_FLAGS);
	acs_say("default spath: \"%s\"", SAFE_PATH);
	acs_say("default shell: \"%s\"", DEFAULT_SHELL);
	acs_say("default log format: \"%s\"", DEFAULT_LOG_FORMAT);
	acs_say("lock file pattern: \"%s\"", LOCKFILE_PATH);
	acs_say("failure delay: %uus", DELAY_WRPASS);
	acs_say("\n");
	acs_say("Environment:");
	acs_nsay("Always kept variables: ");
	for (x = 0; x < trusted_envvars_sz; x++) {
		if (!trusted_envvars[x].enabled) continue;
		if (x && (x % 10) == 0) acs_say("\n");
		else if (x) acs_nsay(", ");
		acs_nsay("\"%s\"", trusted_envvars[x].pattern);
	}
	acs_say("\n");
	acs_nsay("Always cleared variables: ");
	for (x = 0; x < scary_envvars_sz; x++) {
		if (!scary_envvars[x].enabled) continue;
		if (x && (x % 5) == 0) acs_say("\n");
		else if (x) acs_nsay(", ");
		acs_nsay("\"%s\"", scary_envvars[x].pattern);
	}
	acs_say("\n");
}
#endif

void print_uidinfos(char *c_opt_str, int pui_flags)
{
	uid_t tuid;
	gid_t tgid;
	char *tusr;
	char *tgrp;
	size_t tgsz; gid_t *tgids;
	char *tgrps;
	char *s, *d, *t;
	int x;

	if (nocommands && !is_super_user()) xexits("virtual commands were disabled by superuser.");

	if (isflag(pui_flags, UARG_g)) {
		tgid = dstgid; tgrp = dstgrp;
	}
	else {
		tgid = srcgid; tgrp = srcgrp;
	}

	if (isflag(pui_flags, UARG_u)) {
		tuid = dstuid; tusr = dstusr;
		tgsz = dstgsz; tgids = dstgids;
		tgid = dstgid; tgrp = dstgrp;
	}
	else {
		tuid = srcuid; tusr = srcusr;
		tgsz = srcgsz; tgids = srcgids;
		tgid = srcgid; tgrp = srcgrp;
	}

	s = d = c_opt_str; t = NULL;
	while ((s = acs_strtok_r(d, ",", &t))) {
		if (d) d = NULL;

		if (!strcmp(s, "id")) {
			acs_nsay("uid=%u(%s) ", tuid, tusr);
			acs_nsay("gid=%u(%s) ", tgid, tgrp);
			if (tgsz) {
				tgrps = build_usergroups(tgsz, tgids, 1, 0);
				acs_say("groups=%s", tgrps);
				pfree(tgrps);
			}
			else acs_say("\n");
		}
		else if (!strcmp(s, "uid")) acs_say("%u", tuid);
		else if (!strcmp(s, "gid")) acs_say("%u", tgid);
		else if (!strcmp(s, "user")) acs_say("%s", tusr);
		else if (!strcmp(s, "group")) acs_say("%s", tgrp);
		else if (!strcmp(s, "gids")) {
			tgrps = build_usergroups(tgsz, tgids, 0, 1);
			x = 0;
			while (*(tgrps+x)) {
				if (*(tgrps+x) == ',') *(tgrps+x) = ' ';
				x++;
			}
			acs_say("%s", tgrps);
		}
		else if (!strcmp(s, "groups")) {
			tgrps = build_usergroups(tgsz, tgids, 0, 0);
			x = 0;
			while (*(tgrps+x)) {
				if (*(tgrps+x) == ',') *(tgrps+x) = ' ';
				x++;
			}
			acs_say("%s", tgrps);
		}
		else if (!strcmp(s, "udir"))
			acs_say("%s", udirbyname(tusr));
		else if (!strcmp(s, "shell"))
			 acs_say("%s", shellbyname(tusr));
		else if (!strcmp(s, "suser")) acs_say("%s", suusr);
		else usage_long();
	}
	acs_exit(0);
}

#ifdef _ACCESS_VERSION
void show_version(void)
{
	acs_say(PROGRAM_NAME ": authenticator for Unix systems");
	acs_say("Version " _ACCESS_VERSION);
	if (is_super_user() && arg_V_cnt == 2) print_builtin_defs();
	acs_exit(0);
}
#endif
