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

char *progname;

time_t curr_time;
char *curr_date;
char *curr_secs;

int fullinfo;

#ifdef WITH_STATIC_MEMORY
static unsigned char access_static_memory_pool[ACS_XSALLOC_MAX+ACS_ALLOC_BUMPER];
void *access_memory_pool = access_static_memory_pool;
#else
void *access_memory_pool;
#endif

pid_t ourpid, parentpid;
char *timefmt, *logfmt;
flagtype suflags, argflags, notargflags;
char *execname;
char *spath, *supath, *logpath;
char *prompt, *denymsg;
char *trigline, *trigflags;
char *execfpath, *execpath, *hashbang, *renamed_first_arg;
uint64_t delay = DELAY_WRPASS;
int minfd = 3, maxfd = -1;
int passwdfd = -1;
mode_t dumask = DEFAULT_UMASK;
char *lockpath;
char *lockfile;

struct tty_info ttyinfo = { .fd = -1, };

int arg_x_cnt;
int arg_V_cnt;

struct usermap *usermaps;

struct envvar *envvars;

/* C89 style initialiser */
#define EVL_ENTRY(s) {s, 1}

/* Always kept environment variables */
struct def_envvar_list trusted_envvars[] = {
	EVL_ENTRY("TERM"),
	EVL_ENTRY("DISPLAY"),
};
size_t trusted_envvars_sz = STAT_ARRAY_SZ(trusted_envvars);

/*
 * Always cleared environment variables.
 * This is a list of nasty vars that modify
 * various program paths in TARGET program.
 * I can't support all of them (and especially vars in
 * third-party programs), but common linker/loader/shell
 * vars are banned here.
 *
 * NOTE: superuser can override and keep ALL of those!
 */
struct def_envvar_list scary_envvars[] = {
/* fnmatch wildcards */
	EVL_ENTRY("*PATH*"), EVL_ENTRY("LD_*"),
	EVL_ENTRY("DYLD_*"), EVL_ENTRY("_RLD*"),
	EVL_ENTRY("LDR_*"), EVL_ENTRY("MALLOC_*"),
	EVL_ENTRY("LIBC_*"), EVL_ENTRY("MUSL_*"),
	EVL_ENTRY("PS?"), EVL_ENTRY("*_ACE"),
	EVL_ENTRY("ACCESS_*"),
/* single names */
	EVL_ENTRY("MAIL"), EVL_ENTRY("HOSTALIASES"),
	EVL_ENTRY("LOCALDOMAIN"), EVL_ENTRY("RESOLV_HOST_CONF"),
	EVL_ENTRY("RES_OPTIONS"), EVL_ENTRY("GETCONF_DIR"),
	EVL_ENTRY("_"), EVL_ENTRY("IFS"),
	EVL_ENTRY("ENV"), EVL_ENTRY("BASH_ENV"),
	EVL_ENTRY("INPUTRC"), EVL_ENTRY("KRB_CONF"),
	EVL_ENTRY("KRB5_CONFIG"), EVL_ENTRY("LANG"),
	EVL_ENTRY("LANGUAGE"), EVL_ENTRY("PATH_LOCALE"),
	EVL_ENTRY("TERMINFO"), EVL_ENTRY("TERMINFO_DIRS"),
	EVL_ENTRY("TERMCAP"), EVL_ENTRY("TMPDIR"),
	EVL_ENTRY("TZDIR"), EVL_ENTRY("HISTFILE"),
};
size_t scary_envvars_sz = STAT_ARRAY_SZ(scary_envvars);

#undef EVL_ENTRY

/* Resource limit strings, format: nrlim:soft:hard */
char **rlimspec_list;
#ifdef WITH_RESETRLIMITS
int prsvrlims_fail; /* resetrlimits code failed, but continue until trapped into runaway. */
#endif

/* user variables which appear in format templates (%set) */
char **setvars;

uid_t srcuid, dstuid, dsteuid;
gid_t srcgid, dstgid, dstegid;
gid_t *srcgids, *dstgids;
int srcgsz, dstgsz;
char *srcusr, *srcgrp, *dstusr, *dstgrp;
char *dsteusr, *dstegrp;
char *srcgrps, *srcgidss, *dstgrps, *dstfgrps, *dstgidss; /* dstfgrps = full resolved dst. grouplist. */
char *suusr;
char *cmdline, *bcmdline, *bfullargv;
char *buserenv, *benviron;
char *scwd, *cwd;
char *sdstdir, *dstdir, *dstusrdir;
char *dstusrshell;
char *schrootdir, *chrootdir;
char *linepw;
char *blamecmd;
char *pwaskcmd;
char *auditcmd, *auditspath;
pid_t auditpid;
int auditret, auditreturn; /* auditret: successive return value to be tested, auditreturn: what really was returned by audit program */
int extern_prog_running; /* indicates that external program is running. For signal_handler. */
char *fromtty;
char *custom_blame_str;
#ifdef HAVE_SETPRIORITY
int taskprio_arg = PRIO_INVALID;
int taskprio_conf = PRIO_INVALID;
#endif

int match_type = MATCH_FNMATCH;

flagtype auth;
int noblame;

char *errstr;
char default_shell[] = DEFAULT_SHELL;
char default_root[] = "/";

int nocommands; /* disable -c completely */

int getp_flags = GETP_NOECHO | GETP_WAITFILL;
