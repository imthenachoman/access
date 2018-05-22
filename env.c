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

void acs_setenv(const char *name, const char *value, int overwrite)
{
	if (setenv(name, value, overwrite) == -1)
		xerror("setenv");
}

void acs_unsetenv(const char *name)
{
	if (unsetenv(name) == -1)
		xerror("unsetenv");
}

void clear_environ(void)
{
	char **env = environ;

	while (*env) {
		*env = NULL;
		env++;
	}
	*environ = NULL;
}

int is_envvar_exists(const char *name, flagtype class)
{
	size_t x, y;

	x = DYN_ARRAY_SZ(envvars);
	if (!x) return 0;

	for (y = 0; y < x; y++) {
		if (!envvars[y].class) continue;
		if (name) {
			if (!strcmp(envvars[y].name, name)) {
				if (!class) return y+1;
				else if (class && class == envvars[y].class) return y+1;
			}
		}
		else if (class) {
			if (class == envvars[y].class) return y+1;
		}
		else return 0;
	}

	return 0;
}

void add_envvar(const char *name, const char *value, flagtype class)
{
	size_t x, y;

	if (!name || !class) return;

	x = DYN_ARRAY_SZ(envvars);

	/* find same, overwrite it */
	y = is_envvar_exists(name, 0);
	if (y) {
		x = y-1;
		goto _found;
	}

	/* find allocated but empty cell */
	for (y = 0; y < x; y++) {
		if (!envvars[y].class) {
			x = y;
			goto _found;
		}
	}

	/* eh, reallocate to get tail free cell */
	envvars = acs_realloc(envvars, (x+1) * sizeof(struct envvar));

_found:
	pfree(envvars[x].name);
	pfree(envvars[x].value);
	envvars[x].name = acs_strdup(name);
	if (value) envvars[x].value = acs_strdup(value);
	envvars[x].class = class;
}

static void free_envvar(struct envvar *ev)
{
	if (!ev) return;
	ev->class = 0;
	pfree(ev->name);
	pfree(ev->value);
}

void delete_envvars(const char *dname, flagtype class, int match_wildcards)
{
	size_t x, y;
	int f;

	y = DYN_ARRAY_SZ(envvars);
	for (x = 0; x < y; x++) {
		if (!envvars[x].class) continue;
		if (envvars[x].class == class) {
			f = match_pattern_type(dname, envvars[x].name,
				match_wildcards ? MATCH_FNMATCH : MATCH_STRCMP);
			if (f) free_envvar(&envvars[x]);
		}
	}
}

void add_envvar_pair(const char *spec, flagtype class)
{
	char *var, *s, *d;

	s = acs_strchr(spec, '=');
	if (!s) {
		add_envvar(spec, NULL, class);
		return;
	}

	var = acs_strdup(spec);

	*(var+(s-spec)) = 0;
	d = var+(s-spec)+1;
	add_envvar(var, d, class);

	pfree(var);
}

static void save_trusted_envvars(void)
{
	size_t x, y;
	char *s;

	y = DYN_ARRAY_SZ(envvars);
	for (x = 0; x < y; x++) {
		if (!envvars[x].class) continue;

		if (envvars[x].class == EVC_KEEP_SET
		&& !envvars[x].value) {
			s = getenv(envvars[x].name);
			if (s) envvars[x].value = acs_strdup(s);
			else free_envvar(&envvars[x]);
		}
	}

	for (x = 0; x < trusted_envvars_sz; x++) {
		if (!trusted_envvars[x].enabled) continue;
		/* was it there before? */
		y = is_envvar_exists(trusted_envvars[x].pattern, 0);
		if (y && envvars[y-1].class != EVC_KEEP_SET) continue;

		s = getenv(trusted_envvars[x].pattern);
		if (s) add_envvar(trusted_envvars[x].pattern, s, EVC_KEEP_SET);
	}
}

static void kill_real_envvar(const char *dname, int match_wildcards)
{
	static char *t;
	char **env = environ;
	char *s;
	int f;

	if (!t) t = acs_malloc(ACS_ALLOC_SMALL);

	if (env) {
		while (*env) {
			s = acs_strchr(*env, '=');
			/* HACK: writing to environ directly, then restoring, */
			if (s) *s = 0;
			/* ... so here *env will be single envname, */
			f = match_pattern_type(dname, *env,
				match_wildcards ? MATCH_FNMATCH : MATCH_STRCMP);
			if (f) {
				acs_strlcpy(t, *env, ACS_ALLOC_SMALL);
				if (s) *s = '=';
				acs_unsetenv(t);
				/* start over */
				env = environ;
				continue;
			}
			/* ... and restore eq. sign here again. */
			if (s) *s = '=';
			env++;
		}
	}
}

int is_scary_envvar(const char *spec)
{
	size_t x;
	char *var, *s;
	int ret;

	if (is_super_user()) return 0;

	var = acs_strdup(spec);
	s = acs_strchr(var, '=');
	if (s) *s = 0;

	ret = 0;
	for (x = 0; x < scary_envvars_sz; x++) {
		/* TODO: this check is a nop currently: nobody had parsed cfg at this time */
/*		if (!scary_envvars[x].enabled) continue; */
		if (match_pattern_type(scary_envvars[x].pattern, var, MATCH_FNMATCH)) {
			ret = 1;
			break;
		}
	}

	pfree(var);
	return ret;
}

void kill_scary_envvars(int suser)
{
	size_t x;

	for (x = 0; x < scary_envvars_sz; x++) {
		if (!scary_envvars[x].enabled) continue;
		kill_real_envvar(scary_envvars[x].pattern, 1);
		if (!suser) delete_envvars(scary_envvars[x].pattern, EVC_OPTE_SET, 1);
	}
}

static void unset_envvars(flagtype class, int match_wildcards)
{
	size_t x, y;

	y = DYN_ARRAY_SZ(envvars);
	for (x = 0; x < y; x++) {
		if (!envvars[x].class) continue;
		if (envvars[x].class == class) kill_real_envvar(envvars[x].name, match_wildcards);
	}
}

static void set_envvars(flagtype class, int noparse)
{
	static char *t;
	size_t x, y;
	struct fmtstr_args *fsa = NULL;
	size_t nr_fsa;
	struct fmtstr_state fst;

	if (!t) t = acs_malloc(ACS_ALLOC_MAX);

	y = DYN_ARRAY_SZ(envvars);
	if (y == 0) return;

	for (x = 0; x < y; x++) {
		if (!envvars[x].class) continue;
		if (envvars[x].class != class) continue;

		if (!envvars[x].value) {
			acs_setenv(envvars[x].name, "", 1);
			continue;
		}

		if (noparse) {
			acs_setenv(envvars[x].name, envvars[x].value, 1);
		}
		else {
			if (!fsa) preset_fsa_full(&fsa, &nr_fsa);

			acs_memzero(&fst, sizeof(struct fmtstr_state));
			fst.args = fsa;
			fst.nargs = nr_fsa;
			fst.fmt = envvars[x].value;
			fst.result = t;
			fst.result_sz = ACS_ALLOC_MAX;

			parse_fmtstr(&fst);

			if (fst.trunc == 0) {
				parse_escapes(t, ACS_ALLOC_MAX);
				acs_setenv(envvars[x].name, t, 1);
			}
			else xexits("%s: value too long.", envvars[x].name);
		}
	}

	pfree(fsa);
}

int builtin_envvar_enable(struct def_envvar_list *el, size_t elsz, const char *pattern, int enab)
{
	size_t x;

	for (x = 0; x < elsz; x++) {
		if (!strcmp(el[x].pattern, pattern)) {
			el[x].enabled = enab;
			return 1;
		}
	}

	return 0;
}

void fsa_add_uservars(struct fmtstr_args **fsa, size_t *nr_fsa)
{
	struct fmtstr_args *tfsa = *fsa;
	size_t nr_tfsa = *nr_fsa;

	if (setvars) {
		size_t sz, x;
		sz = DYN_ARRAY_SZ(setvars);
		for (x = 0; x < sz; x += 2) {
			if (setvars[x] && setvars[x+1]) {
				APPEND_FSA(tfsa, nr_tfsa, setvars[x], 0, "%s", setvars[x+1]);
			}
		}
	}

	*nr_fsa = DYN_ARRAY_SZ(tfsa);
	*fsa = tfsa;
}

void preset_fsa_basic(struct fmtstr_args **fsa, size_t *nr_fsa)
{
	struct fmtstr_args *tfsa = NULL;
	size_t nr_tfsa = 0;

	APPEND_FSA(tfsa, nr_tfsa, "srcuid", sizeof(uid_t), "%u", &srcuid);
	APPEND_FSA(tfsa, nr_tfsa, "srcusr", 0, "%s", srcusr);
	APPEND_FSA(tfsa, nr_tfsa, "srcgid", sizeof(gid_t), "%u", &srcgid);
	APPEND_FSA(tfsa, nr_tfsa, "srcgrp", 0, "%s", srcgrp);
	APPEND_FSA(tfsa, nr_tfsa, "srcgrps", 0, "%s", srcgrps);
	APPEND_FSA(tfsa, nr_tfsa, "srcgids", 0, "%s", srcgidss);
	APPEND_FSA(tfsa, nr_tfsa, "rootdir", 0, "%s", chrootdir ? chrootdir : default_root);
	APPEND_FSA(tfsa, nr_tfsa, "spath", 0, "%s", get_spath());
	APPEND_FSA(tfsa, nr_tfsa, "hashbang", 0, "%s", hashbang);
	APPEND_FSA(tfsa, nr_tfsa, "pid", sizeof(pid_t), "%u", &ourpid);
	APPEND_FSA(tfsa, nr_tfsa, "ppid", sizeof(pid_t), "%u", &parentpid);
	APPEND_FSA(tfsa, nr_tfsa, "progname", 0, "%s", PROGRAM_NAME);
#ifdef _ACCESS_VERSION
	APPEND_FSA(tfsa, nr_tfsa, "version", 0, "%s", _ACCESS_VERSION);
#endif
	APPEND_FSA(tfsa, nr_tfsa, "timestamp", 0, "%s", curr_secs);
	APPEND_FSA(tfsa, nr_tfsa, "dispname", 0, "%s", progname);

	fsa_add_uservars(&tfsa, &nr_tfsa);
	*nr_fsa = nr_tfsa;
	*fsa = tfsa;
}

void preset_fsa_full(struct fmtstr_args **fsa, size_t *nr_fsa)
{
	struct fmtstr_args *tfsa = NULL;
	size_t nr_tfsa = 0;

	APPEND_FSA(tfsa, nr_tfsa, "dstuid", sizeof(uid_t), "%u", &dstuid);
	APPEND_FSA(tfsa, nr_tfsa, "dstusr", 0, "%s", dstusr);
	APPEND_FSA(tfsa, nr_tfsa, "dsteuid", sizeof(uid_t), "%u", &dsteuid);
	APPEND_FSA(tfsa, nr_tfsa, "dsteusr", 0, "%s", dsteusr);
	APPEND_FSA(tfsa, nr_tfsa, "dstgid", sizeof(gid_t), "%u", &dstgid);
	APPEND_FSA(tfsa, nr_tfsa, "dstgrp", 0, "%s", dstgrp);
	APPEND_FSA(tfsa, nr_tfsa, "dstegid", sizeof(gid_t), "%u", &dstegid);
	APPEND_FSA(tfsa, nr_tfsa, "dstegrp", 0, "%s", dstegrp);
	APPEND_FSA(tfsa, nr_tfsa, "dstgrps", 0, "%s", dstfgrps);
	APPEND_FSA(tfsa, nr_tfsa, "dstgids", 0, "%s", dstgidss);
	APPEND_FSA(tfsa, nr_tfsa, "srcuid", sizeof(uid_t), "%u", &srcuid);
	APPEND_FSA(tfsa, nr_tfsa, "srcusr", 0, "%s", srcusr);
	APPEND_FSA(tfsa, nr_tfsa, "srcgid", sizeof(gid_t), "%u", &srcgid);
	APPEND_FSA(tfsa, nr_tfsa, "srcgrp", 0, "%s", srcgrp);
	APPEND_FSA(tfsa, nr_tfsa, "srcgrps", 0, "%s", srcgrps);
	APPEND_FSA(tfsa, nr_tfsa, "srcgids", 0, "%s", srcgidss);
	APPEND_FSA(tfsa, nr_tfsa, "tty", 0, "%s", ttyinfo.ttyname);
	APPEND_FSA(tfsa, nr_tfsa, "cwd", 0, "%s", cwd);
	APPEND_FSA(tfsa, nr_tfsa, "dstusrdir", 0, "%s", dstusrdir);
	APPEND_FSA(tfsa, nr_tfsa, "dstdir", 0, "%s", dstdir);
	APPEND_FSA(tfsa, nr_tfsa, "dstusrshell", 0, "%s", dstusrshell);
	APPEND_FSA(tfsa, nr_tfsa, "rootdir", 0, "%s", chrootdir ? chrootdir : default_root);
	APPEND_FSA(tfsa, nr_tfsa, "spath", 0, "%s", get_spath());
	APPEND_FSA(tfsa, nr_tfsa, "execpath", 0, "%s", execfpath);
	APPEND_FSA(tfsa, nr_tfsa, "cmdline", 0, "%s", cmdline);
	APPEND_FSA(tfsa, nr_tfsa, "hashbang", 0, "%s", hashbang);
	APPEND_FSA(tfsa, nr_tfsa, "flags", 0, "%s", trigflags);
	APPEND_FSA(tfsa, nr_tfsa, "line", 0, "%s", trigline);
	APPEND_FSA(tfsa, nr_tfsa, "cfgfile", 0, "%s", get_cur_conf_name());
	APPEND_FSA(tfsa, nr_tfsa, "cfgline", sizeof(int), "%u", pget_cur_conf_lnum());
	APPEND_FSA(tfsa, nr_tfsa, "pid", sizeof(pid_t), "%u", &ourpid);
	APPEND_FSA(tfsa, nr_tfsa, "ppid", sizeof(pid_t), "%u", &parentpid);
	APPEND_FSA(tfsa, nr_tfsa, "progname", 0, "%s", PROGRAM_NAME);
#ifdef _ACCESS_VERSION
	APPEND_FSA(tfsa, nr_tfsa, "version", 0, "%s", _ACCESS_VERSION);
#endif
	APPEND_FSA(tfsa, nr_tfsa, "datetime", 0, "%s", curr_date);
	APPEND_FSA(tfsa, nr_tfsa, "timestamp", 0, "%s", curr_secs);
	APPEND_FSA(tfsa, nr_tfsa, "dispname", 0, "%s", progname);
	APPEND_FSA(tfsa, nr_tfsa, "firstarg", 0, "%s", renamed_first_arg);
	APPEND_FSA(tfsa, nr_tfsa, "bfullargv", 0, "%s", bfullargv);
	APPEND_FSA(tfsa, nr_tfsa, "bcmdline", 0, "%s", bcmdline);
	APPEND_FSA(tfsa, nr_tfsa, "buserenv", 0, "%s", buserenv);
	APPEND_FSA(tfsa, nr_tfsa, "benviron", 0, "%s", benviron);
	APPEND_FSA(tfsa, nr_tfsa, "auditcmd", 0, "%s", auditcmd);
	APPEND_FSA(tfsa, nr_tfsa, "pwaskcmd", 0, "%s", pwaskcmd);
	APPEND_FSA(tfsa, nr_tfsa, "auditpid", sizeof(pid_t), "%u", &auditpid);
	APPEND_FSA(tfsa, nr_tfsa, "auditret", sizeof(int), "%d", &auditreturn);

	/* parse user vars */
	fsa_add_uservars(&tfsa, &nr_tfsa);
	*nr_fsa = nr_tfsa;
	*fsa = tfsa;
}

void set_basic_envvars(void)
{
	static char *t;
	char *s;

	if (!isflag(argflags, ARG_P)) {
		acs_setenv("USER", dstusr, 1);
		acs_setenv("LOGNAME", dstusr, 1);
		acs_asprintf(&t, "%u", dstuid);
		acs_setenv("UID", t, 1);
		acs_setenv("SHELL", dstusrshell, 1);
		acs_setenv("HOME", dstusrdir, 1);
	}
	else {
		acs_setenv("USER", srcusr, 1);
		acs_setenv("LOGNAME", srcusr, 1);
		acs_asprintf(&t, "%u", srcuid);
		acs_setenv("UID", t, 1);
		s = shellbyname(srcusr);
		acs_setenv("SHELL", s, 1);
		s = udirbyname(srcusr);
		acs_setenv("HOME", s, 1);
	}

	acs_setenv("PWD", dstdir, 1); /* bash complains */
	acs_setenv("PATH", get_spath(), 1);
}

void set_user_environ(void)
{
	save_trusted_envvars();

	if ((isflag(argflags, ARG_l) || isflag(argflags, ARG_E))
	|| (!is_super_user() && isflag(suflags, FLG_CLRENV) && !isflag(argflags, ARG_P)))
		clear_environ();

	set_envvars(EVC_OPTE_SET, 1);
	kill_scary_envvars(is_super_user());
	unset_envvars(EVC_OPTE_UNSET, 0);
	set_basic_envvars();
	unset_envvars(EVC_CONF_UNSET, 1);
	set_envvars(EVC_KEEP_SET, 1);
	set_envvars(EVC_CONF_SET, 0);

	if (is_super_user()) {
		set_envvars(EVC_OPTE_SET, 1);
		unset_envvars(EVC_OPTE_UNSET, 0);
	}
}
