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

#ifndef HAVE_UNIX_CRYPT
#undef WITH_ACSTESTAUTH_PROG
#endif

#ifdef WITH_ACSTESTAUTH_PROG

/*
 * acstestauth: ask user for the password, then verify it
 * indeed matches with the encrypted on stored in system.
 * This tool is allowed to run only by superuser.
 * The normal purpose of this tool is to be run from (interactive) scripts.
 *
 * acstestauth usage:
 * -v: print verification status: "OK" if password is correct, "NO" if not.
 * -u user: retrieve password hash for this user.
 * -p prompt: print custom prompt.
 * -F pwfd: read password in clear from password fd pwfd.
 * -H hash: do not do user verification. Just verify this hash instead.
 */

int askpass_filter(struct getpasswd_state *getps, char chr, size_t pos);

static char *acstestauth_usr;
static char acstestauth_pwd1[ACS_PASSWD_MAX], acstestauth_pwd2[ACS_PASSWD_MAX];
static struct getpasswd_state acstestauth_getps;
static struct fmtstr_args *acstestauth_fsa;
static size_t acstestauth_nr_fsa;
static struct fmtstr_state acstestauth_fst;
static int acstestauth_readfdpw, acstestauth_passwdfd;
static char *acstestauth_prompt;
static char *acstestauth_hash;
static char *acstestauth_pwaskcmd;
static int acstestauth_pwdpipe[2];
static int acstestauth_verbose;

static char *s;
static char **tpp, **targv, **tenvp;
static char *acstestauth_tmp;

static void acstestauth_usage(void)
{
	acs_say("usage: acstestauth [-qv] [-u user] [-p prompt] [-F pwfd] [-H hash] [-e pwaskcmd]");
	acs_exit(1);
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

int acstestauth_main(int argc, char **argv, uid_t srcuid, gid_t srcgid, int srcgsz, gid_t *srcgids)
{
	size_t err;
	int c, r;

	set_progname("acstestauth");

	if (!is_super_user()) xexits_status(2, "only superuser can do this");

	acs_opterr = 1;
	while ((c = acs_getopt(argc, argv, "qvu:p:F:H:e:")) != -1) {
		switch (c) {
			case 'u':
				acstestauth_usr = acs_strdup(acs_optarg);
				if (uidbyname(acstestauth_usr) == NOUID) xerror_status(2, "%s", acstestauth_usr);
				break;
			case 'p': acstestauth_prompt = acs_strdup(acs_optarg); break;
			case 'F':
				if (is_number(acs_optarg, 0)) {
					acstestauth_readfdpw = 1;
					acstestauth_passwdfd = atoi(acs_optarg);
				}
				else xexits_status(2, "%s: invalid fd number", acs_optarg);
				break;
			case 'H': acstestauth_hash = acs_strdup(acs_optarg); break;
			case 'e': acstestauth_pwaskcmd = acs_strdup(acs_optarg); break;
			case 'q': acstestauth_verbose = 0; break;
			case 'v': acstestauth_verbose = 1; break;
			default: acstestauth_usage(); break;
		}
	}

	/* for custom prompt */
	readin_default_settings();

	if (!acstestauth_usr) acstestauth_usr = srcusr;
	if (!acstestauth_prompt) acstestauth_prompt = prompt;

	if (acstestauth_readfdpw) {
		if (!fdgetstring(acstestauth_passwdfd, acstestauth_pwd1, sizeof(acstestauth_pwd1)-1))
			xexits_status(2, "reading password from fd %d error (%s)",
				acstestauth_passwdfd, acs_strerror(errno));
	}
	else {
		preset_fsa_basic(&acstestauth_fsa, &acstestauth_nr_fsa);
		APPEND_FSA(acstestauth_fsa, acstestauth_nr_fsa, "pwusr", 0, "%s", acstestauth_usr);

		acstestauth_fst.args = acstestauth_fsa;
		acstestauth_fst.nargs = acstestauth_nr_fsa;
		acstestauth_fst.fmt = acstestauth_prompt;
		acstestauth_fst.result = acstestauth_pwd2; /* Reuse acstestauth_pwd2 */
		acstestauth_fst.result_sz = sizeof(acstestauth_pwd2);
		parse_fmtstr(&acstestauth_fst);
		pfree(acstestauth_fsa);
		if (acstestauth_fst.trunc) xexits_status(2, "bad prompt= parse state");

		if (acstestauth_pwaskcmd) {
			if (pipe(acstestauth_pwdpipe) != 0)
				xerror_status(2, "pipe for %s failed", acstestauth_pwaskcmd);

			pwasksetenv(acstestauth_tmp, "%s=%s", "PATH", auditspath ? auditspath : get_spath());
			pwasksetenv(acstestauth_tmp, "%s=%d", "ACSTESTAUTH_PWDFD", acstestauth_pwdpipe[1]);
			pwasksetenv(acstestauth_tmp, "%s=%s", "ACSTESTAUTH_PROMPT", acstestauth_pwd2);
			pwasksetenv(acstestauth_tmp, "%s=%s", "ACSTESTAUTH_PWUSR", acstestauth_usr);
			pfree(acstestauth_tmp);

			s = acs_strdup(acstestauth_pwaskcmd);
			targv = parse_cmdline(s);
			if (!targv) xexits("-e argument is empty!");
			tpp = targv;
			if (*(targv+1)) tpp++;
			reseterr();
			r = forkexec(1, *targv, tpp, tenvp, NULL, acstestauth_pwdpipe, acstestauth_pwd1, ACS_PASSWD_MAX-1);
			if (errno) xerror_status(2, "running password asking program \"%s\" failed", *targv);
			pfree(targv);
			pfree(s);
			destroy_argv(&tenvp);
			if (r != 0) {
				if (acs_strnlen(acstestauth_pwd1, ACS_ALLOC_MAX))
					xexits_status(r, "%s", acstestauth_pwd1);
				else xexits_status(r, "user aborted password asking program: %d", r);
			}
		}
		else {
			acs_memzero(&acstestauth_getps, sizeof(struct getpasswd_state));
			if (ttyinfo.fd != -1) acstestauth_getps.fd = acstestauth_getps.efd = ttyinfo.fd;
			else acstestauth_getps.fd = acstestauth_getps.efd = -1;
			acstestauth_getps.passwd = acstestauth_pwd1;
			acstestauth_getps.pwlen = sizeof(acstestauth_pwd1)-1;
			acstestauth_getps.echo = acstestauth_pwd2; /* See above */
			acstestauth_getps.charfilter = askpass_filter;
			acstestauth_getps.maskchar = 'x';
			acstestauth_getps.flags = GETP_WAITFILL;

			err = acs_getpasswd(&acstestauth_getps);

			if (err == NOSIZE) {
				if (acstestauth_getps.error != -1)
					xexits_status(2, "password reading error (%s)",
					acs_strerror(acstestauth_getps.error));

				xexits_status(2, "password input rejected by user");
			}
		}
	}

	block_tty(&ttyinfo, 1);

	if (!acstestauth_hash) r = match_password(acstestauth_usr, acstestauth_pwd1) ? 0 : 1;
	else r = strcmp(acs_crypt(acstestauth_pwd1, acstestauth_hash), acstestauth_hash) ? 1 : 0;

	acs_memzero(acstestauth_pwd1, sizeof(acstestauth_pwd1));
	acs_memzero(acstestauth_pwd2, sizeof(acstestauth_pwd2));

	block_tty(&ttyinfo, 0);

	if (acstestauth_verbose) {
		if (r == 0) acs_say("OK");
		else acs_say("NO");
	}

	acs_exit(r);
	return r;
}

#endif
