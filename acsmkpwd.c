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
#undef WITH_ACSMKPWD_PROG
#endif

#ifdef WITH_ACSMKPWD_PROG

/*
 * acsmkpwd: generate raw acs_crypt() hashes.
 * Argument: saltstring - specify custom salt string.
 * Superuser usage only.
 */

int askpass_filter(struct getpasswd_state *getps, char chr, size_t pos);

static char *acsmkpwd_salt;
static char acsmkpwd_pwd1[ACS_PASSWD_MAX], acsmkpwd_pwd2[ACS_PASSWD_MAX];
static struct getpasswd_state acsmkpwd_getps;

int acsmkpwd_main(int argc, char **argv, uid_t srcuid, gid_t srcgid, int srcgsz, gid_t *srcgids)
{
	size_t err;

	set_progname("acsmkpwd");

	if (!is_super_user()) xexits("only superuser can do this");

	if (argv[1] && !str_empty(argv[1])) {
		acsmkpwd_salt = acs_strdup(argv[1]);
		err = acs_strnlen(argv[1], ACS_ALLOC_MAX);
		acs_memzero(argv[1], err);
	}
	else acsmkpwd_salt = make_random_salt();

_pwagain:
	acs_memzero(&acsmkpwd_getps, sizeof(struct getpasswd_state));
	if (ttyinfo.fd != -1) acsmkpwd_getps.fd = acsmkpwd_getps.efd = ttyinfo.fd;
	else acsmkpwd_getps.fd = acsmkpwd_getps.efd = -1;
	acsmkpwd_getps.passwd = acsmkpwd_pwd1;
	acsmkpwd_getps.pwlen = sizeof(acsmkpwd_pwd1)-1;
	acsmkpwd_getps.echo = "Password:";
	acsmkpwd_getps.charfilter = askpass_filter;
	acsmkpwd_getps.maskchar = 'x';
	acsmkpwd_getps.flags = GETP_WAITFILL;

	err = acs_getpasswd(&acsmkpwd_getps);

	if (err == NOSIZE) {
		if (acsmkpwd_getps.error != -1)
			xexits("password reading error (%s)", acs_strerror(acsmkpwd_getps.error));

		xexits("password input rejected by user");
	}

	if (ttyinfo.fd != -1) acsmkpwd_getps.fd = acsmkpwd_getps.efd = ttyinfo.fd;
	else acsmkpwd_getps.fd = acsmkpwd_getps.efd = -1;
	acsmkpwd_getps.passwd = acsmkpwd_pwd2;
	acsmkpwd_getps.pwlen = sizeof(acsmkpwd_pwd2)-1;
	acsmkpwd_getps.echo = "Again:";

	err = acs_getpasswd(&acsmkpwd_getps);

	if (err == NOSIZE) {
		if (acsmkpwd_getps.error != -1)
			xexits("password reading error (%s)", acs_strerror(acsmkpwd_getps.error));

		xexits("password input rejected by user");
	}

	if (!strcmp(acsmkpwd_pwd1, acsmkpwd_pwd2)) {
		acs_say("%s", acs_crypt(acsmkpwd_pwd1, acsmkpwd_salt));
	}
	else {
		acs_esay("Passwords are different, try again");
		goto _pwagain;
	}

	acs_memzero(&acsmkpwd_getps, sizeof(struct getpasswd_state));
	acs_memzero(acsmkpwd_pwd1, sizeof(acsmkpwd_pwd1));
	acs_memzero(acsmkpwd_pwd2, sizeof(acsmkpwd_pwd2));

	acs_exit(0);
	return 0;
}

#endif
