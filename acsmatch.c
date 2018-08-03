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

#ifdef WITH_ACSMATCH_PROG

/*
 * Match pattern against string.
 * -q: be quiet (never output anything)
 * -v: be verbose (output a status string)
 * -b: output a null divided cells to parse manually with xargs(1)
 * By default, without options, it simply outputs a status number.
 * Shell return 0 on "success", 1 on "failure".
 */

static int acsmatch_quiet;
static int acsmatch_verbose;

static void acsmatch_usage(void)
{
	acs_say("usage: acsmatch [-qvb] type pattern string");
	acs_say("type: regex,fnmatch,strcmp");
	acs_exit(1);
}

int acsmatch_main(int argc, char **argv, uid_t srcuid, gid_t srcgid, int srcgsz, gid_t *srcgids)
{
	int c, type, status;

	set_progname("acsmatch");

	if (is_setuid()) {
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

	acs_opterr = 1;
	while ((c = acs_getopt(argc, argv, "qvb")) != -1) {
		switch (c) {
			case 'q': acsmatch_quiet = 1; break;
			case 'v': acsmatch_verbose = 1; break;
			case 'b': acsmatch_verbose = 2; break; /* binary out */
			default: acsmatch_usage(); break;
		}
	}

	if (!argv[acs_optind]) acsmatch_usage();
	type = get_match_type_byname(argv[acs_optind]);
	if (type <= 0) acsmatch_usage();
	if (!argv[acs_optind+1] || !argv[acs_optind+2]) acsmatch_usage();

	status = match_pattern_type(argv[acs_optind+1], argv[acs_optind+2], type);

	if (acsmatch_quiet) goto _ret;
	else if (!acsmatch_verbose) acs_esay("%d", status);
	else if (acsmatch_verbose == 1)
		acs_esay("%s:\"%s\":\"%s\"=%d",
		argv[acs_optind], argv[acs_optind+1], argv[acs_optind+2], status);
	else if (acsmatch_verbose == 2) {
		write(1, argv[acs_optind], strlen(argv[acs_optind]));
		write(1, "\0", 1);
		write(1, argv[acs_optind+1], strlen(argv[acs_optind+1]));
		write(1, "\0", 1);
		write(1, argv[acs_optind+2], strlen(argv[acs_optind+2]));
		write(1, "\0", 1);
		write(1, status ? "1" : "0", 1);
		write(1, "\0", 1);
	}

	/* shell translate */
_ret:	return status ? 0 : 1;
}

#endif
