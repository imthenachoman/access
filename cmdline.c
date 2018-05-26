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

char *build_cmdline(int argc, char **argv)
{
	const char *fmt;
	size_t x;
	char *r, *s;

	fmt = "%s ";
	for (x = 0, r = s = NULL; x < argc && *(argv+x); x++) {
		if (acs_strchr(*(argv+x), ' ')) fmt = "\"%s\" ";
		acs_asprintf(&s, fmt, *(argv+x));
		acs_astrcat(&r, s);
		fmt = "%s ";
	}

	x = shrink_dynstr(&r);
	if (x > 1 && x != NOSIZE) *(r+x-2) = 0;
	pfree(s);
	return r;
}

char *build_protected_cmdline(int argc, char **argv)
{
	int x;
	size_t n, y;
	char *r, *s;

	for (x = 0, r = NULL; x < argc && *(argv+x); x++) {
		n = acs_szalloc(r);
		y = acs_strnlen(*(argv+x), ACS_XSALLOC_MAX)+1;
		r = acs_realloc(r, n+y);
		memcpy(r+n, *(argv+x), y);
	}

	s = r;
	n = acs_szalloc(s);
	r = acs_malloc(((n/2)*3)+8);
	base64_encode(r, s, n);
	pfree(s);

	shrink_dynstr(&r);
	return r;
}

/*
 * To those who would grab it for free:
 *
 * It parses quotes and quote escapes, so strings like:
 *   `/bin/sh sh -c "env; sh -c \"echo 123\"; exit 1"` <-- yes, exactly.
 * will be parsed as:
 *   a[0]->`/bin/sh`
 *   a[1]->`sh`
 *   a[2]->`-c`
 *   a[3]->`env; sh -c "echo 123"; exit 1`
 *   a[4]->NULL
 * (here, backticks are just not to confuse with double quotes).
 * However: no other special characters other than ' ' (space) and double quote
 * could be escaped!
 *
 * This is really a simple function. It does not do whole shell logic there,
 * and you should never expect it to be fully shell compatible!!
 * Because it is never called for a user input, it is safe to have errors here.
 * It simply gets the basic job right, and I am not going to enhance it anymore.
 *
 * -- Rys, 08Dec2017.
 */
char **parse_cmdline(char *p)
{
	char *s, *d;
	char **args = NULL;
	int x, y;
	size_t l, sz;

	if (!p) return NULL;
	if (str_empty(p)) return NULL;

	l = acs_strnlen(p, ACS_ALLOC_MAX);

	s = d = p; x = y = 0;
	while (1) {
		if (*d == '\"' && (d-p && *(d-1) != '\\')) {
			memmove(d, d+1, l-(d-p)); l--;
			if (!x) x = 1; else x = 0;
			continue;
		}
		if (y || (*d == ' ' && (d-p && *(d-1) != '\\') && !x)) {
			*d = 0;
			acs_strlrep(s, l, "\\ ", " ");
			acs_strlrep(s, l, "\\\"", "\"");

			sz = DYN_ARRAY_SZ(args);
			args = acs_realloc(args, (sz+(sz == 0 ? 2 : 1)) * sizeof(char *));
			if (sz) sz--;
			*(args+sz) = s;

			s = d+1;
		}
		if (y) break;
		d++; if (str_empty(d)) y = 1;
	}

	return args;
}

int is_exec(const char *path)
{
	errno = 0;
	if ((file_or_dir(path) == PATH_IS_FILE) && !errno) {
		/* checking file mode is not enough. Ask system about if it's ready to be exec'd. */
		if ((access(path, X_OK) == 0) && !errno) return 1;
	}
	return 0;
}

/* Pure `which` like, running over spath */
char *which(const char *spathspec, const char *progname, const char *root)
{
	char *tmp = NULL;
	char *spath_copy, *s, *d, *t;
	int x;

	x = is_abs_rel(progname);
	if (x) {
		if (x == PATH_ABSOLUTE) {
			if (root) acs_asprintf(&tmp, "%s%s", root, progname);
			else acs_asprintf(&tmp, "%s", progname);
		}
		else if (x == PATH_RELATIVE) {
			if (root) acs_asprintf(&tmp,
				"%s%s/%s", root, dstdir, progname);
			else acs_asprintf(&tmp, "%s/%s", dstdir, progname);
		}

		if (is_exec(tmp)) {
			shrink_dynstr(&tmp);
			return tmp;
		}

		pfree(tmp);
		return NULL;
	}

	spath_copy = acs_strdup(spathspec ? spathspec : get_spath());

	s = d = spath_copy; t = NULL; x = 0;
	while ((s = acs_strtok_r(d, ":", &t))) {
		if (d) d = NULL;

		if (root) acs_asprintf(&tmp, "%s%s/%s", root, s, progname);
		else acs_asprintf(&tmp, "%s/%s", s, progname);

		errno = 0;
		if (is_exec(tmp)) {
			x = 1;
			break;
		}
	}

	pfree(spath_copy);

	if (x) {
		shrink_dynstr(&tmp);
		return tmp;
	}

	pfree(tmp);
	return NULL;
}

char *find_access(const char *name)
{
	char *r = NULL;

	acs_asprintf(&r, "%s/bin/%s", PREFIX, name ? name : PROGRAM_NAME);
	if (is_exec(r)) return r;

	pfree(r);
	return which(spath, name ? name : PROGRAM_NAME, NULL);
}
