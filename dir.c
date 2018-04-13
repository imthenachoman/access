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

static char *dir_path;

int acs_chdir(const char *s, int noexit)
{
	if (chdir(s) == -1) {
		noexit ? acs_perror("%s", s) : xerror("%s", s);
		if (chdir(default_root) == -1) {
			acs_perror("%s", default_root);
			return -1;
		}
	}
	return 0;
}

char *acs_getcwd(void)
{
	char *r;
	int xerrno;

	if (!dir_path) dir_path = acs_malloc(PATH_MAX);
	acs_memzero(dir_path, PATH_MAX);
	r = getcwd(dir_path, PATH_MAX);
	if (!r) {
		xerrno = errno;
		r = acs_realpath(".");
		if (!r) {
			errno = xerrno;
			return NULL;
		}
	}
	return acs_strdup(r);
}

char *acs_realpath(const char *path)
{
	char *r;

	if (!dir_path) dir_path = acs_malloc(PATH_MAX);
	acs_memzero(dir_path, PATH_MAX);
	r = realpath(path, dir_path);
	if (!r) return NULL;
	return acs_strdup(r);
}

int file_or_dir(const char *path)
{
	struct stat st;

	acs_memzero(&st, sizeof(struct stat));
	if (stat(path, &st) == -1) return -1;
	if (S_ISDIR(st.st_mode)) return PATH_IS_DIR;
	return PATH_IS_FILE;
}

/*
 * Unix abs/relative semantics:
 * 1. "/" - absolute
 * 2. "./" - relative
 * 3. "../" - relative
 * 4. contains '/', but not as first char - relative
 */
int is_abs_rel(const char *progname)
{
	char *s;

	if (*progname == '/')
		return PATH_ABSOLUTE;
	else if ((*progname == '.' && *(progname+1) == '/')
		|| (*progname == '.' && *(progname+1) == '.' && *(progname+2) == '/'))
		return PATH_RELATIVE;

	s = acs_strchr(progname, '/');
	if (s && *(s+1)) return PATH_RELATIVE;

	return 0;
}
