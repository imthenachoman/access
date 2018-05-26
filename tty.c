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

void tty_init(void)
{
	int x;

	if (ttyinfo.fd != -1) return;

	for (x = 0; x < 3; x++) {
		ttyinfo.ttyname = acs_ttyname(x);
		if (ttyinfo.ttyname) break;
	}
	if (is_path_tty(ttyinfo.ttyname)) {
		if (grab_tty(&ttyinfo) == -1) xerror("grabbing tty");
	}
	else {
		ttyinfo.fd = -1;
		ttyinfo.ttyname = acs_strdup("not a tty");
	}
}

/* Used in reading a password from fd */
int fdgetstring(int fd, char *s, size_t n)
{
	size_t l;

	l = (size_t)read(fd, s, n);
	if (l != NOSIZE) {
		if (l > 0 && s[l-1] == '\n') l--;
		s[l] = 0;
	}
	else return 0;

	return 1;
}

char *acs_ttyname(int fd)
{
	char *p = ttyname(fd);
	if (!p) return NULL;
	return acs_strdup(p);
}

int is_path_tty(const char *tty_name)
{
	struct stat st;
	if (!tty_name) return 0;
	if (!strcmp(tty_name, "not a tty")) return 0;
/*	if (access(tty_name, F_OK) == -1) return 0; */
	if (stat(tty_name, &st) == -1) return 0;
	if (!S_ISCHR(st.st_mode)) return 0;
	return 1;
}
