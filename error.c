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

static char no_error_str[] = "no error information";

void acs_do_exit(int status)
{
	release_lockfile();
	block_tty(&ttyinfo, 0);
	if (ttyinfo.fd != -1) put_tty(&ttyinfo);
	access_exit_memory();

	exit(status);
}

void acs_exit(int status)
{
	acs_do_exit(status);
}

void set_progname(const char *name)
{
	char *t;

	t = acs_strdup(name);
	if (progname) pfree(progname);
	progname = acs_strdup(acs_basename(t));
	pfree(t);
}

static void do_error(int status, int noexit, const char *f, va_list ap)
{
	char *p;
	va_list t;

	acs_nesay("%s: ", progname);
	va_copy(t, ap);
	acs_nvesay(f, t);
	va_end(t);
	if (errstr) p = errstr;
	else if (errno) p = acs_strerror(errno);
	else p = no_error_str;
	acs_esay(": %s", p);

	if (!noexit) acs_do_exit(status);
}

void xerror(const char *f, ...)
{
	va_list ap;

	va_start(ap, f);
	do_error(2, 0, f, ap);
	va_end(ap);
}

void xerror_status(int status, const char *f, ...)
{
	va_list ap;

	va_start(ap, f);
	do_error(status, 0, f, ap);
	va_end(ap);
}

void acs_perror(const char *f, ...)
{
	va_list ap;

	va_start(ap, f);
	do_error(2, 1, f, ap);
	va_end(ap);
}

static void do_exits(int status, const char *f, va_list ap)
{
	va_list t;

	acs_nesay("%s: ", progname);
	va_copy(t, ap);
	acs_nvesay(f, t);
	va_end(t);
	acs_esay("\n");

	acs_do_exit(status);
}

void xexits(const char *f, ...)
{
	va_list ap;

	va_start(ap, f);
	do_exits(2, f, ap);
	va_end(ap);
}

void xexits_status(int status, const char *f, ...)
{
	va_list ap;

	va_start(ap, f);
	do_exits(status, f, ap);
	va_end(ap);
}

void seterr(const char *f, ...)
{
	va_list ap;
	int r;

	errno = 0;
	va_start(ap, f);
	r = acs_vasprintf(&errstr, f, ap);
	if (r == -1) xerror("seterr");
	va_end(ap);
}

void reseterr(void)
{
	pfree(errstr);
	errno = 0;
}

/*
 * strerror NULL return and printf("%s\n", NULL) segfault
 * are very unlikely to meet in same place, but I pretend
 * to be portable. Also, if system is broken in one place,
 * it is very likely to be broken in another one.
 */
char *acs_strerror(int err)
{
	char *serr = strerror(err);
	if (!serr) return no_error_str;
	return serr;
}
