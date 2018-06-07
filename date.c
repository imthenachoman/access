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

static char *getsdate(time_t t, const char *fmt)
{
	char *r;
	size_t rn;
	struct tm *tmnow;

	rn = ACS_ALLOC_SMALL;
	r = acs_malloc(rn);

	if (!fmt) fmt = "%c";
	tmnow = localtime(&t);
	if (!tmnow) {
		acs_asprintf(&r, "(localtime error: %s)", acs_strerror(errno));
		return r;
	}
_again:	if (strftime(r, rn, fmt, tmnow) == 0) {
		rn += ACS_ALLOC_SMALL;
		if (rn > ACS_XSALLOC_MAX) {
			acs_realloc(r, ACS_ALLOC_SMALL);
			acs_asprintf(&r, "(getsdate error: tried to allocate %zu bytes)", rn);
			return r;
		}
		r = acs_realloc(r, rn);
		goto _again;
	}

	shrink_dynstr(&r);
	return r;
}

void init_datetime(void)
{
	if (curr_time && curr_date) return;

	curr_time = time(NULL);
	curr_date = getsdate(curr_time, NULL);
	curr_secs = getsdate(curr_time, "%s");
}

/*
 * do not touch curr_time, but update
 * curr_date if user had set custom tstamp format.
 */
void update_datetime(void)
{
	if (!timefmt) return;
	pfree(curr_date);
	curr_date = getsdate(curr_time, timefmt);
}
