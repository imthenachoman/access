/*
 * access -- authenticator for Unix systems.
 *
 * access is copyrighted:
 * Copyright (C) 2014-2018 Andrey Rys. All rights reserved.
 * This file Copyright (C) 2005-2013 Rich Felker, adopted for access.
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

#ifdef WITH_PORTS
void xsetgrent();
#define xendgrent xsetgrent
struct group *xgetgrent();

int acs_getgrouplist(const char *user, gid_t gid, gid_t *groups, int *ngroups)
{
	size_t n, i;
	struct group *gr;
	if (*ngroups<1) return -1;
	n = *ngroups;
	*groups++ = gid;
	*ngroups = 1;

	xsetgrent();
	while ((gr = xgetgrent()) && *ngroups < INT_MAX) {
		for (i=0; gr->gr_mem[i] && strcmp(user, gr->gr_mem[i]); i++);
		if (!gr->gr_mem[i]) continue;
		if (++*ngroups <= n) *groups++ = gr->gr_gid;
	}
	xendgrent();

	return *ngroups > n ? -1 : *ngroups;
}
#else
int acs_getgrouplist(const char *user, gid_t gid, gid_t *groups, int *ngroups)
{
	return getgrouplist(user, gid, groups, ngroups);
}
#endif
