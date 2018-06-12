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

char *usermap_gethash(const char *user)
{
	size_t x, sz;

	sz = DYN_ARRAY_SZ(usermaps);
	for (x = 0; x < sz; x++) if (usermaps[x].user) if (!strcmp(usermaps[x].user, user)) return usermaps[x].hash;
	return NULL;
}

uid_t usermap_getuid(const char *user)
{
	size_t x, sz;

	sz = DYN_ARRAY_SZ(usermaps);
	for (x = 0; x < sz; x++) if (usermaps[x].user) if (!strcmp(usermaps[x].user, user)) return usermaps[x].uid;
	return NOUID;
}

gid_t usermap_getgid(const char *user)
{
	size_t x, sz;

	sz = DYN_ARRAY_SZ(usermaps);
	for (x = 0; x < sz; x++) if (usermaps[x].user) if (!strcmp(usermaps[x].user, user)) return usermaps[x].gid;
	return NOGID;
}

char *usermap_getudir(const char *user)
{
	size_t x, sz;

	sz = DYN_ARRAY_SZ(usermaps);
	for (x = 0; x < sz; x++) if (usermaps[x].user) if (!strcmp(usermaps[x].user, user)) return usermaps[x].udir;
	return NULL;
}

char *usermap_getushell(const char *user)
{
	size_t x, sz;

	sz = DYN_ARRAY_SZ(usermaps);
	for (x = 0; x < sz; x++) if (usermaps[x].user) if (!strcmp(usermaps[x].user, user)) return usermaps[x].shell;
	return NULL;
}

char *usermap_getnamebyuid(uid_t uid)
{
	size_t x, sz;

	sz = DYN_ARRAY_SZ(usermaps);
	for (x = 0; x < sz; x++) if (usermaps[x].uid != NOUID) if (usermaps[x].uid == uid) return usermaps[x].user;
	return NULL;
}

gid_t usermap_getgidbyuid(uid_t uid)
{
	size_t x, sz;

	sz = DYN_ARRAY_SZ(usermaps);
	for (x = 0; x < sz; x++) if (usermaps[x].uid != NOUID) if (usermaps[x].uid == uid) return usermaps[x].gid;
	return NOGID;
}
