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

struct rlimitnames {
	int num;
	char shellname;
	const char *name;
};

#ifdef WITH_RESETRLIMITS
static struct rlimit rlim_tmp;

/* save and reset critical ones which may affect access operation. */
struct prsvrlims {
#ifdef RLIMIT_DATA
	struct rlimit data;
#else
#warning REQUIRED rlimit type RLIMIT_DATA is not defined!
#endif
#ifdef RLIMIT_STACK
	struct rlimit stack;
#else
#warning REQUIRED rlimit type RLIMIT_STACK is not defined!
#endif
#ifdef RLIMIT_RSS
	struct rlimit rss;
#endif
#ifdef RLIMIT_AS
	struct rlimit as;
#endif
#ifdef RLIMIT_CORE
	struct rlimit core;
#else
#warning REQUIRED rlimit type RLIMIT_CORE is not defined!
#endif
#ifdef RLIMIT_FSIZE
	struct rlimit fsize;
#endif
#ifdef RLIMIT_NOFILE
	struct rlimit nofile;
#endif
#ifdef RLIMIT_NPROC
	struct rlimit nproc;
#endif
};

static struct prsvrlims prsv_rlims;
#endif

/* shell "ulimit" opt chars are taken from busybox ash... */
static const struct rlimitnames rlimits[] = {
#ifdef RLIMIT_CPU
	{RLIMIT_CPU, 't', ACS_CPPNSTR(RLIMIT_CPU)},
#endif
#ifdef RLIMIT_FSIZE
	{RLIMIT_FSIZE, 'f', ACS_CPPNSTR(RLIMIT_FSIZE)},
#endif
#ifdef RLIMIT_DATA
	{RLIMIT_DATA, 'd', ACS_CPPNSTR(RLIMIT_DATA)},
#endif
#ifdef RLIMIT_STACK
	{RLIMIT_STACK, 's', ACS_CPPNSTR(RLIMIT_STACK)},
#endif
#ifdef RLIMIT_CORE
	{RLIMIT_CORE, 'c', ACS_CPPNSTR(RLIMIT_CORE)},
#endif
#ifdef RLIMIT_RSS
	{RLIMIT_RSS, 'm', ACS_CPPNSTR(RLIMIT_RSS)},
#endif
#ifdef RLIMIT_NPROC
	{RLIMIT_NPROC, 'p', ACS_CPPNSTR(RLIMIT_NPROC)},
#endif
#ifdef RLIMIT_NOFILE
	{RLIMIT_NOFILE, 'n', ACS_CPPNSTR(RLIMIT_NOFILE)},
#endif
#ifdef RLIMIT_MEMLOCK
	{RLIMIT_MEMLOCK, 'l', ACS_CPPNSTR(RLIMIT_MEMLOCK)},
#endif
#ifdef RLIMIT_AS
	{RLIMIT_AS, 'v', ACS_CPPNSTR(RLIMIT_AS)},
#endif
#ifdef RLIMIT_LOCKS
	{RLIMIT_LOCKS, 'w', ACS_CPPNSTR(RLIMIT_LOCKS)},
#endif
#ifdef RLIMIT_SIGPENDING /* not in ash */
	{RLIMIT_SIGPENDING, 'S', ACS_CPPNSTR(RLIMIT_SIGPENDING)},
#endif
#ifdef RLIMIT_MSGQUEUE /* not in ash */
	{RLIMIT_MSGQUEUE, 'Q', ACS_CPPNSTR(RLIMIT_MSGQUEUE)},
#endif
#ifdef RLIMIT_NICE
	{RLIMIT_NICE, 'e', ACS_CPPNSTR(RLIMIT_NICE)},
#endif
#ifdef RLIMIT_RTPRIO
	{RLIMIT_RTPRIO, 'r', ACS_CPPNSTR(RLIMIT_RTPRIO)},
#endif
};

static int numrlim(const char *name)
{
	size_t x;

	if (is_number(name, 0)) return atoi(name);

	for (x = 0; x < STAT_ARRAY_SZ(rlimits); x++) {
		if (*name == rlimits[x].shellname && str_empty(name+1)) return rlimits[x].num;
		else if (!strcmp(name, rlimits[x].name) || !strcmp(name, rlimits[x].name+7)) return rlimits[x].num;
	}

	return -1;
}

void add_rlimspec(const char *rlimspec)
{
	size_t x;

	x = DYN_ARRAY_SZ(rlimspec_list);
	rlimspec_list = acs_realloc(rlimspec_list, (x+1) * sizeof(char *));
	rlimspec_list[x] = acs_strdup(rlimspec);
}

void remove_rlimspec(const char *rlimspec)
{
	size_t x, sz;

	sz = DYN_ARRAY_SZ(rlimspec_list);
	for (x = 0; x < sz; x++) {
		if (rlimspec_list[x] && !strcmp(rlimspec_list[x], rlimspec))
			pfree(rlimspec_list[x]);
	}
}

int apply_rlimspec(const char *rlimspec)
{
	static char *tmp;
	char *s, *d;
	int res;
	struct rlimit r;

	r.rlim_cur = r.rlim_max = 0;

	if (!tmp) tmp = acs_malloc(ACS_ALLOC_SMALL);

	acs_strlcpy(tmp, rlimspec, ACS_ALLOC_SMALL);
	s = tmp;
	d = acs_strchr(s, ':');
	if (!d) goto _err;
	*d = 0;
	res = numrlim(s); s = d+1;
	if (res == -1) goto _err;
	d = acs_strchr(s, ':');
	if (!d) goto _err;
	*d = 0;
	if (!strcmp(s, "-1")) r.rlim_cur = RLIM_INFINITY;
	else r.rlim_cur = (rlim_t)atol_prefixed(s);
	s = d+1;
	if (!strcmp(s, "-1")) r.rlim_max = RLIM_INFINITY;
	else r.rlim_max = (rlim_t)atol_prefixed(s);

	return setrlimit(res, &r);

_err:
	xexits("invalid rlimspec specification '%s' (should be: nrlim:soft:hard)", rlimspec);
	return 1; /* never */
}

void process_rlimits(void)
{
	size_t x, sz;

	sz = DYN_ARRAY_SZ(rlimspec_list);
	for (x = 0; x < sz; x++) {
		if (rlimspec_list[x] && apply_rlimspec(rlimspec_list[x]) == -1)
			xerror("rlimspec %s failed", rlimspec_list[x]);
	}
}

#ifdef WITH_RESETRLIMITS
#define getprsvrlim(x, y) \
	do { if (getrlimit(x, &y) == -1) { acs_perror("preserving rlimit %s failed", #x); reseterr(); } } while (0)

void preserve_user_limits(void)
{
#ifdef RLIMIT_STACK
	getprsvrlim(RLIMIT_STACK, prsv_rlims.stack);
#endif
#ifdef RLIMIT_DATA
	getprsvrlim(RLIMIT_DATA, prsv_rlims.data);
#endif
#ifdef RLIMIT_RSS
	getprsvrlim(RLIMIT_RSS, prsv_rlims.rss);
#endif
#ifdef RLIMIT_AS
	getprsvrlim(RLIMIT_AS, prsv_rlims.as);
#endif
#ifdef RLIMIT_FSIZE
	getprsvrlim(RLIMIT_FSIZE, prsv_rlims.fsize);
#endif
#ifdef RLIMIT_CORE
	getprsvrlim(RLIMIT_CORE, prsv_rlims.core);
#endif
#ifdef RLIMIT_NOFILE
	getprsvrlim(RLIMIT_NOFILE, prsv_rlims.nofile);
#endif
#ifdef RLIMIT_NPROC
	getprsvrlim(RLIMIT_NPROC, prsv_rlims.nproc);
#endif
}

#define resetrlim(x, s, h) \
	do { rlim_tmp.rlim_cur = s; rlim_tmp.rlim_max = h; \
	if (setrlimit(x, &rlim_tmp) == -1) { prsvrlims_fail = 1; acs_perror("resetting rlimit %s failed", #x); reseterr(); } } while (0)

#define setprsvrlim(x, y) \
	do { if (setrlimit(x, &y) == -1) { prsvrlims_fail = 1; acs_perror("setting rlimit %s failed", #x); reseterr(); } } while (0)

void reset_user_limits(void)
{
#ifdef RLIMIT_STACK
	/* reset to some safe value */
	resetrlim(RLIMIT_STACK, 1024*8192, 1024*8192);
#endif
#ifdef RLIMIT_DATA
	resetrlim(RLIMIT_DATA, -1, -1);
#endif
#ifdef RLIMIT_RSS
	resetrlim(RLIMIT_RSS, -1, -1);
#endif
#ifdef RLIMIT_AS
	resetrlim(RLIMIT_AS, -1, -1);
#endif
#ifdef RLIMIT_FSIZE
	resetrlim(RLIMIT_FSIZE, -1, -1);
#endif
#ifdef RLIMIT_CORE
	/* do not dump cores even if OS permits us */
	resetrlim(RLIMIT_CORE, 0, 0);
#endif
#ifdef RLIMIT_NOFILE
	resetrlim(RLIMIT_NOFILE, 1024, 4096);
#endif
#ifdef RLIMIT_NPROC
	/* enough? */
	resetrlim(RLIMIT_NPROC, 64, 64);
#endif
}

void restore_user_limits(void)
{
#ifdef RLIMIT_STACK
	setprsvrlim(RLIMIT_STACK, prsv_rlims.stack);
#endif
#ifdef RLIMIT_DATA
	setprsvrlim(RLIMIT_DATA, prsv_rlims.data);
#endif
#ifdef RLIMIT_RSS
	setprsvrlim(RLIMIT_RSS, prsv_rlims.rss);
#endif
#ifdef RLIMIT_AS
	setprsvrlim(RLIMIT_AS, prsv_rlims.as);
#endif
#ifdef RLIMIT_FSIZE
	setprsvrlim(RLIMIT_FSIZE, prsv_rlims.fsize);
#endif
#ifdef RLIMIT_CORE
	setprsvrlim(RLIMIT_CORE, prsv_rlims.core);
#endif
#ifdef RLIMIT_NOFILE
	setprsvrlim(RLIMIT_NOFILE, prsv_rlims.nofile);
#endif
#ifdef RLIMIT_NPROC
	setprsvrlim(RLIMIT_NPROC, prsv_rlims.nproc);
#endif
}
#endif
