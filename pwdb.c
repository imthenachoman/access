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

uid_t uidbyname(const char *name)
{
	struct passwd *p;
	uid_t x;

	reseterr();
	x = usermap_getuid(name);
	if (x != NOUID) return x;
	if (is_number(name, 0))
		return (uid_t)atoi(name);
	p = getpwnam(name);
	if (p) return p->pw_uid;
	else {
		seterr("user was not found");
		return NOUID;
	}
}

gid_t gidbyuid(uid_t uid)
{
	struct passwd *p;
	gid_t x;

	reseterr();
	x = usermap_getgidbyuid(uid);
	if (x != NOGID) return x;
	p = getpwuid(uid);
	if (p) return p->pw_gid;
	else {
		seterr("no valid entry for this uid");
		return NOGID;
	}
}

gid_t gidbyname(const char *name)
{
	struct group *g;
	gid_t x;

	reseterr();
	x = usermap_getgid(name);
	if (x != NOGID) return x;
	if (is_number(name, 0))
		return (gid_t)atoi(name);
	g = getgrnam(name);
	if (g) return g->gr_gid;
	else {
		seterr("group was not found");
		return NOGID;
	}
}

int getugroups(const char *name, gid_t gr, gid_t *grps, int *ngrps)
{
	reseterr();
	if (is_number(name, 0)) {
		struct passwd *p;
		p = getpwuid(atoi(name));
		if (p) name = p->pw_name;
		else seterr("no valid entry for this uid");
	}
	return acs_getgrouplist(name, gr, grps, ngrps);
}

char *shellbyname(const char *name)
{
	struct passwd *p;
	char *r;

	reseterr();
	r = usermap_getushell(name);
	if (r) return r;
	if (is_number(name, 0)) {
		p = getpwuid(atoi(name));
		if (!p) goto _binsh;
	}
	else {
		p = getpwnam(name);
		if (!p) goto _binsh;
	}
	r = acs_strndup(p->pw_shell, ACS_ALLOC_MAX);
	if (!r) goto _binsh;
	return r;

_binsh:
	return default_shell;
}

char *udirbyname(const char *name)
{
	struct passwd *p;
	char *r;

	reseterr();
	r = usermap_getudir(name);
	if (r) return r;
	if (is_number(name, 0)) {
		p = getpwuid(atoi(name));
		if (!p) goto _root;
	}
	else {
		p = getpwnam(name);
		if (!p) goto _root;
	}
	r = acs_strndup(p->pw_dir, ACS_ALLOC_MAX);
	if (!r) goto _root;
	return r;

_root:
	return default_root;
}

char *namebyuid(uid_t uid)
{
	struct passwd *p;
	char *r;

	reseterr();
	r = usermap_getnamebyuid(uid);
	if (r) return r;
	p = getpwuid(uid);
	if (p) return acs_strdup(p->pw_name);
	else {
		acs_asprintf(&r, "%u", uid);
		shrink_dynstr(&r);
		return r;
	}
}

char *namebygid(gid_t gid)
{
	struct group *g;

	reseterr();
	g = getgrgid(gid);
	if (g) return acs_strdup(g->gr_name);
	else {
		char *r = NULL;
		acs_asprintf(&r, "%u", gid);
		shrink_dynstr(&r);
		return r;
	}
}

char *build_usergroups(int size, gid_t *list, int for_id, int do_numeric)
{
	int x;
	char *s, *r;

	if (size == 0) return acs_strdup("");

	for (x = 0, s = r = NULL; x < size; x++) {
		if (do_numeric) {
			acs_asprintf(&s, (size-x > 1) ? "%u," : "%u", *(list+x));
			acs_astrcat(&r, s);
		}
		else {
			char *t = namebygid(*(list+x));
			if (for_id)
				acs_asprintf(&s, (size-x > 1) ? "%u(%s)," : "%u(%s)", *(list+x), t);
			else acs_asprintf(&s, (size-x > 1) ? "%s," : "%s", t);
			acs_astrcat(&r, s);
			pfree(t);
		}
	}

	shrink_dynstr(&r);
	pfree(s);
	return r;
}

int match_password(const char *user, const char *secret)
{
	const char *hash;
	struct passwd *pw;
#ifdef SHADOW_SUPPORT
	struct spwd *p;
#endif

	/* First do match with locally defined usermaps */
	hash = usermap_gethash(user);
	if (hash) {
		if (!strcmp(acs_crypt(secret, hash), hash)) return 1;
	}

	/* Otherwise, ask system about user passwords */
	else {
#ifdef SHADOW_SUPPORT
		p = getspnam(user);
		if (!p) goto _pw;
		hash = p->sp_pwdp;
		if (!hash) return 0;
		if (!acs_strnlen(hash, ACS_ALLOC_MAX) && !acs_strnlen(secret, ACS_ALLOC_MAX)) return 1;
		if (!strcmp(acs_crypt(secret, hash), hash)) return 1;
_pw:
#endif
		pw = getpwnam(user);
		if (!pw) return 0;
		hash = pw->pw_passwd;
		if (!hash) return 0;
		if (!acs_strnlen(hash, ACS_ALLOC_MAX) && !acs_strnlen(secret, ACS_ALLOC_MAX)) return 1;
		if (!strcmp(acs_crypt(secret, hash), hash)) return 1;
	}

	return 0;
}

int is_numbergrps(const char *sgrps)
{
	char *sgrps_l, *s, *d, *t;

	sgrps_l = acs_strdup(sgrps);
	s = d = sgrps_l; t = NULL;
	while ((s = acs_strtok_r(d, ",", &t))) {
		if (d) d = NULL;
		if (*s == '+' || *s == '-') s++;
		if (is_number(s, 0)) {
			pfree(sgrps_l);
			return 1;
		}
	}

	pfree(sgrps_l);
	return 0;
}
