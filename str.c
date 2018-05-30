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

/* fault on NULL str */
int str_empty(const char *str)
{
	if (!*str) return 1;
	return 0;
}

char *acs_strndup(const char *s, size_t n)
{
	size_t l = acs_strnlen(s, n);
	char *d = acs_malloc_real(l+1); /* gives zero memory */

	if (!d) return NULL;
	memcpy(d, s, l);

	return d;
}

size_t char_to_nul(char *s, size_t l, char c)
{
	char *os = s;
	int found = 0;

	while (*s && l) {
		if (*s == c) {
			*s = 0;
			found = 1;
			break;
		}
		s++;
		l--;
	}
	return found ? s-os : NOSIZE;
}

int acs_snprintf(char *s, size_t n, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = acs_vsnprintf(s, n, fmt, ap);
	va_end(ap);
	return r;
}

static int acs_vsnprintf_real(char *s, size_t n, const char *fmt, va_list ap)
{
	int r;
	va_list t;
#ifdef HAVE_NO_SNPRINTF
	FILE *fdevnull;
#endif

	acs_memzero(s, n);

#ifdef HAVE_NO_SNPRINTF
	fdevnull = fopen("/dev/null", "w");
	if (!fdevnull) xexits("acs_vsnprintf: /dev/null is not available!");
	va_copy(t, ap);
	r = vfprintf(fdevnull, fmt, t);
	va_end(t);
	fclose(fdevnull);
	if (r < 0 || r >= n) return r;
	if (n && s) r = vsprintf(s, fmt, t);
#else
	va_copy(t, ap);
	r = vsnprintf(s, n, fmt, t);
	va_end(t);
#endif
	return r;
}

int acs_vsnprintf(char *s, size_t n, const char *fmt, va_list ap)
{
	int r;
	va_list t;

	va_copy(t, ap);
	r = acs_vsnprintf_real(s, n, fmt, t);
	va_end(t);
	if (r < 0) xexits("acs_vsnprintf: error occured.");
	else if (r >= n) xexits("acs_vsnprintf: buffer too short.");

	return r;
}

int acs_vasprintf(char **s, const char *fmt, va_list ap)
{
	int r;
	size_t n;
	va_list t;

	if (!*s) {
		n = ACS_ALLOC_SMALL;
		*s = acs_malloc_real(n);
		if (!*s) return -1;
	}
	else n = acs_szalloc(*s);

	va_copy(t, ap);
	r = acs_vsnprintf_real(*s, n, fmt, t);
	va_end(t);
	if (r == -1) return -1;
	if (r >= ACS_XSALLOC_MAX) {
		errno = ERANGE;
		return -1;
	}

	if (r >= n) {
		char *p;

		n = (size_t)r+1;
		p = acs_realloc_real(*s, n);
		if (!p) return -1;
		*s = p;

		va_copy(ap, t);
		r = acs_vsnprintf_real(*s, n, fmt, t);
		va_end(t);
		if (r == -1) return -1;
	}

	return r;
}

int acs_asprintf(char **s, const char *fmt, ...)
{
	int r;
	va_list ap;

	va_start(ap, fmt);
	r = acs_vasprintf(s, fmt, ap);
	if (r == -1) xerror("acs_asprintf");
	va_end(ap);

	return r;
}

size_t acs_strlcpy(char *d, const char *s, size_t n)
{
	size_t x;

	acs_memzero(d, n);

	x = acs_strlcpy_real(d, s, n);
	if (x >= n) xexits("acs_strlcpy complains that data is truncated.");
	return x;
}

size_t acs_strnlen(const char *s, size_t n)
{
	const char *p = memchr(s, 0, n);
	return p ? p-s : n;
}

char *acs_strdup(const char *s)
{
	char *r = acs_strndup(s, ACS_XSALLOC_MAX);
	if (!r) {
		errstr = NULL;
		xerror("acs_strdup");
		return NULL;
	}
	else return r;
}

char *acs_strnstr(const char *hs, const char *ne, size_t hsn)
{
	size_t nen = acs_strnlen(ne, ACS_XSALLOC_MAX);
	if (hsn > ACS_XSALLOC_MAX) hsn = ACS_XSALLOC_MAX;
	hsn = acs_strnlen(hs, hsn);
	return acs_memmem(hs, hsn, ne, nen);
}

char *acs_strstr(const char *hs, const char *ne)
{
	return acs_strnstr(hs, ne, ACS_XSALLOC_MAX);
}

char *acs_strnchr(const char *s, char c, size_t n)
{
	if (n > ACS_XSALLOC_MAX) n = ACS_XSALLOC_MAX;
	n = acs_strnlen(s, n);
	return acs_memmem(s, n, &c, sizeof(char));
}

char *acs_strchr(const char *s, char c)
{
	return acs_strnchr(s, c, ACS_XSALLOC_MAX);
}

int is_fmtstr(const char *s)
{
	if (!s || str_empty(s)) return 0;
	if (acs_strstr(s, "%{") && acs_strchr(s, '}')) return 1;
	return 0;
}

static int getxchr(char *chr, const char *s)
{
	unsigned long x;
	char *p;

	if (!s || str_empty(s)) return 0;
	chr[1] = 0;
	x = strtoul(s, &p, 16);
	if (str_empty(p)) {
		chr[0] = (unsigned char)x;
		return 1;
	}
	return 0;
}

/* it should never overflow, so it is safe to pass a nonexpandable buffer here. */
void parse_escapes(char *str, size_t n)
{
	char chr[2], spec[5], *s, *d;

	if (!str || str_empty(str)) return;
	if (!acs_strnchr(str, '\\', n)) return;

	acs_strlrep(str, n, "\\n", "\n");
	acs_strlrep(str, n, "\\r", "\r");
	acs_strlrep(str, n, "\\t", "\t");

	s = str;
	while (1) {
		d = acs_strnstr(s, "\\x", n-(s-str));
		if (!d) break;
		acs_strlcpy_real(spec, d, sizeof(spec));
		if (!acs_isxdigit(spec[3])) spec[3] = 0;
		if (!getxchr(chr, spec+2)) goto _cont;
		acs_strlrep(str, n, spec, chr);
_cont:		s = d+1;
		if (s-str >= n) break;
	}
}

char *parse_fmtstr(struct fmtstr_state *fst)
{
	struct fmtstr_args *args = fst->args;
	int nargs = fst->nargs;
	const char *fmt = fst->fmt;
	char *out = fst->result;
	size_t outl = fst->result_sz;
	char *s, *d;
	size_t n;
	int x, f;

	if (!is_fmtstr(fmt)) {
		/* get slack and never do the useless hard job */
		n = acs_strlcpy_real(out, fmt, outl);
		if (n >= outl) fst->trunc = 1;
		fst->nr_parsed = 0;
		return out;
	}

	n = acs_strlcpy_real(out, fmt, outl);
	if (n >= outl) {
		fst->trunc = 1;
		fst->nr_parsed = 0;
		return out;
	}

	s = d = NULL;
	for (x = 0; x < nargs
	&& (args+x)
	&& (args+x)->spec; x++) {
		acs_asprintf(&s, "%%{%s}", (args+x)->spec);
		if (!acs_strstr(fmt, s)) continue; /* not found - get slack now! */

		switch ((args+x)->size) {
			case 1: acs_asprintf(&d, (args+x)->fmt, *(uint8_t *)(args+x)->data); break;
			case 2: acs_asprintf(&d, (args+x)->fmt, *(uint16_t *)(args+x)->data); break;
			case 4: acs_asprintf(&d, (args+x)->fmt, *(uint32_t *)(args+x)->data); break;
			case 8: acs_asprintf(&d, (args+x)->fmt, *(uint64_t *)(args+x)->data); break;
			default: acs_asprintf(&d, (args+x)->fmt,
				(args+x)->data ? (args+x)->data : "");
				break;
		}

		f = -1;
		n = acs_strltrep(out, outl, &f, s, d);
		if (n == outl) {
			fst->trunc = 1;
			break;
		}
		if (f > 0) fst->nr_parsed++;
	}

	pfree(s);
	pfree(d);

	return out;
}

size_t shrink_dynstr(char **s)
{
	size_t x;

	if (!s) return NOSIZE;
	if (!*s) return NOSIZE;
	if (str_empty(*s)) return 0;

	x = acs_strnlen(*s, ACS_XSALLOC_MAX)+1;
	*s = acs_realloc(*s, x);
	return x;
}

void acs_astrcat(char **d, const char *s)
{
	size_t dn, sn, t;
	char *dd;

	if (!s || !d) return;
	if (!*d) {
		*d = acs_strdup(s);
		return;
	}

	dd = *d;
	sn = acs_strnlen(s, ACS_XSALLOC_MAX);
	dn = t = shrink_dynstr(&dd);
	if (t > 0) t--;
	dn += sn+1;
	dd = acs_realloc(dd, dn);
	acs_strlcpy(dd+t, s, sn+1);
	*d = dd;
}

char *preset_parse_fmtstr(const char *fmts)
{
	char *r;
	size_t rsz;
	struct fmtstr_args *fsa;
	struct fmtstr_state fst;
	size_t nr_fsa;

	if (!is_fmtstr(fmts)) return acs_strdup(fmts);

	rsz = ACS_ALLOC_MAX;
	r = acs_malloc(rsz);

	preset_fsa_full(&fsa, &nr_fsa);

_again:	acs_memzero(&fst, sizeof(struct fmtstr_state));
	fst.args = fsa;
	fst.nargs = nr_fsa;
	fst.fmt = fmts;
	fst.result = r;
	fst.result_sz = rsz;

	parse_fmtstr(&fst);

	if (fst.trunc) {
		rsz /= 2; rsz *= 3;
		r = acs_realloc(r, rsz);
		goto _again;
	}

	pfree(fsa);

	if (fst.nr_parsed) {
		shrink_dynstr(&r);
		return r;
	}
	else {
		pfree(r);
		return acs_strdup(fmts);
	}
}

size_t remove_chars(char *str, size_t max, const char *rm)
{
	const char *urm;
	char *s;
	size_t ntail;

	urm = rm; ntail = 0;
	while (*urm) {
_findanother:	s = memchr(str, *urm, max);
		if (s) {
			memmove(s, s+1, max-(s-str)-1);
			ntail++;
			goto _findanother;
		}
		urm++;
	}
	acs_memzero(str+(max-ntail), ntail);
	return max-ntail;
}
