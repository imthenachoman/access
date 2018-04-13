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

/*
 * Total getgrent port refactor by Lynx -- 29Jun2017.
 *
 * This code is not heavily tested - it is not in access by default,
 * and used only on crippled systems.
 *
 * This refactor gives me an idea of new passwd db functions for SL libc.
 * I will revisit this stuff someday later.
 */

#ifdef WITH_PORTS

static FILE *__gr_f;

static unsigned atou(char **s)
{
	unsigned x;
	for (x=0; **s-'0'<10U; ++*s) x=10*x+(**s-'0');
	return x;
}

static struct group *xgetgrent_a(FILE *f, struct group *gr, char **line, char ***mem)
{
	char *s, *d, *t, *gr_mems = NULL;
	size_t x, filled;

	acs_free(*line);
	*line = acs_malloc_real(ACS_ALLOC_MAX);
	if (!*line) return NULL;

	while (1) {
		if (acs_fgets(*line, ACS_ALLOC_MAX, f) == NOSIZE) {
			acs_free(*line); *line = NULL;
			return NULL;
		}

		x = filled = 0;
		s = d = *line; t = NULL;
		while ((s = acs_strtok_r(d, ":", &t))) {
			if (d) d = NULL;
			switch (x) {
				case 0: gr->gr_name = s; break;
				case 1: gr->gr_passwd = s; break;
				case 2: gr->gr_gid = atou(&s); filled = 1; break;
				default: gr_mems = s; break;
			}
			x++;
		}

		if (filled) break;
	}

	acs_free(*mem); *mem = NULL;
	if (gr_mems) {
		x = 0;
		s = d = gr_mems; t = NULL;
		while ((s = acs_strtok_r(d, ",", &t))) {
			if (d) d = NULL;
			*mem = acs_realloc_real(*mem, sizeof(char *) * (x+2));
			if (!*mem) {
				acs_free(*line); *line = NULL;
				return NULL;
			}
			*(*mem+x) = s;
			x++;
		}
	}
	else *mem = acs_malloc_real(sizeof(char *));
	gr->gr_mem = *mem;

	return gr;
}

void xsetgrent()
{
	if (__gr_f) fclose(__gr_f);
	__gr_f = 0;
}

struct group *xgetgrent()
{
	static char *line, **mem;
	static struct group gr;
	if (!__gr_f) __gr_f = fopen("/etc/group", "rbe");
	if (!__gr_f) return 0;
	return xgetgrent_a(__gr_f, &gr, &line, &mem);
}

#endif
