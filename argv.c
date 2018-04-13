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
 * Refine a single passed argument into multiple ones.
 * - Copy args before argv+idx,
 * - Break single arg into multiple ones further down,
 * - Copy remainings after it.
 * This one does not parses special strings, it just breaks
 * up anything which contains space.
 */
void refine_argv(int *argc, char ***argv, int idx)
{
	char **tpp, *s, *d, *t;
	int x, xidx = idx;

	tpp = acs_malloc(sizeof(char *));
	for (x = 0; x < xidx; x++) {
		tpp = acs_realloc(tpp, sizeof(char *) * (x+2));
		tpp[x] = *(*(argv)+x);
	}

	s = d = *(*(argv)+xidx); t = NULL;
	while ((s = acs_strtok_r(d, " ", &t))) {
		if (d) d = NULL;

		tpp = acs_realloc(tpp, sizeof(char *) * (x+2));
		tpp[x] = s;
		x++;
	}
	tpp[x] = NULL;

	xidx++;
	while (*(*(argv)+xidx)) {
		tpp = acs_realloc(tpp, sizeof(char *) * (x+2));
		tpp[x] = *(*(argv)+xidx);
		x++; xidx++;
	}
	tpp[x] = NULL;

	*argc = x;
	*argv = tpp;
}

void destroy_argv(char ***argv)
{
	size_t sz, x;
	char **uargv = *argv;

	sz = DYN_ARRAY_SZ(uargv);
	for (x = 0; x < sz; x++)
		pfree(*(uargv+x));
	acs_free(uargv); *argv = NULL;
}
