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

/* getopt always there. */

char *acs_optarg;
int acs_optind=1, acs_opterr=1, acs_optopt, __xoptpos, __xoptreset=0;

#undef xoptpos
#define xoptpos __xoptpos

int acs_getopt(int argc, char * const argv[], const char *optstring)
{
	int i;
	wchar_t c, d;
	int k, l;
	char *optchar;

	if (!acs_optind || __xoptreset) {
		__xoptreset = 0;
		__xoptpos = 0;
		acs_optind = 1;
	}

	if (acs_optind >= argc || !argv[acs_optind] || argv[acs_optind][0] != '-' || !argv[acs_optind][1])
		return -1;
	if (argv[acs_optind][1] == '-' && !argv[acs_optind][2])
		return acs_optind++, -1;

	if (!xoptpos) xoptpos++;
	if ((k = acs_mbtowc(&c, argv[acs_optind]+xoptpos, MB_LEN_MAX)) < 0) {
		k = 1;
		c = 0xfffd; /* replacement char */
	}
	optchar = argv[acs_optind]+xoptpos;
	acs_optopt = c;
	xoptpos += k;

	if (!argv[acs_optind][xoptpos]) {
		acs_optind++;
		xoptpos = 0;
	}

	for (i=0; (l = acs_mbtowc(&d, optstring+i, MB_LEN_MAX)) && d!=c; i+=l>0?l:1);

	if (d != c) {
		if (optstring[0] != ':' && acs_opterr) {
			write(2, argv[0], strlen(argv[0]));
			write(2, ": illegal option: ", 18);
			write(2, optchar, k);
			write(2, "\n", 1);
		}
		return '?';
	}
	if (optstring[i+1] == ':') {
		if (acs_optind >= argc) {
			if (optstring[0] == ':') return ':';
			if (acs_opterr) {
				write(2, argv[0], strlen(argv[0]));
				write(2, ": option requires an argument: ", 31);
				write(2, optchar, k);
				write(2, "\n", 1);
			}
			return '?';
		}
		acs_optarg = argv[acs_optind++] + xoptpos;
		xoptpos = 0;
	}
	return c;
}
