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
 * Accept simple single char prefix names
 */
long atol_prefixed(const char *s)
{
	char pfx[2] = {0};
	char N[128];
	size_t l;

	if (!s) return 0;

	acs_strlcpy(N, s, sizeof(N));
	l = acs_strnlen(N, sizeof(N));
	*pfx = *(N+l-1);

	if (is_number(pfx, 1) || *pfx == 'B' || *pfx == 'c') return atol(N);
	else if (*pfx == 'b') return atol(N)*512;
	else if (*pfx == 'k' || *pfx == 'K') return atol(N)*1024;
	else if (*pfx == 'm' || *pfx == 'M') return atol(N)*1024*1024;
	else if (*pfx == 'g' || *pfx == 'G') return atol(N)*1024*1024*1024;
	else return atol(N);
}
