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

int is_number(const char *s, int sign)
{
	char *p;
	if (!s || str_empty(s)) return 0;
	if (sign) strtol(s, &p, 10);
	else {
		/*
		 * isxdigit is actually a hack, but
		 * next call will filter out hexs too.
		 */
		if (!acs_isxdigit(*s)) return 0;
		strtoul(s, &p, 10);
	}
	return str_empty(p) ? 1 : 0;
}

int yes_or_no(const char *s)
{
	if (!s || str_empty(s)) return YESNO_ERR;
	if (!strcasecmp(s, "yes") || !strcasecmp(s, "y") || !strcmp(s, "1")) return YESNO_YES;
	if (!strcasecmp(s, "no") || !strcasecmp(s, "n") || !strcmp(s, "0")) return YESNO_NO;
	return YESNO_UND;
}

int acs_isxdigit(char c)
{
	return (((unsigned)c - '0' < 10)
	|| (((unsigned)c - 'a' < 6) || ((unsigned)c - 'A' < 6)));
}
