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

/* This code was taken from ryshttpd. */

#include "access.h"

struct config {
	void *cfgdata; /* config file as whole */
	void *cfgbkup; /* pristine backup copy */
	size_t cfglen; /* it's length */
	int currlnum; /* current line number */
	char *d, *t; /* for strtok_r */
};

static size_t small_file_fdsize(int fd)
{
	off_t l, cur;

	cur = lseek(fd, 0L, SEEK_CUR);
	l = lseek(fd, 0L, SEEK_SET);
	if (l == -1) return NOSIZE;
	l = lseek(fd, 0L, SEEK_END);
	if (l == -1) return NOSIZE;
	lseek(fd, cur, SEEK_SET);

	return (size_t)l;
}

int is_comment(const char *s)
{
	if (str_empty(s)
	|| *s == '#'
	|| *s == '\n'
	|| (*s == '\r' && *(s+1) == '\n')
	|| *s == ';'
	|| (*s == '/' && *(s+1) == '/')) return 1;
	return 0;
}

void *load_config(int fd)
{
	size_t x;
	struct config *r;
	char *s;

	r = acs_malloc(sizeof(struct config));

	x = small_file_fdsize(fd);
	if (x == NOSIZE) {
		free_config(r);
		return NULL;
	}

	r->cfgdata = acs_malloc(x+1); /* so last line will not face xmalloc safety zone. */
	if ((size_t)read(fd, r->cfgdata, x) != x) {
		free_config(r);
		return NULL;
	}

	r->cfglen = acs_strlrep(r->cfgdata, x, "\r\n", "\n");
	r->cfgdata = acs_realloc(r->cfgdata, r->cfglen+1);
	s = r->cfgdata+r->cfglen; *s = 0;

	r->cfgbkup = acs_malloc(r->cfglen);
	memcpy(r->cfgbkup, r->cfgdata, r->cfglen);

	r->currlnum = 0;
	r->d = r->cfgdata;
	return (void *)r;
}

char *get_config_line(void *config)
{
	struct config *cfg;
	char *line, *s, *d;

	if (!config) return NULL;
	cfg = config;

	if (cfg->currlnum == 0) {
		s = d = cfg->cfgdata;
		while (*d && d-s < cfg->cfglen && *d == '\n') {
			d++;
			cfg->currlnum++;
		}
	}

_again:
	line = acs_strtok_r(cfg->t ? NULL : cfg->d, "\n", &cfg->t);
	if (!line) return NULL;
	cfg->currlnum++;
	if (cfg->t) {
		s = cfg->cfgdata;
		d = cfg->t;
		while (*d && d-s < cfg->cfglen && *d == '\n') {
			d++;
			cfg->currlnum++;
		}
	}
	if (is_comment(line)) goto _again;

	return line;
}

int *config_current_line_number(void *config)
{
	struct config *cfg;

	if (!config) return NULL;
	cfg = config;
	return &cfg->currlnum;
}

void reset_config(void *config)
{
	struct config *cfg;

	if (!config) return;
	cfg = config;

	memcpy(cfg->cfgdata, cfg->cfgbkup, cfg->cfglen);

	cfg->d = cfg->cfgdata;
	cfg->t = NULL;
	cfg->currlnum = 0;
}

void free_config(void *config)
{
	struct config *cfg;

	cfg = config;
	pfree(cfg->cfgdata);
	pfree(cfg->cfgbkup);
	pfree(cfg);
}
