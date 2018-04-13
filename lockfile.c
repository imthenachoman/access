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

int create_lockfile(void)
{
	struct fmtstr_args *fsa;
	size_t nr_fsa;
	struct fmtstr_state fst;
	int fd;
	char *path = NULL;

	if (is_super_user()) {
		lockfile = NULL;
		return 1;
	}

	path = acs_malloc(PATH_MAX);

	preset_fsa_full(&fsa, &nr_fsa);

	acs_memzero(&fst, sizeof(struct fmtstr_state));
	fst.args = fsa;
	fst.nargs = nr_fsa;
	fst.fmt = lockpath ? lockpath : LOCKFILE_PATH;
	fst.result = path;
	fst.result_sz = PATH_MAX;
	parse_fmtstr(&fst);
	pfree(fsa);
	if (fst.trunc) xexits("bad lockpath= parse state"); /* should not fail with builtin one */

	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd == -1) {
		if (errno == EEXIST) {
			pfree(path);
			return 0;
		}
		else blame("lockfile \"%s\" is not created: %s", path, acs_strerror(errno));
	}

	lockfile = acs_strndup(path, ACS_ALLOC_MAX);
	if (!lockfile) {
		lockfile = path;
		release_lockfile();
		xerror("creating lock");
	}

	close(fd);
	pfree(path);

	return 1;
}

/*
 * should be called BEFORE dropping superuser rights
 *
 * should not leak files, because called from:
 * - acs_exit(), which is called from everywhere
 * - before changing uids
 *
 * should fail only when EACCES
 * should not be recursive
 */
void release_lockfile(void)
{
	char *s;

	if (is_super_user()) return;

	s = lockfile;
	if (lockfile) {
		lockfile = NULL;
		if (unlink(s) == -1) xerror("releasing lock");
	}
}
