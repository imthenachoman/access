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

static void filter_logline(char *logline)
{
	size_t sz, x;
	char chr[2], schr[8];

	sz = acs_szalloc(logline);
	if (sz == 0) return;

	chr[1] = 0;
	for (x = 1; x < 32; x++) {
_last:		chr[0] = (char)x;
		acs_snprintf(schr, sizeof(schr), "\\x%02zx", x);
		if (acs_strlrep(logline, sz, chr, schr) >= sz)
			xexits("logline filtering failed");
		if (x == 127) return;
	}

	x = 127;
	goto _last;
}

#define retn(x) do { if (logfd != -1) close(logfd); pfree(path); pfree(logline); return x; } while (0)
int write_log_line(const char *blamestr)
{
	int logfd = -1;
	size_t sz;
	char *logline, *slogfmt;
	char *path = NULL;
	struct fmtstr_args *fsa;
	size_t nr_fsa;
	struct fmtstr_state fst;

	logline = acs_malloc(ACS_ALLOC_MAX);

	preset_fsa_full(&fsa, &nr_fsa);

	if (logfmt) slogfmt = acs_strdup(logfmt);
	else slogfmt = acs_strdup(DEFAULT_LOG_FORMAT);
	parse_escapes(slogfmt, acs_szalloc(slogfmt));

	acs_memzero(&fst, sizeof(struct fmtstr_state));
	fst.args = fsa;
	fst.nargs = nr_fsa;
	fst.fmt = slogfmt;
	fst.result = logline;
	fst.result_sz = ACS_ALLOC_MAX;
	parse_fmtstr(&fst);
	pfree(fsa);
	pfree(slogfmt);
	if (fst.trunc) xexits("bad logfmt= parse state");

	filter_logline(logline);

	if (blamestr) {
		acs_astrcat(&logline, ": ");
		acs_astrcat(&logline, blamestr);
	}

#ifdef SYSLOG_SUPPORT
	if (isflag(suflags, FLG_SYSLOG)) {
		openlog(PROGRAM_NAME, LOG_PID, LOG_AUTHPRIV);
		syslog(blamestr ? LOG_ALERT : LOG_NOTICE, "%s", logline);
		closelog();
		/* syslog() gives us no way to check that message is logged; always "success" */
		retn(1);
	}
	else {
#endif
		path = acs_malloc(PATH_MAX);

		preset_fsa_full(&fsa, &nr_fsa);

		acs_memzero(&fst, sizeof(struct fmtstr_state));
		fst.args = fsa;
		fst.nargs = nr_fsa;
		fst.fmt = logpath ? logpath : PATH_LOG;
		fst.result = path;
		fst.result_sz = PATH_MAX;
		parse_fmtstr(&fst);
		pfree(fsa);
		if (fst.trunc) xexits("bad logfile= parse state");

		logfd = open(path, O_CREAT|O_WRONLY|O_APPEND, 0640);
		if (logfd == -1) retn(0);
		fchmod(logfd, 0640); /* always update mode */

		acs_astrcat(&logline, "\n");
		sz = shrink_dynstr(&logline);
		if (sz > 1 && sz != NOSIZE) sz--;
		else if (sz == NOSIZE) retn(0);
		else retn(1);

		if (write(logfd, logline, sz) == -1) retn(0);

		close(logfd);
		retn(1);
#ifdef SYSLOG_SUPPORT
	}
#endif
}
