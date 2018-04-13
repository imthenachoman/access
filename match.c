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

char *matched_dir;
extern int refind_exec;

int match_pattern_type(const char *pattern, const char *string, int type)
{
	static char *sp, *ss;
#ifdef WITH_REGEX
	regex_t r;
	int status;
#endif

	if (!sp) sp = acs_malloc(ACS_ALLOC_MAX);
	if (!ss) ss = acs_malloc(ACS_ALLOC_MAX);

	acs_strlcpy(sp, pattern, ACS_ALLOC_MAX);
	acs_strlcpy(ss, string,  ACS_ALLOC_MAX);

#ifdef WITH_REGEX
	if (type == MATCH_REGEX) {
		status = regcomp(&r, sp, REG_EXTENDED | REG_NOSUB);
		if (status) {
			size_t x;
			char *errstr;

			x = regerror(status, &r, NULL, 0);
			if (x > ACS_ALLOC_MAX) x = ACS_ALLOC_MAX;
			errstr = acs_malloc(x);
			regerror(status, &r, errstr, x);
			xexits("regcomp: %s", errstr);
		}

		status = regexec(&r, ss, 0, NULL, 0);
		regfree(&r);

		return status == 0 ? 1 : 0;
	}
#endif
	if (type == MATCH_FNMATCH) return fnmatch(sp, ss, 0) == 0 ? 1 : 0;
	if (type == MATCH_STRCMP) return strcmp(sp, ss) == 0 ? 1 : 0;
	return 0;
}

static void fixup_regex_pattern(char **s, size_t sz)
{
	char *z = *s;
	size_t n = acs_strnlen(z, sz ? sz : ACS_ALLOC_MAX);

	if (sz && sz-n < 3) return;
	if (n && *z == '^' && *(z+n-1) == '$') return;

	if (sz == 0) z = *s = acs_realloc(z, n+3);
	memmove(z+1, z, n);
	*z = '^';
	*(z+n+1) = '$';
}

int match_pattern(const char *pattern, const char *string)
{
	return match_pattern_type(pattern, string, match_type);
}

const char *get_match_type(int type)
{
	switch (type) {
		case MATCH_REGEX: return "regex";
		case MATCH_STRCMP: return "strcmp";
		case MATCH_FNMATCH: default: return "fnmatch";
	}
	return "fnmatch";
}

int get_match_type_byname(const char *s)
{
	if (!s || str_empty(s)) return 0;
	if (!strcmp(s, "regex")) return MATCH_REGEX;
	if (!strcmp(s, "fnmatch")) return MATCH_FNMATCH;
	if (!strcmp(s, "strcmp")) return MATCH_STRCMP;
	return 0;
}

/* TODO: comment this code extensively. */

#define LN_SIZEOF(s) (ACS_ALLOC_MAX-(s-ln))

flagtype execute_rule_match(void)
{
	static char *match_tmp, *match_spath;
	char *match_srcspec, *match_dstspec, *match_flgspec, *match_cmdpat;
	char *ln;
	char *s, *d, *t;
	int x, X;
	const char *tp;
	gid_t tgid, *tgids;
	int tgsz;
	struct fmtstr_args *fsa;
	struct fmtstr_state fst;
	size_t nr_fsa;
	flagtype suflags_l, argflags_l, notargflags_l;
	flagtype ret = 0;
	size_t a, b;

	if (!srcusr || !srcgrp || !srcgrps
	|| !dstusr || !dsteusr || !dstgrp || !dstegrp || !dstgrps
	|| !cmdline) return -1;

	if (!match_tmp) match_tmp = acs_malloc(ACS_ALLOC_MAX);

/*
 * Parse a line of format:
 * "[srcusr]:[srcgrp:srcgrps,srcgrps,...] [dstusr,dsteusr]:[dstgrp,dstegrp]:[dstgrps,dstgrps,...] flag,flag,... cmdline ..."
 */

	ln = get_conf_line();
	if (!ln) return -1;

	pfree(trigline); trigline = acs_strdup(ln);

	/* parse additional %set/%unset lines for flags that could not be fit into match_flgspec because of spaces */
	if (!strncmp(ln, "%set ", 5)) {
		set_variable(ln+5, 0);
		return 0;
	}
	if (!strncmp(ln, "%unset ", 7)) {
		unset_variable(ln+7);
		return 0;
	}

	/* parse local environment variables settings */
	if (!strncmp(ln, "%setenv ", 8)) {
		s = acs_strnchr(ln+8, '=', ACS_ALLOC_MAX);
		if (!s) return 0;
		*s = 0;

		if (is_envvar_exists(ln+8, EVC_CONF_UNSET)) return 0;

		if (is_super_user()
		&& (is_envvar_exists(ln+8, EVC_OPTE_SET)
		|| is_envvar_exists(ln+8, EVC_OPTE_UNSET))) return 0;

		add_envvar(ln+8, s+1, EVC_CONF_SET);
		return 0;
	}
	if (!strncmp(ln, "%delenv ", 8)) {
		if (is_super_user()
		&& (is_envvar_exists(ln+8, EVC_OPTE_SET)
		|| is_envvar_exists(ln+8, EVC_OPTE_UNSET))) return 0;

		delete_envvars(ln+8, EVC_CONF_SET, 1);
		delete_envvars(ln+8, EVC_CONF_UNSET, 1);
		return 0;
	}
	if (!strncmp(ln, "%unsetenv ", 10)) {
		if (is_super_user()
		&& (is_envvar_exists(ln+10, EVC_OPTE_SET)
		|| is_envvar_exists(ln+10, EVC_OPTE_UNSET))) return 0;

		delete_envvars(ln+10, EVC_CONF_SET, 1);
		add_envvar(ln+10, NULL, EVC_CONF_UNSET);
		return 0;
	}
	if (!strncmp(ln, "%unkeepenv ", 11)) {
		if (!embedded_variable_setstate(trusted_envvars, trusted_envvars_sz, ln+11, 0))
			delete_envvars(ln+11, EVC_KEEP_SET, 1);
		return 0;
	}

	/* Fast check for certain flags, part 1 - NO isflag()! */
	if (chrootdir) {
		if (!schrootdir) return 0;
		if (match_type == MATCH_REGEX) fixup_regex_pattern(&schrootdir, 0);
		if (!match_pattern(schrootdir, chrootdir)) return 0;
	}
	else if (schrootdir && !chrootdir) return 0;
	if (fromtty) {
		if (match_type == MATCH_REGEX) fixup_regex_pattern(&fromtty, 0);
		if (!match_pattern(fromtty, ttyinfo.ttyname)) return 0;
	}
	if (scwd) {
		if (match_type == MATCH_REGEX) fixup_regex_pattern(&scwd, 0);
		if (!match_pattern(scwd, cwd)) return 0;
	}

	/* count total nr of tokens */
	tp = ln; x = 0;
	while (*tp && tp-ln < ACS_ALLOC_MAX) {
		if (*tp == ' ') x++;
		tp++;
	}

	/* if less than 3 spaces (4 real tokens), then fail */
	if (x < 3) return 0;

	match_srcspec = match_dstspec = match_flgspec = match_cmdpat = NULL;
	s = d = ln; t = NULL; X = 0;
	while ((s = acs_strtok_r(d, " ", &t))) {
		if (d) d = NULL;

		switch (X) {
			case 0: match_srcspec = s; break;
			case 1: match_dstspec = s; break;
			case 2: match_flgspec = s; break;
			case 3: match_cmdpat  = s; break;
		}

		X++;
		if (X > 3) {
			/* unclose cmd pattern to include args */
			if (x > 3) {
				s += acs_strnlen(s, LN_SIZEOF(s));
				*s = ' ';
			}
			break;
		}
	}

	suflags_l = suflags; argflags_l = argflags; notargflags_l = notargflags;
	pfree(trigflags); trigflags = acs_strdup(match_flgspec);
	resolve_flags(match_flgspec, 0, &suflags_l, &argflags_l, &notargflags_l);

	/* Fast check for certain flags, part 2 */
	if (isflag(suflags_l, FLG_NOEUID) && strncmp(dstusr, dsteusr, ACS_ALLOC_MAX) != 0) return 0;
	if (isflag(suflags_l, FLG_NOEGID) && strncmp(dstgrp, dstegrp, ACS_ALLOC_MAX) != 0) return 0;
	if (sdstdir && isflag(argflags_l, ARG_d)) {
		if (match_type == MATCH_REGEX) fixup_regex_pattern(&sdstdir, 0);
		if (!match_pattern(sdstdir, dstdir)) return 0;
	}

	/* Parse source user specification part */
	s = d = match_srcspec; t = NULL; x = 0;
	while ((s = acs_strtok_r(d, ":", &t))) {
		if (d) d = NULL;
		switch (x) {
			case 0: /* srcusr */
				if (!strncmp(s, srcusr, LN_SIZEOF(match_srcspec))
				|| !strcmp(s, ACS_ANYUSR)) ret = 1;
				else return 0;
				break;
			case 1: /* srcgrp */
				if (!strncmp(s, srcgrp, LN_SIZEOF(match_srcspec))
				|| !strcmp(s, ACS_ANYUSR)) ret = 1;
				else return 0;
				break;
			case 2: /* srcgrps,... */
				if (!strncmp(s, srcgrps, LN_SIZEOF(match_srcspec))
				|| !strcmp(s, ACS_ANYUSR)) ret = 1;
				else if (acs_strnchr(s, '*', LN_SIZEOF(s))
				&& match_pattern_type(s, srcgrps, MATCH_FNMATCH)) ret = 1;
				else if (acs_strnchr(s, '+', LN_SIZEOF(s))) {
					char *S, *D, *T;
					char *SS, *DD, *TT;
					int XX, YY;

					S = D = s; T = NULL; XX = YY = 0;
					while ((S = acs_strtok_r(D, ",", &T))) {
						if (D) D = NULL;

						acs_asprintf(&match_tmp, "%s", srcgrps);
						SS = DD = match_tmp;
						while ((SS = acs_strtok_r(DD, ",", &TT))) {
							if (DD) DD = NULL;

							if (!strncmp(S+1, SS, ACS_ALLOC_MAX))
								YY++;
						}

						XX++;
					}

					if (XX && XX == YY) ret = 1;
					else return 0;
				}
				else return 0;
				break;
		}
		x++;
	}

	/* Parse destination user specification part */
	if (!strcmp(match_dstspec, ":") || !strcmp(match_dstspec, "::")) {
		setflag(&ret, M_DANYUSR);
		goto _cmd;
	}
	s = d = match_dstspec; t = NULL; x = 0;
	while ((s = acs_strtok_r(d, ":", &t))) {
		if (d) d = NULL;
		switch (x) {
			case 0: /* dstusr,dsteusr */
				if (!strcmp(s, ACS_ANYUSR)
				|| !strcmp(s, ACS_ANYUSR "," ACS_ANYUSR)) {
					setflag(&ret, M_DANYUSR);
					break;
				}
				tp = dstusr;
				/* "<same>,<same>" */
				if (!strcmp(s, ACS_SAMEUSR)
				|| !strcmp(s, ACS_SAMEUSR "," ACS_SAMEUSR)) {
					if (!strncmp(srcusr, dstusr, ACS_ALLOC_MAX)
					&& !strncmp(srcusr, dsteusr, ACS_ALLOC_MAX)) {
						acs_asprintf(&match_tmp, "%s", s);
						tp = match_tmp;
					}
				}
				if (strncmp(dstusr, dsteusr, ACS_ALLOC_MAX) != 0) {
					/* I have single name in config, but
					   invoker requests seteuid - deny request */
					if (!acs_strnchr(s, ',', LN_SIZEOF(s))) return 0;
					/* "<same>,dsteusr" */
					if (acs_strnstr(s, ACS_SAMEUSR ",", LN_SIZEOF(s))) {
						if (!strncmp(srcusr, dstusr, ACS_ALLOC_MAX)) {
							acs_asprintf(&match_tmp,
							ACS_SAMEUSR ",%s", dsteusr);
						}
					}
					/* "dstusr,<same>" */
					else if (acs_strnstr(s, "," ACS_SAMEUSR, LN_SIZEOF(s))) {
						if (!strncmp(srcusr, dsteusr, ACS_ALLOC_MAX)) {
							acs_asprintf(&match_tmp,
							"%s," ACS_SAMEUSR, dstusr);
						}
					}
					/* "dstusr,*" */
					else if (acs_strnstr(s, "," ACS_ANYUSR, LN_SIZEOF(s))) {
						acs_asprintf(&match_tmp,
						"%s," ACS_ANYUSR, dstusr);
					}
					/* "*,dsteusr" */
					else if (!strncmp(s, ACS_ANYUSR ",",
					CSTR_SZ(ACS_ANYUSR ","))) {
						acs_asprintf(&match_tmp,
						ACS_ANYUSR ",%s", dsteusr);
					}
					/* "dstusr,dsteusr" */
					else acs_asprintf(&match_tmp,
						"%s,%s", dstusr, dsteusr);
					tp = match_tmp;
				}
				if (!strncmp(s, tp, LN_SIZEOF(match_dstspec)))
					setflag(&ret, M_DUSR);
				else return 0;
				break;
			case 1: /* dstgrp,dstegrp */
				if (!strcmp(s, ACS_ANYUSR) || !strcmp(s, ACS_ANYUSR "," ACS_ANYUSR)) {
					setflag(&ret, M_DANYGRP);
					break;
				}
				tp = dstgrp;
				if (!strcmp(s, ACS_SAMEUSR)
				|| !strcmp(s, ACS_SAMEUSR "," ACS_SAMEUSR)) {
					if (!strncmp(srcgrp, dstgrp, ACS_ALLOC_MAX)
					&& !strncmp(srcgrp, dstegrp, ACS_ALLOC_MAX)) {
						acs_asprintf(&match_tmp, "%s", s);
						tp = match_tmp;
					}
				}
				if (strncmp(dstgrp, dstegrp, ACS_ALLOC_MAX) != 0) {
					if (!acs_strnchr(s, ',', LN_SIZEOF(s))) return 0;
					if (acs_strnstr(s, ACS_SAMEUSR ",", LN_SIZEOF(s))) {
						if (!strncmp(srcgrp, dstgrp, ACS_ALLOC_MAX)) {
							acs_asprintf(&match_tmp,
							ACS_SAMEUSR ",%s", dstegrp);
						}
					}
					else if (acs_strnstr(s, "," ACS_SAMEUSR, LN_SIZEOF(s))) {
						if (!strncmp(srcgrp, dstegrp, ACS_ALLOC_MAX)) {
							acs_asprintf(&match_tmp,
							"%s," ACS_SAMEUSR, dstgrp);
						}
					}
					else if (acs_strnstr(s, "," ACS_ANYUSR, LN_SIZEOF(s))) {
						acs_asprintf(&match_tmp,
						"%s," ACS_ANYUSR, dstgrp);
					}
					else if (!strncmp(s, ACS_ANYUSR ",",
					CSTR_SZ(ACS_ANYUSR ","))) {
						acs_asprintf(&match_tmp,
						ACS_ANYUSR ",%s", dstegrp);
					}
					else acs_asprintf(&match_tmp,
						"%s,%s", dstgrp, dstegrp);
					tp = match_tmp;
				}
				if (!strncmp(s, tp, LN_SIZEOF(match_dstspec)))
					setflag(&ret, M_DGRP);
				else return 0;
				break;
			case 2: /* dstgrps,... */
				if (!strcmp(s, ACS_ANYUSR)) setflag(&ret, M_DANYGPS);
				else if (!strncmp(s, dstgrps, LN_SIZEOF(match_dstspec)))
					setflag(&ret, M_DGPS);
				else return 0;
				break;
		}
		x++;
	}

	if (isflag(ret, M_DANYUSR)
	&& !isflag(ret, M_DUSR)
	&& !isflag(suflags_l, FLG_USRONLY)) goto _cmd;

	/* if "usronly", then restrict user only to specifying target user */
	if (isflag(suflags_l, FLG_USRONLY)) {
		unsetflag(&ret, M_DGRP);
		unsetflag(&ret, M_DANYGRP);
		unsetflag(&ret, M_DGPS);
		unsetflag(&ret, M_DANYGPS);
	}

	if (!isflag(ret, M_DGRP) && !isflag(ret, M_DANYGRP)) {
		tgid = gidbyuid(dstuid);
		if (tgid == NOGID) tgid = (gid_t)dstuid;
		if (tgid != dstgid) return 0;
		if (tgid != dstegid) return 0;
	}
	if (!isflag(ret, M_DGPS) && !isflag(ret, M_DANYGPS)) {
		tgsz = 1;
		tgids = acs_malloc(sizeof(gid_t));
		if (getugroups(dstusr, dstgid, tgids, &tgsz) == -1) {
			tgids = acs_realloc(tgids, tgsz * sizeof(gid_t));
			if (getugroups(dstusr, dstgid, tgids, &tgsz) == -1)
				xerror("%s", dstusr);
		}

		if (tgsz != dstgsz) {
			pfree(tgids);
			return 0;
		}
		for (x = 0; x < tgsz; x++) {
			if (tgids[x] != dstgids[x]) {
				pfree(tgids);
				return 0;
			}
		}
		pfree(tgids);
	}

_cmd:
	if (ret) ret = 1;
	/* Finally, check command line */
	if (!strcmp(match_cmdpat, ACS_ANYCMD)) goto _ret;

	parse_escapes(match_cmdpat, LN_SIZEOF(match_cmdpat));

	/* parse cmdpat for possible format templates */
	if (!is_fmtstr(match_cmdpat)) goto _skipthis;

	preset_fsa_full(&fsa, &nr_fsa);

	acs_memzero(&fst, sizeof(struct fmtstr_state));
	fst.args = fsa;
	fst.nargs = nr_fsa;
	fst.fmt = match_cmdpat;
	fst.result = match_tmp;
	fst.result_sz = acs_szalloc(match_tmp);

	parse_fmtstr(&fst);
	pfree(fsa);

	if (fst.trunc) return 0;

	if (fst.nr_parsed) {
		acs_strlcpy(match_cmdpat, match_tmp, LN_SIZEOF(match_cmdpat));
		a = acs_strnlen(match_tmp, ACS_ALLOC_MAX)+1;
		b = match_cmdpat-ln;
		trigline = acs_realloc(trigline, a+b);
		s = trigline+b;
		acs_strlcpy(s, match_tmp, a);
	}

_skipthis:
	s = get_spath();
	a = acs_szalloc(match_spath);
	b = acs_szalloc(s);
	if (a < b) {
		match_spath = acs_realloc(match_spath, b);
		a = b;
	}
	acs_strlcpy(match_spath, s, a);

	if (match_type == MATCH_REGEX) fixup_regex_pattern(&match_cmdpat, LN_SIZEOF(match_cmdpat));

	x = is_abs_rel(execname);
	if (x) { /* match by absolute/relative path */
		s = (isflag(argflags_l, ARG_D) && !isflag(argflags_l, ARG_d)) ? dstusrdir : dstdir;
		if (x == PATH_RELATIVE) acs_asprintf(&match_tmp, "%s/%s", s, cmdline); /* relative to dst(usr)dir */
		else acs_asprintf(&match_tmp, "%s", cmdline); /* absolute */
		if (match_pattern(match_cmdpat, match_tmp)) {
			if (x == PATH_RELATIVE) {
				pfree(matched_dir);
				matched_dir = acs_strdup(s);
				refind_exec = 1;
			}
			goto _ret;
		}
		/* workaround fnmatch("/bin/id *", "/bin/id") nonmatches */
		if (match_type == MATCH_FNMATCH) {
			if (x == PATH_RELATIVE) acs_asprintf(&match_tmp, "%s/%s ", s, cmdline);
			else acs_asprintf(&match_tmp, "%s ", cmdline);
			if (match_pattern(match_cmdpat, match_tmp)) {
				if (x == PATH_RELATIVE) {
					pfree(matched_dir);
					matched_dir = acs_strdup(s);
					refind_exec = 1;
				}
				goto _ret;
			}
		}
		return 0;
	}
	else { /* match by safe path */
		s = d = match_spath; t = NULL;
		while ((s = acs_strtok_r(d, ":", &t))) {
			if (d) d = NULL;
			acs_asprintf(&match_tmp, "%s/%s", s, cmdline);
			if (match_pattern(match_cmdpat, match_tmp)) {
				pfree(matched_dir);
				matched_dir = acs_strdup(s);
				goto _ret;
			}
			if (match_type == MATCH_FNMATCH) {
				acs_asprintf(&match_tmp, "%s/%s ", s, cmdline);
				if (match_pattern(match_cmdpat, match_tmp)) {
					pfree(matched_dir);
					matched_dir = acs_strdup(s);
					goto _ret;
				}
			}
		}
		return 0;
	}

_ret:
	/* Flags are stored only with successfull auth */
	suflags = suflags_l; argflags = argflags_l; notargflags = notargflags_l;
	return ret;
}