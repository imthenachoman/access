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

#ifndef _ACCESS_H
#define _ACCESS_H

#define PROGRAM_NAME "access"

#include "config.h"

#define DEFAULT_FLAGS "pw,log,logfail,clearenv,nonumid,noopt_a,noopt_A,noopt_C,noopt_d,noopt_e,noopt_L,noopt_Q,noopt_P,noopt_W"
#define PASSWORD_PROMPT "Password:"
#define DENY_MSG "Permission denied."
#define DELAY_WRPASS 1000000
#define DEFAULT_UMASK 0022

#define ACS_CPPNSTR(x) #x
#define CPPNSTR(x) ACS_CPPNSTR(x)

#define STAT_ARRAY_SZ(x) (sizeof(x)/sizeof(*x))
#define DYN_ARRAY_SZ(x) (acs_szalloc(x)/sizeof(*x))

#define CSTR_SZ(x) (sizeof(x)-1)

#define ACS_ANYUSR "*"
#define ACS_ANYCMD "<all>"
#define ACS_SAMEUSR "<same>"

#define ACS_MEMPOOL_MAX 392960 /* local memory pool size */
#define ACS_XSALLOC_MAX 131072 /* maximum possible memory to get */

#define ACS_ALLOC_MAX 8192 /* ACS_XSALLOC_MAX / 16 */
#define ACS_ALLOC_SMALL 512 /* for small objects */
#define ACS_ALLOC_BUMPER 256
#define ACS_PASSWD_MAX 256
#define ACS_CMDLINE_MAX ACS_ALLOC_MAX

#define FLG_PW 1
#define FLG_LOG 2
#define FLG_TTY 4
#define FLG_DSTPW 8
#define FLG_SUPW 16
#ifdef SYSLOG_SUPPORT
#define FLG_SYSLOG 32 /* use syslog instead of file */
#endif
#define FLG_LOGFAIL 64 /* even if nolog, failed attempts still logged */
#define FLG_FALSE 128 /* This flag will force fail status */
#define FLG_TTYDETACH 256 /* securely detach tty */
/* 512 */
#define FLG_CLRENV 1024 /* reset to minimal environment */
#define FLG_KEEPENV 2048 /* try to preserve pristine environment */
#define FLG_NOEUID 4096
#define FLG_NOEGID 8192
#define FLG_USRONLY 0x4000 /* allow to specify only real target user */
/* 0x8000 */
/* 0x10000 */
/* 0x20000 */
#define FLG_NOLOCK 0x40000 /* don't create and test lockfiles */
#define FLG_WARNUSR 0x80000 /* warn user and show command line to be execute */
#define FLG_NONUMID 0x100000 /* do not permit raw uid numbers usage */
/* 0x200000 */
#define FLG_PWINVALOPT 0x400000 /* ask for password on banned cmdline option */

#define ARG_e 1 /* -e option used */
#define ARG_S 2 /* -S */
#define ARG_l 4 /* -l */
#define ARG_I 8 /* -I */
#define ARG_a 16 /* -a */
#define ARG_A 32 /* -A */
#define ARG_P 64 /* -P */
#define ARG_D 128 /* -D */
#define ARG_b 256 /* -b */
#define ARG_B 512 /* -B */
#define ARG_x 1024 /* -x */
#define ARG_n 2048 /* -n */
#define ARG_F 4096 /* -F */
#define ARG_C 8192 /* -C */
#define ARG_d 0x4000 /* -d */
#define ARG_E 0x8000 /* -E */
#define ARG_X 0x10000 /* -X */
#define ARG_y 0x20000 /* -y */
#define ARG_L 0x40000 /* -L */
#ifdef HAVE_SETPRIORITY
#define ARG_Q 0x80000 /* -Q */
#endif
#define ARG_p 0x100000 /* -p */
#define ARG_v 0x200000 /* -v */
#define ARG_w 0x400000 /* -w */
#define ARG_N 0x800000 /* -N */
#define ARG_W 0x1000000 /* -W */

/* for flags that go into print_userinfos */
#define UARG_u 1
#define UARG_g 2

#define M_DUSR 2 /* Is dst user def & matched? */
#define M_DGRP 4 /* dst group? */
#define M_DGPS 8 /* dst groups? */
#define M_DANYUSR 16 /* any dst user? */
#define M_DANYGRP 32 /* any dst group? */
#define M_DANYGPS 64 /* any dst groups? */

#include "port.h"

typedef unsigned long flagtype;

struct usermap {
	char *user;
	char *hash;
	uid_t uid;
	gid_t gid;
	/* gecos unused */
	char *udir;
	char *shell;
};

#define NOUID ((uid_t)-1)
#define NOGID ((gid_t)-1)

#define NOSIZE ((size_t)-1)

extern char **environ;

extern char *progname;

extern time_t curr_time;
extern char *curr_date;
extern char *curr_secs;

extern int fullinfo;

extern pid_t ourpid, parentpid;
extern char *timefmt, *logfmt;
extern flagtype suflags, argflags, notargflags;
extern char *execname;
extern char *spath, *supath, *logpath;
extern char *prompt, *denymsg;
extern char *trigline, *trigflags;
extern char *execfpath, *execpath, *hashbang, *renamed_first_arg;
extern uint64_t delay;
extern int minfd, maxfd;
extern int passwdfd;
extern mode_t dumask;
extern char *lockpath;
extern char *lockfile;

struct tty_info {
	char *ttyname;

	int fd;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	struct termios ttyconf;
};

extern struct tty_info ttyinfo;

extern int arg_x_cnt;
#ifdef _ACCESS_VERSION
extern int arg_V_cnt;
#endif

extern struct usermap *usermaps;

#define EVC_KEEP_SET		1
#define EVC_CONF_SET		2
#define EVC_CONF_UNSET		3
#define EVC_OPTE_SET		4
#define EVC_OPTE_UNSET		5

struct envvar {
	char *name;
	char *value;
	flagtype class; /* single EVC_* class */
};

extern struct envvar *envvars;

struct def_envvar_list {
	char *pattern;
	int enabled;
};

extern struct def_envvar_list trusted_envvars[];
extern size_t trusted_envvars_sz;
extern struct def_envvar_list scary_envvars[];
extern size_t scary_envvars_sz;

extern char **rlimspec_list;
extern int prsvrlims_fail;

extern char **setvars;

extern uid_t srcuid, dstuid, dsteuid;
extern gid_t srcgid, dstgid, dstegid;
extern gid_t *srcgids, *dstgids;
extern int srcgsz, dstgsz;
extern char *srcusr, *srcgrp, *dstusr, *dstgrp;
extern char *dsteusr, *dstegrp;
extern char *srcgrps, *srcgidss, *dstgrps, *dstfgrps, *dstgidss;
extern char *suusr;
extern char *cmdline, *bcmdline, *bfullargv;
extern char *buserenv, *benviron;
extern char *scwd, *cwd;
extern char *sdstdir, *dstdir, *dstusrdir;
extern char *dstusrshell;
extern char *schrootdir, *chrootdir;
extern char *linepw;
extern char *blamecmd;
extern char *pwaskcmd;
extern char *auditcmd, *auditspath;
extern pid_t auditpid;
extern int auditret, auditreturn;
extern int extern_prog_running;
extern char *fromtty;
extern char *custom_blame_str;
#ifdef HAVE_SETPRIORITY
#define PRIO_INVALID 10000
extern int taskprio_arg, taskprio_conf;
#endif

#define MATCH_REGEX 3
#define MATCH_FNMATCH 2
#define MATCH_STRCMP 1

extern int match_type;

extern flagtype auth;
extern int noblame;

extern char *errstr;
extern char default_shell[];
extern char default_root[];

extern int nocommands;

extern int getp_flags;

/* All our functions */

/* argv.c */

void refine_argv(int *argc, char ***argv, int idx);
void destroy_argv(char ***argv);

/* base64.c */

size_t base64_decode(char *output, size_t outputl, const char *input, size_t inputl);
size_t base64_encode(char *output, const char *input, size_t inputl);

/* cmdline.c */

#define PATH_ABSOLUTE 1
#define PATH_RELATIVE 2

char *build_cmdline(int argc, char **argv);
char *build_protected_cmdline(int argc, char **argv);
char **parse_cmdline(char *p);
int is_exec(const char *path);
char *which(const char *spathspec, const char *progname, const char *root);
char *find_access(const char *name);

/* conf.c */

char *get_cur_conf_name(void);
int get_cur_conf_lnum(void);
int *pget_cur_conf_lnum(void);
int free_conf(void);
void free_conf_all(void);
char *get_conf_line(void);
int open_conf(const char *path);
void resolve_flags(const char *sflags, int single, flagtype *suflags_p, flagtype *argflags_p, flagtype *notargflags_p);
void readin_usermaps(void);
void readin_default_settings(void);
void set_variable(const char *spec, int init);
void unset_variable(const char *name);
void update_vars(void);
#ifdef WITH_DACCESS_PROG
char *parse_client_conf(void);
#endif

/* confdata.c */

int is_comment(const char *s);
void *load_config(int fd);
char *get_config_line(void *config);
int *config_current_line_number(void *config);
void reset_config(void *config);
void free_config(void *config);

/* crypt.c */

char *acs_crypt_r(const char *clear, const char *salt, char *output);
char *acs_crypt(const char *key, const char *salt);

/* date.c */

void init_datetime(void);
void update_datetime(void);

/* dir.c */

#define PATH_IS_FILE 1
#define PATH_IS_DIR  2

int acs_chdir(const char *s, int noexit);
char *acs_getcwd(void);
char *acs_realpath(const char *path);
int file_or_dir(const char *path);
int is_abs_rel(const char *progname);
char **read_match_dir(const char *pattern);
void free_match_dir(char **r);

/* daccess.c */

int daccess_main(int argc, char **argv, uid_t srcuid, gid_t srcgid, int srcgsz, gid_t *srcgids);

/* env.c */

#define APPEND_FSA(pfsa, pnr_fsa, sp, sz, sfmt, vdata)					\
	do {										\
		pfsa = acs_realloc(pfsa, (pnr_fsa+1) * sizeof(struct fmtstr_args));	\
		pfsa[pnr_fsa].spec = sp;						\
		pfsa[pnr_fsa].size = sz;						\
		pfsa[pnr_fsa].fmt = sfmt;						\
		pfsa[pnr_fsa].data = vdata;						\
		pnr_fsa++;								\
	} while (0)

struct fmtstr_args;

void acs_setenv(const char *name, const char *value, int overwrite);
void acs_unsetenv(const char *name);
void clear_environ(void);
int is_envvar_exists(const char *name, flagtype class);
void add_envvar(const char *name, const char *value, flagtype class);
void delete_envvars(const char *dname, flagtype class, int match_wildcards);
void add_envvar_pair(const char *spec, flagtype class);
int is_scary_envvar(const char *spec);
void kill_scary_envvars(int suser);
int builtin_envvar_enable(struct def_envvar_list *el, size_t elsz, const char *pattern, int state);
void set_user_environ(void);
void fsa_add_uservars(struct fmtstr_args **fsa, size_t *nr_fsa);
void preset_fsa_basic(struct fmtstr_args **fsa, size_t *nr_fsa);
void preset_fsa_full(struct fmtstr_args **fsa, size_t *nr_fsa);

/* error.c */

void acs_exit(int status);
void set_progname(const char *name);
void xerror(const char *f, ...);
void xerror_status(int status, const char *f, ...);
void xexits(const char *f, ...);
void xexits_status(int status, const char *f, ...);
void acs_perror(const char *f, ...);
void seterr(const char *f, ...);
void reseterr(void);
char *acs_strerror(int err);

/* exec.c */

int forkexec(int vp, const char *path, char *const argv[], char *const envp[], pid_t *svpid, int *pfd, char *auditrsn, size_t pmsgl);
int dexecve(const char *file, char *const argv[], pid_t *pid);
int execute(const char *p, char *const argv[], pid_t *bgpid);

/* flags.c */

int isflag(flagtype flags, flagtype flag);
void setflag(flagtype *flags, flagtype flag);
void unsetflag(flagtype *flags, flagtype flag);

/* getpasswd.c */

#define GETP_NOECHO 1
#define GETP_NOINTERP 2
#define GETP_WAITFILL 4

struct getpasswd_state;

typedef int (*getpasswd_filt)(struct getpasswd_state *, char, size_t);

struct getpasswd_state {
	char *passwd;
	size_t pwlen;
	const char *echo;
	char maskchar;
	getpasswd_filt charfilter;
	int fd;
	int efd;
	int error;
	struct termios *sanetty;
	int flags;
	size_t retn;
};

size_t acs_getpasswd(struct getpasswd_state *getps);

/* lockfile.c */

int create_lockfile(void);
void release_lockfile(void);

/* log.c */

int write_log_line(const char *blamestr);

/* match.c */

int match_pattern_type(const char *pattern, const char *string, int type);
int match_pattern(const char *pattern, const char *string);
const char *get_match_type(int type);
int get_match_type_byname(const char *s);
flagtype execute_rule_match(void);

/* memory.c */

void access_init_memory(void);
void access_free_memory(int allmem);
void access_exit_memory(void);
int memtest(void *p, size_t l, int c);
void acs_memzero(void *p, size_t l);
void mark_ptr_in_use(void *ptr);
void *acs_malloc(size_t n);
void *acs_malloc_real(size_t n);
void *acs_realloc(void *p, size_t n);
void *acs_realloc_real(void *p, size_t n);
void acs_free(void *p);
#define pfree(p) do { acs_free(p); p = NULL; } while (0)
size_t acs_szalloc(const void *p);

/* pfx.c */

long atol_prefixed(const char *s);

/* pwdb.c */

uid_t uidbyname(const char *name);
gid_t gidbyuid(uid_t uid);
gid_t gidbyname(const char *name);
int getugroups(const char *name, gid_t gr, gid_t *grps, int *ngrps);
char *shellbyname(const char *name);
char *udirbyname(const char *name);
char *namebyuid(uid_t uid);
char *namebygid(gid_t gid);
char *build_usergroups(int size, gid_t *list, int forid, int do_numeric);
int match_password(const char *user, const char *secret);
int is_numbergrps(const char *sgrps);

/* random.c */

void access_getrandom(void *vbuf, size_t size);
unsigned acs_randrange(unsigned s, unsigned d);
char *make_random_salt(void);

/* rlimit.c */

void add_rlimspec(const char *rlimspec);
void remove_rlimspec(const char *rlimspec);
int apply_rlimspec(const char *rlimspec);
void process_rlimits(void);
#ifdef WITH_RESETRLIMITS
void preserve_user_limits(void);
void reset_user_limits(void);
void restore_user_limits(void);
#endif

/* say.c */

void acs_vfsay(FILE *where, int addnl, const char *fmt, va_list ap);
void acs_nvesay(const char *fmt, va_list ap);
void acs_nvsay(const char *fmt, va_list ap);
void acs_nesay(const char *fmt, ...);
void acs_nsay(const char *fmt, ...);
void acs_esay(const char *fmt, ...);
void acs_say(const char *fmt, ...);

/* secure.c */

int is_super_user(void);
int needs_super_user(void);
int is_setuid(void);
char *get_spath(void);
int cfg_permission(const struct stat *st, int dir);
void blame(const char *f, ...);
void close_fd_range(int startfd, int endfd);
int runaway(void);
void ttydetach(void);
int grab_tty(struct tty_info *ttyi);
int put_tty(struct tty_info *ttyi);
int block_tty(const struct tty_info *ttyi, int block);
void warnusr(void);
#ifdef _POSIX_MEMLOCK
int lockpages(void);
#endif
void find_new_exec(const char *spathspec, const char *progname, const char *chroot);

/* signal.c */

void segv_handler(int n);
void install_signals(sighandler_t handler);

/* acsmatch.c */

int acsmatch_main(int argc, char **argv, uid_t srcuid, gid_t srcgid, int srcgsz, gid_t *srcgids);

/* acsmkpwd.c */

int acsmkpwd_main(int argc, char **argv, uid_t srcuid, gid_t srcgid, int srcgsz, gid_t *srcgids);

/* acstestauth.c */

int acstestauth_main(int argc, char **argv, uid_t srcuid, gid_t srcgid, int srcgsz, gid_t *srcgids);

/* str.c */

struct fmtstr_args {
	char *spec;
	size_t size;
	char *fmt;
	void *data;
};

struct fmtstr_state {
	struct fmtstr_args *args;
	int nargs;
	const char *fmt;
	char *result;
	size_t result_sz;
	int nr_parsed;
	short trunc;
};

#define newline_to_nul(s, l) char_to_nul(s, l, '\n')
char *acs_strndup(const char *s, size_t n);
size_t char_to_nul(char *s, size_t l, char c);
int acs_snprintf(char *s, size_t n, const char *fmt, ...);
int acs_vsnprintf(char *s, size_t n, const char *fmt, va_list ap);
int acs_vasprintf(char **s, const char *fmt, va_list ap);
int acs_asprintf(char **s, const char *fmt, ...);
size_t acs_strlcpy(char *d, const char *s, size_t n);
size_t acs_strnlen(const char *s, size_t n);
size_t acs_fgets(char *s, size_t n, FILE *f);
char *acs_strdup(const char *s);
char *acs_strnstr(const char *hs, const char *ne, size_t hsn);
char *acs_strstr(const char *hs, const char *ne);
char *acs_strnchr(const char *s, char c, size_t n);
char *acs_strchr(const char *s, char c);
int is_fmtstr(const char *s);
void parse_escapes(char *str, size_t n);
char *parse_fmtstr(struct fmtstr_state *state);
int str_empty(const char *str);
size_t shrink_dynstr(char **s);
void acs_astrcat(char **d, const char *s);
char *preset_parse_fmtstr(const char *fmts);
size_t remove_chars(char *str, size_t max, const char *rm);

/* strrep.c */

size_t acs_strltrep(char *str, size_t n, int *nr_reps, const char *from, const char *to);
size_t acs_strlrep(char *str, size_t n, const char *from, const char *to);

/* su.c */

int su_main(int argc, char **argv, uid_t srcuid, gid_t srcgid, int srcgsz, gid_t *srcgids);

/* test.c */

#define YESNO_YES 2
#define YESNO_NO  1
#define YESNO_UND 0
#define YESNO_ERR -1

int is_number(const char *s, int sign);
int yes_or_no(const char *s);
int acs_isxdigit(char c);

/* tty.c */

void tty_init(void);
int fdgetstring(int fd, char *s, size_t n);
char *acs_ttyname(int fd);
int is_path_tty(const char *tty_name);

/* usage.c */

void usage(void);
void usage_long(void);
void print_uidinfos(char *c_opt_str, int pui_flags);
#ifdef _ACCESS_VERSION
void print_builtin_defs(void);
void show_version(void);
#endif

/* usermap.c */

char *usermap_gethash(const char *user);
uid_t usermap_getuid(const char *user);
gid_t usermap_getgid(const char *user);
char *usermap_getudir(const char *user);
char *usermap_getushell(const char *user);
char *usermap_getnamebyuid(uid_t uid);
gid_t usermap_getgidbyuid(uid_t uid);

#endif /* _ACCESS_H */
