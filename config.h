/*
 * access config file.
 *
 * NOTE: all the config variables specified here
 * can be freely overriden from command line.
 * This file provides some usable defaults.
 */

/* location of master config file */
#define PATH_CONF "/etc/access.conf"
/* where to write master log file */
#define PATH_LOG "/var/log/access.log"
/* safe path: only binaries from these directories are run when only name is told */
#define SAFE_PATH "/bin:/sbin:/usr/bin:/usr/sbin"
/* default shell which is started when login with -I */
#define DEFAULT_SHELL "/bin/sh"
/* log line format */
#define DEFAULT_LOG_FORMAT "%{datetime} %{pid} " \
	"%{srcusr}:%{srcgrp}[%{srcgrps}] " \
	"%{dstusr},%{dsteusr}:%{dstgrp},%{dstegrp}[%{dstgrps}] " \
	"CWD=\"%{cwd}\" ROOT=\"%{rootdir}\" DIR=\"%{dstdir}\" TTY=\"%{tty}\" " \
	"EXEC=\"%{execpath}\" ARG0=\"%{firstarg}\" CMD=\"%{cmdline}\""
/* directory to put empty lock files into, to prevent brute force */
#define LOCKFILE_PATH "/var/run/%{srcuid}." PROGRAM_NAME /* format templates are accepted. */
/* comment this if you do not want to include su(1) builtin compatibility program */
#define WITH_SU_PROG
/* include "acsmatch" program: simple pattern to string matcher */
#define WITH_ACSMATCH_PROG
/* include "acsmkpwd" program: generate s_crypt() hashes */
#define WITH_ACSMKPWD_PROG
/* include "acstestauth" program: verify user's passwords */
#define WITH_ACSTESTAUTH_PROG
/* include "daccess" program: daemon to run access if there is no setuid fs support */
/* #define WITH_DACCESS_PROG */
#ifdef WITH_DACCESS_PROG
/* daccess socket path. This can be overriden. */
#define DACCESS_SOCK_PATH "/tmp/daccess"
/*
 * daccess control password. It is not necessary to keep secret,
 * but just to verify client program is daccess too.
 */
#define DACCESS_PASSWORD "Tm8EtJvlUI"
#endif
/* use static storage (automatically enabled if PIE support is enabled) */
/* #define WITH_STATIC_MEMORY */
/* include regex matching */
#define WITH_REGEX
/* #define this if you experience troubles with insane systems like Solaris. */
/* #define WITH_PORTS */
/* Do you have shadow support in your libc or elsewhere? */
#define SHADOW_SUPPORT
/* Do you have syslog support? You probably do. */
#define SYSLOG_SUPPORT
/* Do you have classic Unix crypt(3) function? You probably do. */
#define HAVE_UNIX_CRYPT
/* If not, you can use portable Skein/tf1024 one, shipped with access. */
#define WITH_SKEIN_CRYPT
/* You build for OS X with it's insane setgroups(2) */
/* #define WITH_GROUPSLIMIT */
/* Your system has setres{u,g}id syscall. Modern Unixes have this today. But see NOTTODO. */
#define HAVE_SETRESID
/* setpriority may be unavailable on some platforms. comment this if you have errors with it. */
#define HAVE_SETPRIORITY
/* You build for OpenBSD with true issetugid(2) syscall */
/* #define HAVE_ISSETUGID */
/* Your system is insane or too old, so it even does not have snprintf. */
/* #define HAVE_NO_SNPRINTF */
/* Reset resource limits to safer values, do not trust invoker ones which may lead to crash. */
#define WITH_RESETRLIMITS
