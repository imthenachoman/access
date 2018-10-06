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

#ifndef _ACCESS_PORT_H
#define _ACCESS_PORT_H

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#ifdef HAVE_SETRESID
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#ifdef WITH_DACCESS_PROG
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef ACS_NEED_RANDOM
#define ACS_NEED_RANDOM
#endif
#endif

#ifdef WITH_ACSMKPWD_PROG
#ifndef ACS_NEED_RANDOM
#define ACS_NEED_RANDOM
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#ifdef SHADOW_SUPPORT
#include <shadow.h>
#endif
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <libgen.h>
#include <signal.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#ifdef _POSIX_MEMLOCK
#include <sys/mman.h>
#endif
#ifdef SYSLOG_SUPPORT
#include <syslog.h>
#endif
#ifdef WITH_REGEX
#include <regex.h>
#endif
#ifdef WITH_PORTS
#include <wchar.h>
#endif
#ifdef WITH_DACCESS_PROG
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#endif

typedef void (*sighandler_t)(int);

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

#ifdef HAVE_UNIX_CRYPT
extern char *crypt(const char *, const char *);
#endif

/* port_*.c files - mini library */

size_t acs_strlcpy_real(char *dst, const char *src, size_t size);
void *acs_memmem(const void *hs, size_t hsn, const void *ne, size_t nen);
extern char *acs_optarg;
extern int acs_optind, acs_opterr, acs_optopt;
int acs_getopt(int argc, char * const argv[], const char *optstring);
int acs_mbtowc(wchar_t *wc, const char *src, size_t n);
void acs_cfmakeraw(struct termios *t);
char *acs_strtok_r(char *s, const char *sep, char **p);
long long acs_atoll(const char *s);
char *acs_basename(char *s);

#endif /* _ACCESS_PORT_H */
