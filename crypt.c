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
#ifdef WITH_SKEIN_CRYPT
#include "tf1024.h"

#define SALTLEN 16
#define DATALEN 48
#define OFFSET 11
#define PASSES 22005

#define SALTLEN_MAX 32
#define DATALEN_MAX 175
#define HASHLEN_MAX (DATALEN_MAX + SALTLEN_MAX + 4 + 1)
#define OFFSET_MAX 64
#define PASSES_MAX (2 << 24)
#define SK_U_PFX "$U$"
#define SK1024_CONF "/etc/skcrypt.conf"

unsigned int sk_saltlen = SALTLEN;
unsigned int sk_datalen = DATALEN;
unsigned int sk_offset = OFFSET;
unsigned int sk_passes = PASSES;
char sk_localid[64];

int skein_configured;

int read_skein_config(void)
{
	FILE *f;
	char data[256];
	char *s, *d;

	if (skein_configured) return 1;

	f = fopen(SK1024_CONF, "r");
	if (!f) return 0;

	s = data;
	while (fgets(data, 256, f)) {
		if (data[0] == '\n' || data[0] == '#') continue;
		data[acs_strnlen(data, 256)-1] = '\0';

		d = acs_strchr(s, '=');
		if (!d) continue;

		/* old config support, strip trailing space of option */
		if (d-s && *(d-1) == ' ') *(d-1) = '\0';
		/* old config support, strip leading space of argument */
_aga:		*d = '\0'; d++;
		if (*d == ' ') goto _aga;

		if (!strcmp(s, "passes"))
			sk_passes = atoi(d);
		else if (!strcmp(s, "offset"))
			sk_offset = atoi(d);
		else if (!strcmp(s, "localid"))
			acs_strlcpy(sk_localid, d, sizeof(sk_localid));
		else if (!strcmp(s, "slen") || !strcmp(s, "saltlen"))
			sk_saltlen = atoi(d);
		else if (!strcmp(s, "dlen") || !strcmp(s, "datalen"))
			sk_datalen = atoi(d);
	}

	fclose(f);

	if (sk_passes == 0 || sk_passes >= PASSES_MAX)
		sk_passes = PASSES;

	if (sk_offset == 0 || sk_offset >= OFFSET_MAX)
		sk_offset = OFFSET;

	if (sk_saltlen == 0 || sk_saltlen >= SALTLEN_MAX)
		sk_saltlen = SALTLEN;

	if (sk_datalen == 0 || sk_datalen >= DATALEN_MAX)
		sk_datalen = DATALEN;

	return 1;
}

char *acs_crypt_r(const char *clear, const char *salt, char *output)
{
	unsigned char hashbytes[TF_KEY_SIZE];
	char b64[sizeof(hashbytes)*2];
	char slt[SALTLEN_MAX];
	int slen = 0, b64l, x;
	char *p = output;

	if (!read_skein_config()
	&& !is_super_user())
		goto _fail; /* do not lie with false hash */

	/* Process salt */
	if (salt[0] == SK_U_PFX[0] && salt[1] == SK_U_PFX[1] && salt[2] == SK_U_PFX[2]) {
		const char *s, *d;
		s = salt+3;
		d = acs_strchr(s, SK_U_PFX[0]);
		if (!d) d = s;
		slen = (d-s) > sk_saltlen ? sk_saltlen : (d-s);
		acs_memzero(slt, sizeof(slt));
		memcpy(slt, s, slen);
	}
	else goto _fail;

	acs_memzero(hashbytes, sizeof(hashbytes));
	/* crypt and convert to base64 */
	b64l = acs_snprintf(b64, sizeof(b64), "%s%s%s", clear, slt, sk_localid);
	sk1024(b64, b64l, hashbytes, TF_MAX_BITS);
	if (sk_passes) {
		for (x = 0; x < sk_passes; x++)
			sk1024(hashbytes, TF_KEY_SIZE, hashbytes, TF_MAX_BITS);
	}

	acs_memzero(b64, sizeof(b64));
	base64_encode(b64, (const char *)hashbytes, sizeof(hashbytes));
	remove_chars(b64, sizeof(b64), "./+=");
	acs_memzero(hashbytes, sizeof(hashbytes));

	memmove(b64, b64+sk_offset, sk_datalen);
	acs_memzero(b64+sk_datalen, sizeof(b64)-sk_datalen);

	/* Return result */
	acs_snprintf(p, 128, SK_U_PFX"%s$%s", slt, b64);

	acs_memzero(b64, sizeof(b64));
	acs_memzero(slt, sizeof(slt));

	goto _ret;

_fail:
	*p = '*'; *(p+1) = '\0';
_ret:
	return p;
}
#endif

/* Our sane crypt() interface to system's crypt(). */
static char *unix_crypt_wrapper(const char *key, const char *salt)
{
	char *r = NULL;

#ifdef HAVE_UNIX_CRYPT
	r = crypt(key, salt);
#endif
/* Okay, following musl's behavior here because it's a wrapper for common crypt(). */
	if (!r) r = (*salt == '*') ? "x" : "*";
	return r;
}

char *acs_crypt(const char *key, const char *salt)
{
#ifdef WITH_SKEIN_CRYPT
	static char p[128];
#endif
	char *r;

#ifdef WITH_SKEIN_CRYPT
	r = acs_crypt_r(key, salt, p);
	if (*p == '*') r = unix_crypt_wrapper(key, salt);
#else
	r = unix_crypt_wrapper(key, salt);
#endif

	return r;
}
