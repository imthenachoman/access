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

#ifndef TF1024_H
#define TF1024_H

/*
 * Config block for tfcrypt's tf1024.
 * Please modify or remove it it for your own
 * needs when porting to other projects.
 */
#define TF_FAST
/* #define TF_NEED_CORE */
/* #define TF_NEED_MODES */
/* #define TF_NEED_DECRYPT */
/* #define TF_NEED_CTR_MODE */
/* #define TF_NEED_CTR_BACKUP */
/* #define TF_NEED_TCTR_MODE */
/* #define TF_NEED_CBC_MODE */
/* Config block end. */

#ifndef htole64
#warning short circuiting missing htole64, check your build tools
#define htole64(x) (x)
#endif

#undef TF_NR_BITS
#define TF_NR_BITS 1024

#undef TF_UNIT_TYPE
#define TF_UNIT_TYPE uint64_t

#undef TF_BYTE_TYPE
#define TF_BYTE_TYPE uint8_t

#undef TF_SWAP_FUNC
#define TF_SWAP_FUNC htole64

#define TF_ARRAY_SZ(x) (sizeof(x)/sizeof(x[0]))

#define TF_SIZE_UNIT (sizeof(TF_UNIT_TYPE)) /* single TF_UNIT_TYPE */
#define TF_NR_UNITS (TF_NR_BITS / TF_SIZE_UNIT / 8) /* totalbits / sizeof(unit) / bytebits */

#define TF_KEY_SIZE (TF_SIZE_UNIT * TF_NR_UNITS) /* byteops - memset, memcpy etc. */

#define TF_BLOCK_SIZE TF_KEY_SIZE /* for byteops - memset, memcpy etc. */
#define TF_BLOCK_UNITS TF_NR_UNITS /* for TF_UNIT_TYPE ops */

#define TF_TO_BITS(x)   ((x) * 8) /* nr. bytes to bits (128 -> 1024) */
#define TF_FROM_BITS(x) ((x) / 8) /* nr. bits to bytes (1024 -> 128) */
#define TF_MAX_BITS TF_NR_BITS /* max. bits supported (128 * 8 == 1024) */
#define TF_UNIT_BITS (TF_SIZE_UNIT * 8) /* number of bits in a single unit */

/* If host is big endian, then do proper conversions. */
static inline void data_to_little(void *p, size_t l)
{
	size_t idx;
	TF_UNIT_TYPE *P = p;
	TF_UNIT_TYPE t;

	for (idx = 0; idx < (l/sizeof(TF_UNIT_TYPE)); idx++) {
		t = TF_SWAP_FUNC(P[idx]);
		P[idx] = t;
	}
}

/* Counter operations: CTR and other similar modes. */
static inline void ctr_inc(TF_UNIT_TYPE *x, size_t l)
{
	size_t i;

	for (i = 0; i < l; i++) {
		x[i] = ((x[i] + (TF_UNIT_TYPE)1) & ((TF_UNIT_TYPE)~0));
		if (x[i]) break;
	}
}

/* This one wants rewrite, but not called much often. */
static inline void ctr_add(TF_UNIT_TYPE *x, const TF_UNIT_TYPE *y, size_t l)
{
	size_t i, f = 0;
	TF_UNIT_TYPE t;

	for (i = 0; i < l; i++) {
		t = x[i];
		x[i] += y[i]; x[i] &= ((TF_UNIT_TYPE)~0);
		if (x[i] < t) {
_again:			f++;
			t = x[f-i];
			x[f-i]++;
			if (x[f-i] < t) goto _again;
			else f = 0;
		}
	}
}

typedef struct {
	TF_UNIT_TYPE K[TF_NR_UNITS+1];
	TF_UNIT_TYPE T[3];
#ifdef TF_NEED_MODES
#ifdef TF_NEED_TCTR_MODE
#ifdef TF_NEED_CTR_BACKUP
	TF_UNIT_TYPE iT[3];
#endif
#endif
#endif
} tfc1024_ctx;

#ifdef TF_NEED_MODES
typedef struct {
	tfc1024_ctx tfc;
#ifdef TF_NEED_CTR_BACKUP
	TF_UNIT_TYPE ictr[TF_NR_UNITS];
#endif
	TF_UNIT_TYPE ctr[TF_NR_UNITS];
} tf1024_ctx;
#endif

typedef struct {
	tfc1024_ctx tfc;
	size_t hl, bl;
	uint8_t B[TF_BLOCK_SIZE];
} sk1024_ctx;

#ifdef TF_NEED_CORE
void tfc1024_init(tfc1024_ctx *ctx);
void tfc1024_done(tfc1024_ctx *ctx);
void tfc1024_set_key(tfc1024_ctx *ctx, const void *key, size_t klen);
void tfc1024_set_tweak(tfc1024_ctx *ctx, const void *tweak);
#endif

void tfc1024_encrypt_blk(tfc1024_ctx *ctx, const TF_UNIT_TYPE *input, TF_UNIT_TYPE *output);
#ifdef TF_NEED_DECRYPT
void tfc1024_decrypt_blk(tfc1024_ctx *ctx, const TF_UNIT_TYPE *input, TF_UNIT_TYPE *output);
#endif


void sk1024_init_key(sk1024_ctx *ctx);
void sk1024_update_key(sk1024_ctx *ctx, const void *key, size_t klen);
void sk1024_final_key(sk1024_ctx *ctx);
void sk1024_init(sk1024_ctx *ctx, size_t bits, int with_key);
void sk1024_update(sk1024_ctx *ctx, const void *msg, size_t l);
void sk1024_final_pad(sk1024_ctx *ctx, void *outhash, short do_pad);
void sk1024_final(sk1024_ctx *ctx, void *outhash);
void sk1024(const void *src, size_t slen, void *dst, size_t bits);

#ifdef TF_NEED_MODES
void tf1024_init(tf1024_ctx *ctx);
void tf1024_done(tf1024_ctx *ctx);
void tf1024_start_counter(tf1024_ctx *ctx, const void *ctr);
void tf1024_rewind_counter(tf1024_ctx *ctx, const void *newctr, size_t ctrsz);
#ifdef TF_NEED_CTR_MODE
void tf1024_crypt(tf1024_ctx *ctx, const void *src, size_t slen, void *dst);
#endif
#ifdef TF_NEED_TCTR_MODE
void tf1024_start_counter_tctr(tfc1024_ctx *ctx, const void *ctr);
void tf1024_rewind_counter_tctr(tfc1024_ctx *ctx, const void *newctr, size_t ctrsz);
void tf1024_tctr_encrypt(tfc1024_ctx *ctx, const void *src, size_t slen, void *dst);
void tf1024_tctr_decrypt(tfc1024_ctx *ctx, const void *src, size_t slen, void *dst);
#endif
#ifdef TF_NEED_CBC_MODE
void tf1024_cbc_encrypt(tf1024_ctx *ctx, const void *src, size_t slen, void *dst);
void tf1024_cbc_decrypt(tf1024_ctx *ctx, const void *src, size_t slen, void *dst);
#endif
#endif

#endif
