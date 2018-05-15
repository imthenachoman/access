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
#include "smalloc_i.h"

extern void *access_memory_pool;

void acs_memzero(void *p, size_t l)
{
	memset(p, 0, l);
}

int memtest(void *p, size_t l, int c)
{
	char t[64];
	size_t xl = l;

	memset(t, c, sizeof(t));

	if (xl >= sizeof(t)) {
		do {
			if (memcmp(p+(l-xl), t, sizeof(t)) != 0) return 0;
		} while ((xl -= sizeof(t)) >= sizeof(t));
	}

	if (xl) {
		if (memcmp(p+(l-xl), t, xl) != 0) return 0;
	}

	return 1;
}

static char **in_use_list;

static int is_ptr_inuse(const void *ptr)
{
	size_t x, y;

	/* never free in_use_list */
	if (ptr == in_use_list) return 1;
	x = DYN_ARRAY_SZ(in_use_list);

	for (y = 0; y < x; y++) if (in_use_list[y] == ptr) return 1;
	return 0;
}

/* Appeal to SMalloc internals... */
static void do_free_things(int allmem)
{
	struct smalloc_hdr *shdr, *basehdr;
	uintptr_t x;

	/* just try to free a thing if it's hdr has valid tag. */
	shdr = basehdr = smalloc_curr_pool.pool;
	while (CHAR_PTR(shdr)-CHAR_PTR(basehdr) < smalloc_curr_pool.pool_size) {
		x = smalloc_mktag(shdr);
		if (shdr->tag == x) {
			void *uptr = HEADER_TO_USER(shdr);
			/* catch bugs... */
			if (allmem) sm_free(uptr);
			else {
				if (!sm_alloc_valid(uptr)) goto _bad;
				if (!is_ptr_inuse(uptr)) sm_free(uptr);
			}
		}
		shdr++;
	}

	pfree(in_use_list);

	/* after that, pool space MUST BE zeroed out. If not - something is really wrong there. */
	if (allmem && !memtest(smalloc_curr_pool.pool, smalloc_curr_pool.pool_size, 0)) {
_bad:		acs_memzero(access_memory_pool, ACS_MEMPOOL_MAX+ACS_ALLOC_BUMPER);
		access_memory_pool = NULL;
		xexits("memory pool was corrupted!");
	}
}

static size_t access_oom_handler(struct smalloc_pool *spool, size_t failsz)
{
	acs_esay("OOM: failed to allocate %zu bytes!", failsz);
	return 0;
}

static void access_ub_handler(struct smalloc_pool *spool, const void *offender)
{
	xexits("UB: %p is not from our data storage!", offender);
}

static int access_memory_initialised;

void access_init_memory(void)
{
	if (!access_memory_initialised) {
#ifndef WITH_STATIC_MEMORY
		if (!access_memory_pool)
			access_memory_pool = malloc(ACS_MEMPOOL_MAX+ACS_ALLOC_BUMPER); /* never free */
		if (!access_memory_pool) xexits("memory pool initialisation failed!");
#endif
		memset(access_memory_pool+ACS_MEMPOOL_MAX, 'E', ACS_ALLOC_BUMPER);
		sm_set_ub_handler(access_ub_handler);
		if (!sm_set_default_pool(
		access_memory_pool, ACS_MEMPOOL_MAX, 1, access_oom_handler))
			xexits("memory pool initialisation failed!");
		if (ACS_MEMPOOL_MAX-smalloc_curr_pool.pool_size) {
			memset(access_memory_pool+smalloc_curr_pool.pool_size,
			'E', ACS_MEMPOOL_MAX-smalloc_curr_pool.pool_size);
		}
		access_memory_initialised = 1;
	}
}

void mark_ptr_in_use(void *ptr)
{
	size_t x;

	if (!sm_alloc_valid(ptr)) return;

	x = DYN_ARRAY_SZ(in_use_list);
	in_use_list = acs_realloc(in_use_list, (x+1) * sizeof(char *));
	in_use_list[x] = ptr;
}

void access_free_memory(int allmem)
{
	if (!access_memory_pool) return;

	do_free_things(allmem);

	if (memtest(access_memory_pool+ACS_MEMPOOL_MAX, ACS_ALLOC_BUMPER, 'E')) {
		if (ACS_MEMPOOL_MAX-smalloc_curr_pool.pool_size
		&& !memtest(access_memory_pool+smalloc_curr_pool.pool_size,
		ACS_MEMPOOL_MAX-smalloc_curr_pool.pool_size, 'E')) goto _bad;

		return;
	}

_bad:	acs_memzero(access_memory_pool, ACS_MEMPOOL_MAX+ACS_ALLOC_BUMPER);
	access_memory_pool = NULL;
	xexits("memory pool was corrupted!");
}

void access_exit_memory(void)
{
	if (!access_memory_pool) return;

	access_free_memory(1);
	/* will erase memory pool automatically */
	sm_release_default_pool();
	access_memory_initialised = 0;
}

void *acs_malloc(size_t n)
{
	void *r;

	if (!access_memory_initialised) access_init_memory();

	r = sm_malloc(n);
	if (!r) {
		errstr = NULL;
		xerror("acs_malloc");
		return NULL;
	}

	return r;
}

void *acs_malloc_real(size_t n)
{
	if (!access_memory_initialised) access_init_memory();
	return sm_malloc(n);
}

void *acs_realloc(void *p, size_t n)
{
	void *r;

	if (!access_memory_initialised) access_init_memory();

	r = sm_realloc(p, n);
	if (!r && n) {
		errstr = NULL;
		xerror("acs_realloc");
		return NULL;
	}
	else return r;
}

void *acs_realloc_real(void *p, size_t n)
{
	if (!access_memory_initialised) access_init_memory();
	return sm_realloc(p, n);
}

/*
 * just a proxy - do not include smalloc.h somewhere else.
 * and there is a pfree define which resets pointer to NULL.
 */
void acs_free(void *p)
{
	if (!access_memory_initialised) access_init_memory();
	sm_free(p);
}

size_t acs_szalloc(const void *p)
{
	if (!access_memory_initialised) access_init_memory();
	return sm_szalloc(p);
}
