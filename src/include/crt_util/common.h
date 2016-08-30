/**
 * (C) Copyright 2015, 2016 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
 * The Government's rights to use, modify, reproduce, release, perform, display,
 * or disclose this software are subject to the terms of the Apache License as
 * provided in Contract No. B609815.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */

#ifndef __CRT_COMMON_H__
#define __CRT_COMMON_H__

#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <byteswap.h>

#include <crt_api.h>

#define CRT_ENV_DEBUG	"CRT_DEBUG"

/**
 * Debugging flags (32 bits, non-overlapping)
 */
enum {
	CF_UNKNOWN	= (1 << 0),
	CF_VERB_FUNC	= (1 << 1),
	CF_VERB_ALL	= (1 << 2),
	CF_CL		= (1 << 5),
	CF_CL2		= (1 << 6),
	CF_CL3		= (1 << 7),
	CF_PL		= (1 << 8),
	CF_PL2		= (1 << 9),
	CF_PL3		= (1 << 10),
	CF_TP		= (1 << 11),
	CF_VOS1		= (1 << 12),
	CF_VOS2		= (1 << 13),
	CF_VOS3		= (1 << 14),
	CF_SERVER	= (1 << 15),
	CF_MGMT		= (1 << 16),
	CF_DSMC		= (1 << 17),
	CF_DSMS		= (1 << 18),
	CF_SR		= (1 << 19),
	CF_SRC		= (1 << 20),
	CF_SRS		= (1 << 21),
	CF_MISC		= (1 << 30),
	CF_MEM		= (1 << 31),
};

unsigned int crt_debug_mask(void);
void crt_debug_set(unsigned int mask);

#define C_PRINT(fmt, ...)						\
do {									\
	fprintf(stdout, fmt, ## __VA_ARGS__);				\
	fflush(stdout);							\
} while (0)

#define C_DEBUG(mask, fmt, ...)						\
do {									\
	unsigned int __mask = crt_debug_mask();			\
	if (!((__mask & (mask)) & ~(CF_VERB_FUNC | CF_VERB_ALL)))	\
		break;							\
	if (__mask & CF_VERB_ALL) {					\
		fprintf(stdout, "%s:%d:%d:%s() " fmt, __FILE__,		\
			getpid(), __LINE__, __func__, ## __VA_ARGS__);  \
	} else if (__mask & CF_VERB_FUNC) {				\
		fprintf(stdout, "%s() " fmt,				\
			__func__, ## __VA_ARGS__);			\
	} else {							\
		fprintf(stdout, fmt, ## __VA_ARGS__);			\
	}								\
	fflush(stdout);							\
} while (0)

#define C_ERROR(fmt, ...)						\
do {									\
	fprintf(stderr, "%s:%d:%d:%s() " fmt, __FILE__, getpid(),	\
		__LINE__, __func__, ## __VA_ARGS__);			\
	fflush(stderr);							\
} while (0)

#define C_FATAL(error, fmt, ...)					\
do {									\
	fprintf(stderr, "%s:%d:%s() " fmt, __FILE__, __LINE__,		\
		__func__, ## __VA_ARGS__);				\
	fflush(stderr);							\
	exit(error);							\
} while (0)

#define C_ASSERT(e)	assert(e)

#define C_ASSERTF(cond, fmt, ...)					\
do {									\
	if (!(cond))							\
		C_ERROR(fmt, ## __VA_ARGS__);				\
	assert(cond);							\
} while (0)

#define C_CASSERT(cond)							\
	do {switch (1) {case (cond): case 0: break; } } while (0)

#define CF_U64		"%" PRIu64
#define CF_X64		"%" PRIx64

#define CF_OID		CF_U64"."CF_U64"."CF_U64
#define CP_OID(o)	(o).hi, (o).mid, (o).lo

#define CF_UOID		CF_OID".%u"
#define CP_UOID(uo)	CP_OID((uo).id_pub), (uo).id_shard

/*
 * Each thread has CF_UUID_MAX number of thread-local buffers for UUID strings.
 * Each debug message can have at most this many CP_UUIDs.
 *
 * CF_UUID prints the first eight characters of the string representation,
 * while CF_UUIDF prints the full 36-character string representation. CP_UUID()
 * matches both CF_UUID and CF_UUIDF.
 */
#define CF_UUID_MAX	8
#define CF_UUID		"%.8s"
#define CF_UUIDF	"%s"
char *CP_UUID(const void *uuid);

/* For prefixes of error messages about a container */
#define CF_CONT			CF_UUID"/"CF_UUID": "
#define CP_CONT(puuid, cuuid)	CP_UUID(puuid), CP_UUID(cuuid)

/* memory allocating macros */
#define C_ALLOC(ptr, size)						 \
	do {								 \
		(ptr) = (__typeof__(ptr))calloc(1, size);		 \
		if ((ptr) != NULL) {					 \
			C_DEBUG(CF_MEM, "alloc #ptr : %d at %p.\n",	\
				(int)(size), ptr);			\
			break;						\
		}						 \
		C_ERROR("out of memory (tried to alloc '" #ptr "' = %d)",\
			(int)(size));					 \
	} while (0)

# define C_FREE(ptr, size)						\
	do {								\
		C_DEBUG(CF_MEM, "free #ptr : %d at %p.\n",		\
			(int)(size), ptr);				\
		free(ptr);						\
		(ptr) = NULL;						\
	} while (0)

#define C_ALLOC_PTR(ptr)        C_ALLOC(ptr, sizeof *(ptr))
#define C_FREE_PTR(ptr)         C_FREE(ptr, sizeof *(ptr))

#define C_GOTO(label, rc)       do { ((void)(rc)); goto label; } while (0)

#define CRT_GOLDEN_RATIO_PRIME_64	0xcbf29ce484222325ULL
#define CRT_GOLDEN_RATIO_PRIME_32	0x9e370001UL

static inline uint64_t
crt_u64_hash(uint64_t val, unsigned int bits)
{
	uint64_t hash = val;

	hash *= CRT_GOLDEN_RATIO_PRIME_64;
	return hash >> (64 - bits);
}

static inline uint32_t
crt_u32_hash(uint64_t key, unsigned int bits)
{
	return (CRT_GOLDEN_RATIO_PRIME_32 * key) >> (32 - bits);
}

uint64_t crt_hash_mix64(uint64_t key);
uint32_t crt_hash_mix96(uint32_t a, uint32_t b, uint32_t c);

/** consistent hash search */
unsigned int crt_chash_srch_u64(uint64_t *hashes, unsigned int nhashes,
				 uint64_t value);

/** djb2 hash a string to a uint32_t value */
uint32_t crt_hash_string_u32(const char *string, unsigned int len);
/** murmur hash (64 bits) */
uint64_t crt_hash_murmur64(const unsigned char *key, unsigned int key_len,
			    unsigned int seed);

#define LOWEST_BIT_SET(x)       ((x) & ~((x) - 1))

static inline unsigned int
crt_power2_nbits(unsigned int val)
{
	unsigned int shift;

	for (shift = 1; (val >> shift) != 0; shift++);

	return val == LOWEST_BIT_SET(val) ? shift - 1 : shift;
}

int
crt_rank_list_dup(crt_rank_list_t **dst, const crt_rank_list_t *src,
		   bool input);
void
crt_rank_list_free(crt_rank_list_t *rank_list);
void
crt_rank_list_copy(crt_rank_list_t *dst, crt_rank_list_t *src, bool input);
void
crt_rank_list_sort(crt_rank_list_t *rank_list);
bool
crt_rank_list_find(crt_rank_list_t *rank_list, crt_rank_t rank, int *idx);
bool
crt_rank_list_identical(crt_rank_list_t *rank_list1,
			 crt_rank_list_t *rank_list2, bool input);
bool
crt_rank_in_rank_list(crt_rank_list_t *rank_list, crt_rank_t rank);


#if !defined(container_of)
/* given a pointer @ptr to the field @member embedded into type (usually
 *  * struct) @type, return pointer to the embedding instance of @type. */
# define container_of(ptr, type, member)		\
	        ((type *)((char *)(ptr)-(char *)(&((type *)0)->member)))
#endif

#ifndef offsetof
# define offsetof(typ,memb)	((long)((char *)&(((typ *)0)->memb)))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef MIN
# define MIN(a,b) (((a)<(b)) ? (a): (b))
#endif
#ifndef MAX
# define MAX(a,b) (((a)>(b)) ? (a): (b))
#endif

#ifndef min
#define min(x,y) ((x)<(y) ? (x) : (y))
#endif

#ifndef max
#define max(x,y) ((x)>(y) ? (x) : (y))
#endif

#ifndef min_t
#define min_t(type,x,y) \
	        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#endif
#ifndef max_t
#define max_t(type,x,y) \
	        ({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
#endif

#define CRT_UUID_STR_SIZE 37	/* 36 + 1 for '\0' */

/* byte swapper */
#define C_SWAP16(x)	bswap_16(x)
#define C_SWAP32(x)	bswap_32(x)
#define C_SWAP64(x)	bswap_64(x)
#define C_SWAP16S(x)	do { *(x) = C_SWAP16(*(x)); } while (0)
#define C_SWAP32S(x)	do { *(x) = C_SWAP32(*(x)); } while (0)
#define C_SWAP64S(x)	do { *(x) = C_SWAP64(*(x)); } while (0)

static inline int
crt_errno2der(int err)
{
	switch (err) {
	case 0:		return 0;
	case EPERM:
	case EACCES:	return -CER_NO_PERM;
	case ENOMEM:	return -CER_NOMEM;
	case EDQUOT:
	case ENOSPC:	return -CER_NOSPACE;
	case EEXIST:	return -CER_EXIST;
	case ENOENT:	return -CER_NONEXIST;
	case ECANCELED:	return -CER_CANCELED;
	default:	return -CER_INVAL;
	}
	return 0;
}

#endif /* __CRT_COMMON_H__ */