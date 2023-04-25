/**
 * \file md_wrap.c
 *
 * \brief Generic message digest wrapper for mbed TLS
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */


#include "memory_buffer_alloc.h"
#include "md_internal.h"
#include "sha256.h"


static int sha224_update_wrap( void *const ctx, const unsigned char *const input,
		const size_t ilen );

static int sha224_finish_wrap( void *const ctx, unsigned char *const output );

static void *sha224_ctx_alloc( void );

static void sha224_ctx_free( void *const ctx );

static void sha224_clone_wrap( void *const dst, const void *const src );

static int sha224_process_wrap( void *const ctx, const unsigned char *const data );

static int sha256_starts_wrap( void *const ctx );

static int sha256_wrap( const unsigned char *const input, const size_t ilen,
		unsigned char *const output );

/*
 * Wrappers for generic message digests
 */
static int sha224_update_wrap( void *const ctx, const unsigned char *const input,
		const size_t ilen )
{
	return( mbedtls_sha256_update_ret( (mbedtls_sha256_context_s *) ctx,
			input, ilen ) );
}

static int sha224_finish_wrap( void *const ctx, unsigned char *const output )
{
	return( mbedtls_sha256_finish_ret( (mbedtls_sha256_context_s *) ctx,
			output ) );
}

static void *sha224_ctx_alloc( void )
{
	void *const ctx = buffer_alloc_calloc( 1, sizeof( mbedtls_sha256_context_s ) );

	if( ctx != NULL_PTR )
	{
		mbedtls_sha256_init( (mbedtls_sha256_context_s *) ctx );
	}

	return( ctx );
}

static void sha224_ctx_free( void *const ctx )
{
	mbedtls_sha256_free( (mbedtls_sha256_context_s *) ctx );
	buffer_alloc_free( ctx );
}

static void sha224_clone_wrap( void *const dst, const void *const src )
{
	mbedtls_sha256_clone( (mbedtls_sha256_context_s *) dst,
			(const mbedtls_sha256_context_s *) src );
}

static int sha224_process_wrap( void *const ctx, const unsigned char *const data )
{
	return( mbedtls_internal_sha256_process( (mbedtls_sha256_context_s *) ctx,
			data ) );
}

static int sha256_starts_wrap( void *const ctx )
{
	return( mbedtls_sha256_starts_ret( (mbedtls_sha256_context_s *) ctx, 0 ) );
}

static int sha256_wrap( const unsigned char *const input, const size_t ilen,
		unsigned char *const output )
{
	return( mbedtls_sha256_ret( input, ilen, output, 0 ) );
}

const mbedtls_md_info_t_s mbedtls_sha256_info = {
		MBEDTLS_MD_SHA256,
		"SHA256",
		32,
		64,
		&sha256_starts_wrap,
		&sha224_update_wrap,
		&sha224_finish_wrap,
		&sha256_wrap,
		&sha224_ctx_alloc,
		&sha224_ctx_free,
		&sha224_clone_wrap,
		&sha224_process_wrap,
};


