/*
 *  HMAC_DRBG implementation (NIST SP 800-90)
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


#include "Crypto_Types_General.h"
#include "hmac_drbg.h"

#include "platform_util.h"
#include <string.h>


/*
 * HMAC_DRBG context initialization
 */
void mbedtls_hmac_drbg_init( mbedtls_hmac_drbg_context_s *const ctx )
{
	memset( ctx, 0, sizeof( mbedtls_hmac_drbg_context_s ) );

}

/*
 * HMAC_DRBG update, using optional additional data (10.1.2.2)
 */
int mbedtls_hmac_drbg_update_ret( mbedtls_hmac_drbg_context_s *const ctx,
		const unsigned char *const additional,
		const size_t add_len )
{
	const size_t md_len = mbedtls_md_get_size( ctx->md_ctx.md_info );
	const unsigned char rounds = ( (additional != NULL_PTR) && (add_len != 0)) ? 2 : 1;
	unsigned char sep[1];
	unsigned char K[MBEDTLS_MD_MAX_SIZE];
	int ret;


	for( sep[0] = 0; sep[0] < rounds; sep[0]++ )
	{
		/* Step 1 or 4 */
		ret = mbedtls_md_hmac_reset( &ctx->md_ctx ) ;
		if( ret != 0 )
		{
			goto exit;
		}

		ret = mbedtls_md_hmac_update( &ctx->md_ctx,
				ctx->V, md_len );
		if( ret != 0 )
		{
			goto exit;
		}

		ret = mbedtls_md_hmac_update( &ctx->md_ctx,
				sep, 1 );
		if( ret != 0 )
		{
			goto exit;
		}
		if( rounds == 2 )
		{
			ret = mbedtls_md_hmac_update( &ctx->md_ctx,
					additional, add_len );
			if( ret != 0 )
			{
				goto exit;
			}
		}

		ret = mbedtls_md_hmac_finish( &ctx->md_ctx, K ) ;
		if( ret != 0 )
		{
			goto exit;
		}

		/* Step 2 or 5 */

		ret = mbedtls_md_hmac_starts( &ctx->md_ctx, K, md_len );
		if( ret != 0 )
		{
			goto exit;
		}

		ret = mbedtls_md_hmac_update( &ctx->md_ctx,
				ctx->V, md_len ) ;
		if( ret != 0 )
		{
			goto exit;
		}

		ret = mbedtls_md_hmac_finish( &ctx->md_ctx, ctx->V );
		if( ret != 0 )
		{
			goto exit;
		}
	}

	exit:
	mbedtls_platform_zeroize( K, sizeof( K ) );
	return( ret );
}

/*
 * Simplified HMAC_DRBG initialisation (for use with deterministic ECDSA)
 */
int mbedtls_hmac_drbg_seed_buf( mbedtls_hmac_drbg_context_s *const ctx,
		const mbedtls_md_info_t_s *const md_info,
		const unsigned char *const data, const size_t data_len )
{
	int ret;

	ret = mbedtls_md_setup( &ctx->md_ctx, md_info, 1 );
	if( ret != 0 )
	{
		return( ret );
	}

	/*
	 * Set initial working state.
	 * Use the V memory location, which is currently all 0, to initialize the
	 * MD context with an all-zero key. Then set V to its initial value.
	 */

	ret = mbedtls_md_hmac_starts( &ctx->md_ctx, ctx->V,
			mbedtls_md_get_size( md_info ) );
	if( ret != 0 )
	{
		return( ret );
	}
	memset( ctx->V, 0x01, mbedtls_md_get_size( md_info ) );

	ret = mbedtls_hmac_drbg_update_ret( ctx, data, data_len );
	if( ret != 0 )
	{
		return( ret );
	}

	return( 0 );
}

/*
 * HMAC_DRBG reseeding: 10.1.2.4 (arabic) + 9.2 (Roman)
 */
int mbedtls_hmac_drbg_reseed( mbedtls_hmac_drbg_context_s *const ctx,
		const unsigned char *const additional, const size_t len )
{
	unsigned char seed[MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT];
	size_t seedlen;
	int ret;

	/* III. Check input length */
	if( (len > MBEDTLS_HMAC_DRBG_MAX_INPUT) ||
			(((ctx->entropy_len) + len) > MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT) )
	{
		return( MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG );
	}

	memset( seed, 0, MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT );

	/* IV. Gather entropy_len bytes of entropy for the seed */
	ret = ctx->f_entropy( ctx->p_entropy,
			seed, ctx->entropy_len ) ;
	if( ret != 0 )
	{
		return( MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED );
	}

	seedlen = ctx->entropy_len;

	/* 1. Concatenate entropy and additional data if any */
	if( (additional != NULL_PTR) && (len != 0) )
	{
		memcpy( seed + seedlen, additional, len );
		seedlen += len;
	}

	/* 2. Update state */
	ret = mbedtls_hmac_drbg_update_ret( ctx, seed, seedlen ) ;
	if( ret != 0 )
	{
		goto exit;
	}

	/* 3. Reset reseed_counter */
	ctx->reseed_counter = 1;

	exit:
	/* 4. Done */
	mbedtls_platform_zeroize( seed, seedlen );
	return( ret );
}

/*
 * HMAC_DRBG random function with optional additional data:
 * 10.1.2.5 (arabic) + 9.3 (Roman)
 */
int mbedtls_hmac_drbg_random_with_add( void *const p_rng,
		unsigned char *const output, const size_t out_len,
		const unsigned char *const additional, size_t add_len )
{
	int ret;
	mbedtls_hmac_drbg_context_s *const ctx = (mbedtls_hmac_drbg_context_s *) p_rng;
	const size_t md_len = mbedtls_md_get_size( ctx->md_ctx.md_info );
	size_t left = out_len;
	unsigned char *out = output;

	/* II. Check request length */
	if( out_len > MBEDTLS_HMAC_DRBG_MAX_REQUEST )
	{
		return( MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG );
	}

	/* III. Check input length */
	if( add_len > MBEDTLS_HMAC_DRBG_MAX_INPUT )
	{
		return( MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG );
	}

	/* 1. (aka VII and IX) Check reseed counter and PR */
	if( ((ctx->f_entropy) != NULL_PTR) && /* For no-reseeding instances */
			( ((ctx->prediction_resistance) == MBEDTLS_HMAC_DRBG_PR_ON) ||
					((ctx->reseed_counter) > ctx->reseed_interval) ) )
	{
		ret = mbedtls_hmac_drbg_reseed( ctx, additional, add_len );
		if( ret != 0 )
		{
			return( ret );
		}

		add_len = 0; /* VII.4 */
	}

	/* 2. Use additional data if any */
	if( (additional != NULL_PTR) && (add_len != 0) )
	{
		ret = mbedtls_hmac_drbg_update_ret( ctx,
				additional, add_len );
		if( ret != 0 )
		{
			goto exit;
		}
	}

	/* 3, 4, 5. Generate bytes */
	while( left != 0 )
	{
		size_t use_len = (left > md_len) ? md_len : left;

		ret = mbedtls_md_hmac_reset( &ctx->md_ctx ) ;
		if( ret != 0 )
		{
			goto exit;
		}

		ret = mbedtls_md_hmac_update( &ctx->md_ctx,
				ctx->V, md_len );
		if( ret != 0 )
		{
			goto exit;
		}


		ret = mbedtls_md_hmac_finish( &ctx->md_ctx, ctx->V );
		if( ret != 0 )
		{
			goto exit;
		}

		memcpy( out, ctx->V, use_len );
		out += use_len;
		left -= use_len;
	}

	/* 6. Update */

	ret = mbedtls_hmac_drbg_update_ret( ctx,
			additional, add_len );
	if( ret != 0 )
	{
		goto exit;
	}

	/* 7. Update reseed counter */
	ctx->reseed_counter++;

	exit:
	/* 8. Done */
	return( ret );
}

/* 
 * HMAC_DRBG random function
 */
sint32 mbedtls_hmac_drbg_random( void *const p_rng, uint8 *const output, const uint32 out_len )
{
	int ret;
	mbedtls_hmac_drbg_context_s *const ctx = (mbedtls_hmac_drbg_context_s *) p_rng;


	ret = mbedtls_hmac_drbg_random_with_add( ctx, output, out_len, NULL_PTR, 0 );


	return( ret );
}

/*
 * Free an HMAC_DRBG context
 */
void mbedtls_hmac_drbg_free( mbedtls_hmac_drbg_context_s *const ctx )
{
	if( ctx == NULL_PTR )
	{
		return;
	}

	mbedtls_md_free( &ctx->md_ctx );
	mbedtls_platform_zeroize( ctx, sizeof( mbedtls_hmac_drbg_context_s ) );
}

