/*
 *  FIPS-180-2 compliant SHA-256 implementation
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
/*
 *  The SHA-256 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */

#include "sha256.h"
#include "platform_util.h"
#include "memory_buffer_alloc.h"
#include <string.h>


#define SHA256_VALIDATE_RET(cond)                           \
		MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_SHA256_BAD_INPUT_DATA )
#define SHA256_VALIDATE(cond)  MBEDTLS_INTERNAL_VALIDATE( cond )


/*
 * 32-bit integer manipulation macros (big endian)
 */

#define GET_UINT32_BE(n,b,i)                            \
		do {                                                    \
			(n) = ( (uint32) (b)[(i)    ] << 24 )             \
			| ( (uint32) (b)[(i) + 1] << 16 )             \
			| ( (uint32) (b)[(i) + 2] <<  8 )             \
			| ( (uint32) (b)[(i) + 3]       );            \
		} while( 0 )

#define PUT_UINT32_BE(n,b,i)                            \
		do {                                                    \
			(b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
			(b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
			(b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
			(b)[(i) + 3] = (unsigned char) ( (n)       );       \
		} while( 0 )


void mbedtls_sha256_init( mbedtls_sha256_context_s * const ctx )
{
	SHA256_VALIDATE( ctx != NULL_PTR );

	memset( ctx, 0, sizeof( mbedtls_sha256_context_s ) );
}

void mbedtls_sha256_free( mbedtls_sha256_context_s *const ctx )
{
	if( ctx == NULL_PTR )
	{
		return;
	}

	mbedtls_platform_zeroize( ctx, sizeof( mbedtls_sha256_context_s ) );
}

void mbedtls_sha256_clone( mbedtls_sha256_context_s * const dst,
		const mbedtls_sha256_context_s * const src )
{
	SHA256_VALIDATE( dst != NULL_PTR );
	SHA256_VALIDATE( src != NULL_PTR );

	*dst = *src;
}

/*
 * SHA-256 context setup
 */
 int mbedtls_sha256_starts_ret( mbedtls_sha256_context_s *const ctx, const int is224 )
 {
	 SHA256_VALIDATE_RET( ctx != NULL_PTR );
	 SHA256_VALIDATE_RET( is224 == 0 || is224 == 1 );

	 ctx->total[0] = 0;
	 ctx->total[1] = 0;

	 if( is224 == 0 )
	 {
		 /* SHA-256 */
		 ctx->state[0] = (uint32)0x6A09E667U;
		 ctx->state[1] = (uint32)0xBB67AE85U;
		 ctx->state[2] = (uint32)0x3C6EF372U;
		 ctx->state[3] = (uint32)0xA54FF53AU;
		 ctx->state[4] = (uint32)0x510E527FU;
		 ctx->state[5] = (uint32)0x9B05688CU;
		 ctx->state[6] = (uint32)0x1F83D9ABU;
		 ctx->state[7] = (uint32)0x5BE0CD19U;
	 }
	 else
	 {
		 /* SHA-224 */
		 ctx->state[0] = (uint32)0xC1059ED8U;
		 ctx->state[1] = (uint32)0x367CD507U;
		 ctx->state[2] = (uint32)0x3070DD17U;
		 ctx->state[3] = (uint32)0xF70E5939U;
		 ctx->state[4] = (uint32)0xFFC00B31U;
		 ctx->state[5] = (uint32)0x68581511U;
		 ctx->state[6] = (uint32)0x64F98FA7U;
		 ctx->state[7] = (uint32)0xBEFA4FA4U;
	 }

	 ctx->is224 = is224;

	 return( 0 );
 }


 static const uint32 K[64] =
 {
		 (uint32)0x428A2F98U, (uint32)0x71374491U, (uint32)0xB5C0FBCFU, (uint32)0xE9B5DBA5U,
		 (uint32)0x3956C25BU, (uint32)0x59F111F1U, (uint32)0x923F82A4U, (uint32)0xAB1C5ED5U,
		 (uint32)0xD807AA98U, (uint32)0x12835B01U, (uint32)0x243185BEU, (uint32)0x550C7DC3U,
		 (uint32)0x72BE5D74U, (uint32)0x80DEB1FEU, (uint32)0x9BDC06A7U, (uint32)0xC19BF174U,
		 (uint32)0xE49B69C1U, (uint32)0xEFBE4786U, (uint32)0x0FC19DC6U, (uint32)0x240CA1CCU,
		 (uint32)0x2DE92C6FU, (uint32)0x4A7484AAU, (uint32)0x5CB0A9DCU, (uint32)0x76F988DAU,
		 (uint32)0x983E5152U, (uint32)0xA831C66DU, (uint32)0xB00327C8U, (uint32)0xBF597FC7U,
		 (uint32)0xC6E00BF3U, (uint32)0xD5A79147U, (uint32)0x06CA6351U, (uint32)0x14292967U,
		 (uint32)0x27B70A85U, (uint32)0x2E1B2138U, (uint32)0x4D2C6DFCU, (uint32)0x53380D13U,
		 (uint32)0x650A7354U, (uint32)0x766A0ABBU, (uint32)0x81C2C92EU, (uint32)0x92722C85U,
		 (uint32)0xA2BFE8A1U, (uint32)0xA81A664BU, (uint32)0xC24B8B70U, (uint32)0xC76C51A3U,
		 (uint32)0xD192E819U, (uint32)0xD6990624U, (uint32)0xF40E3585U, (uint32)0x106AA070U,
		 (uint32)0x19A4C116U, (uint32)0x1E376C08U, (uint32)0x2748774CU, (uint32)0x34B0BCB5U,
		 (uint32)0x391C0CB3U, (uint32)0x4ED8AA4AU, (uint32)0x5B9CCA4FU, (uint32)0x682E6FF3U,
		 (uint32)0x748F82EEU, (uint32)0x78A5636FU, (uint32)0x84C87814U, (uint32)0x8CC70208U,
		 (uint32)0x90BEFFFAU, (uint32)0xA4506CEBU, (uint32)0xBEF9A3F7U, (uint32)0xC67178F2U,
 };

#define  SHR(x,n) (((x) & 0xFFFFFFFF) >> (n))
#define ROTR(x,n) (SHR(x,n) | ((x) << (32 - (n))))

#define S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))

#define F0(x,y,z) (((x) & (y)) | ((z) & ((x) | (y))))
#define F1(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))

#define R(t)                                    \
		(                                               \
				W[t] = S1(W[(t) -  2]) + W[(t) -  7] +          \
				S0(W[(t) - 15]) + W[(t) - 16]            \
		)

#define P(a,b,c,d,e,f,g,h,x,K)                  \
		{                                               \
			temp1 = (h) + S3(e) + F1(e,f,g) + (K) + (x);      \
			temp2 = S2(a) + F0(a,b,c);                  \
			(d) += temp1; (h) = (temp1) + (temp2);              \
		}

 int mbedtls_internal_sha256_process( mbedtls_sha256_context_s *const ctx,
		 const unsigned char data[64] )
 {
	 uint32 temp1, temp2, W[64];
	 uint32 A[8];
	 unsigned int i;

	 SHA256_VALIDATE_RET( ctx != NULL_PTR );
	 SHA256_VALIDATE_RET( (const unsigned char *)data != NULL_PTR );

	 for( i = 0; i < (unsigned int)8; i++ )
	 {
		 A[i] = ctx->state[i];
	 }

	 for( i = 0; i < (unsigned int)16; i++ )
	 {
		 GET_UINT32_BE( W[i], data, 4 * i );
	 }

	 for( i = 0; i < (unsigned int)16; i += 8 )
	 {
		 P( A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i+0], K[i+0] );
		 P( A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[i+1], K[i+1] );
		 P( A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[i+2], K[i+2] );
		 P( A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[i+3], K[i+3] );
		 P( A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[i+4], K[i+4] );
		 P( A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[i+5], K[i+5] );
		 P( A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[i+6], K[i+6] );
		 P( A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[i+7], K[i+7] );
	 }

	 for( i = 16; i < (unsigned int)64; i +=(unsigned int)8)
	 {
		 P( A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(i+0), K[i+0] );
		 P( A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(i+1), K[i+1] );
		 P( A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(i+2), K[i+2] );
		 P( A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(i+3), K[i+3] );
		 P( A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(i+4), K[i+4] );
		 P( A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(i+5), K[i+5] );
		 P( A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(i+6), K[i+6] );
		 P( A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(i+7), K[i+7] );
	 }


	 for( i = 0; i < (unsigned int)8; i++ )
	 {
		 ctx->state[i] += A[i];
	 }

	 return( 0 );
 }


 /*
  * SHA-256 process buffer
  */
 int mbedtls_sha256_update_ret( mbedtls_sha256_context_s *const ctx,
		 const unsigned char *input,
		 size_t ilen )
 {
	 int ret;
	 size_t fill;
	 uint32 left;

	 SHA256_VALIDATE_RET( ctx != NULL_PTR );
	 SHA256_VALIDATE_RET( ilen == 0 || input != NULL_PTR );

	 if( ilen == 0 )
	 {
		 return( 0 );
	 }
	 left = ctx->total[0] & 0x3F;
	 fill = 64 - left;

	 ctx->total[0] += (uint32) ilen;
	 ctx->total[0] &= (uint32) 0xFFFFFFFFU;

	 if( ctx->total[0] < (uint32) ilen )
	 {
		 ctx->total[1]++;
	 }

	 if(left > 0)
	 {
		 if(ilen >= fill)
		 {
			 memcpy( (void *) (ctx->buffer + left), input, fill );

			 ret = mbedtls_internal_sha256_process( ctx, ctx->buffer );

			 if( ret != 0 )
			 {
				 return( ret );
			 }
			 input += fill;
			 ilen  -= fill;
			 left = 0;
		 }
	 }

	 while( ilen >= 64 )
	 {

		 ret = mbedtls_internal_sha256_process( ctx, input ) ;
		 if( ret != 0 )
		 {
			 return( ret );
		 }
		 input += 64;
		 ilen  -= 64;
	 }

	 if( ilen > 0 )
	 {
		 memcpy( (void *) (ctx->buffer + left), input, ilen );
	 }
	 return( 0 );
 }

 /*
  * SHA-256 final digest
  */
 int mbedtls_sha256_finish_ret( mbedtls_sha256_context_s *const ctx,
		 unsigned char output[32] )
 {
	 int ret;
	 uint32 used;
	 uint32 high, low;

	 SHA256_VALIDATE_RET( ctx != NULL_PTR );
	 SHA256_VALIDATE_RET( (unsigned char *)output != NULL_PTR );

	 /*
	  * Add padding: 0x80 then 0x00 until 8 bytes remain for the length
	  */
	 used = ctx->total[0] & 0x3F;

	 ctx->buffer[used] = 0x80;

	 used++;

	 if( used <= 56 )
	 {
		 /* Enough room for padding + length in current block */
		 memset( ctx->buffer + used, 0, 56 - used );
	 }
	 else
	 {
		 /* We'll need an extra block */
		 memset( ctx->buffer + used, 0, 64 - used );

		 ret = mbedtls_internal_sha256_process( ctx, ctx->buffer );

		 if( ret != 0 )
		 {
			 return( ret );
		 }
		 memset( ctx->buffer, 0, 56 );
	 }

	 /*
	  * Add message length
	  */
	 high = ( ctx->total[0] >> 29 )
        		 | ( ctx->total[1] <<  3 );
	 low  = ( ctx->total[0] <<  3 );

	 PUT_UINT32_BE( high, ctx->buffer, 56 );
	 PUT_UINT32_BE( low,  ctx->buffer, 60 );
	 ret = mbedtls_internal_sha256_process( ctx, ctx->buffer );

	 if( ret != 0 )
	 {
		 return( ret );
	 }
	 /*
	  * Output final state
	  */
	 PUT_UINT32_BE( ctx->state[0], output,  0 );
	 PUT_UINT32_BE( ctx->state[1], output,  4 );
	 PUT_UINT32_BE( ctx->state[2], output,  8 );
	 PUT_UINT32_BE( ctx->state[3], output, 12 );
	 PUT_UINT32_BE( ctx->state[4], output, 16 );
	 PUT_UINT32_BE( ctx->state[5], output, 20 );
	 PUT_UINT32_BE( ctx->state[6], output, 24 );

	 if( ctx->is224 == 0 )
	 {
		 PUT_UINT32_BE( ctx->state[7], output, 28 );
	 }
	 return( 0 );
 }

 /*
  * output = SHA-256( input buffer )
  */
 int mbedtls_sha256_ret( const unsigned char *const input,
		 const size_t ilen,
		 unsigned char output[32],
		 const int is224 )
 {
	 int ret;
	 mbedtls_sha256_context_s ctx;

	 SHA256_VALIDATE_RET( is224 == 0 || is224 == 1 );
	 SHA256_VALIDATE_RET( ilen == 0 || input != NULL_PTR );
	 SHA256_VALIDATE_RET( (unsigned char *)output != NULL_PTR );

	 mbedtls_sha256_init( &ctx );

	 ret = mbedtls_sha256_starts_ret( &ctx, is224 );
	 if( ret != 0 )
	 {
		 goto exit;
	 }

	 ret = mbedtls_sha256_update_ret( &ctx, input, ilen );
	 if( ret != 0 )
	 {
		 goto exit;
	 }

	 ret = mbedtls_sha256_finish_ret( &ctx, output );
	 if( ret != 0 )
	 {
		 goto exit;
	 }
	 exit:
	 mbedtls_sha256_free( &ctx );

	 return( ret );
 }


