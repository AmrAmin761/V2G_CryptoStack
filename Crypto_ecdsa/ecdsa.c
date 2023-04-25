/*
 *  Elliptic curve DSA
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


#include "ecdsa.h"
#include "memory_buffer_alloc.h"
#include <string.h>
#include "hmac_drbg.h"
#include "platform_util.h"


/* Random Number K */
const uint8 secret_key_ecdsa[] =
{

   /* Secret Key number 1 */

   0x94, 0xa1, 0xbb, 0xb1, 0x4b, 0x90, 0x6a, 0x61, 0xa2, 0x80,
   0xf2, 0x45, 0xf9, 0xe9, 0x3c, 0x7f, 0x3b, 0x4a, 0x62, 0x47,
   0x82, 0x4f, 0x5d, 0x33, 0xb9, 0x67, 0x07, 0x87, 0x64, 0x2a,
   0x68, 0xde,


   /* Secret Key number 2 */

   0x6d, 0x3e, 0x71, 0x88, 0x2c, 0x3b, 0x83, 0xb1, 0x56, 0xbb,
   0x14, 0xe0, 0xab, 0x18, 0x4a, 0xa9, 0xfb, 0x72, 0x80, 0x68,
   0xd3, 0xae, 0x9f, 0xac, 0x42, 0x11, 0x87, 0xae, 0x0b, 0x2f,
   0x34, 0xc6,


   /* Secret Key number 3 */

   0xad, 0x5e, 0x88, 0x7e, 0xb2, 0xb3, 0x80, 0xb8, 0xd8, 0x28,
   0x0a, 0xd6, 0xe5, 0xff, 0x8a, 0x60, 0xf4, 0xd2, 0x62, 0x43,
   0xe0, 0x12, 0x4c, 0x2f, 0x31, 0xa2, 0x97, 0xb5, 0xd0, 0x83,
   0x5d, 0xe2,


   /* Secret Key number 4 */

   0x24, 0xfc, 0x90, 0xe1, 0xda, 0x13, 0xf1, 0x7e, 0xf9, 0xfe,
   0x84, 0xcc, 0x96, 0xb9, 0x47, 0x1e, 0xd1, 0xaa, 0xac, 0x17,
   0xe3, 0xa4, 0xba, 0xe3, 0x3a, 0x11, 0x5d, 0xf4, 0xe5, 0x83,
   0x4f, 0x18,
};





/* Parameter validation macros based on platform_util.h */
#define ECDSA_VALIDATE_RET( cond )    \
		MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECDSA_VALIDATE( cond )        \
		MBEDTLS_INTERNAL_VALIDATE( cond )

#define ECDSA_RS_ECP    NULL_PTR

#define ECDSA_RS_ENTER( SUB )   (void) rs_ctx
#define ECDSA_RS_LEAVE( SUB )   (void) rs_ctx



static int derive_mpi( const mbedtls_ecp_group_s *const grp, mbedtls_mpi *const x,
		const unsigned char *const buf, const size_t blen );


static int ecdsa_sign_restartable( mbedtls_ecp_group_s *const grp,
		mbedtls_mpi *const r, mbedtls_mpi *const s,
		const mbedtls_mpi *const d, const unsigned char *const buf, const size_t blen,
		sint32 (* const f_rng)(void * , uint8 * , uint32), void *const p_rng,
		const mbedtls_ecdsa_restart_ctx *const rs_ctx );


static int ecdsa_sign_det_restartable( mbedtls_ecp_group_s *const grp,
		mbedtls_mpi *const r, mbedtls_mpi *const s,
		const mbedtls_mpi *const d, const unsigned char *const buf, const size_t blen,
		const mbedtls_md_type_t md_alg,
		const mbedtls_ecdsa_restart_ctx *const rs_ctx );

static int ecdsa_verify_restartable( mbedtls_ecp_group_s *const grp,
		const unsigned char *const buf, const size_t blen,
		const mbedtls_ecp_point_s *const Q,
		const mbedtls_mpi *const r, const mbedtls_mpi *const s,
		const mbedtls_ecdsa_restart_ctx *const rs_ctx );



/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
 static int derive_mpi( const mbedtls_ecp_group_s *const grp, mbedtls_mpi *const x,
		 const unsigned char *const buf, const size_t blen )
{
	 int ret;
	 sint32 result_output_fun;
	 const size_t n_size = ( grp->nbits + 7 ) / 8;
	 const size_t use_size = (blen > n_size) ? n_size : blen;
	 result_output_fun = mbedtls_mpi_read_binary( x, buf, use_size );

	 MBEDTLS_MPI_CHK(result_output_fun);
	 if( (use_size * 8) > grp->nbits )
	 {
		 result_output_fun = mbedtls_mpi_shift_r( x, (use_size * 8) - (grp->nbits) );

		 MBEDTLS_MPI_CHK(result_output_fun);
	 }
	 /* While at it, reduce modulo N */
	 if( mbedtls_mpi_cmp_mpi( x, &grp->N ) >= 0 )
	 {
		 result_output_fun = mbedtls_mpi_sub_mpi( x, x, &grp->N );

		 MBEDTLS_MPI_CHK(result_output_fun);
	 }
	 cleanup:
	 return( ret );
}

 /*
  * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
  * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
  */
 static int ecdsa_sign_restartable( mbedtls_ecp_group_s *const grp,
		 mbedtls_mpi *const r, mbedtls_mpi *const s,
		 const mbedtls_mpi *const d, const unsigned char *const buf, const size_t blen,
		 sint32 (* const f_rng)(void * , uint8 * , uint32), void *const p_rng,
		 const mbedtls_ecdsa_restart_ctx *const rs_ctx )
 {
	 int ret, key_tries, sign_tries;
	 int *p_sign_tries = &sign_tries, *p_key_tries = &key_tries;
	 sint32 result_output_fun;
	 mbedtls_ecp_point_s R;
	 mbedtls_mpi k, e, t;
	 mbedtls_mpi *const pk = &k, *const pr = r;

	 static uint32 private_key_count =0;
	 /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
	 if( grp->N.limbsPtr == NULL_PTR )
	 {
		 return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	 }

	 /* Make sure d is in range 1..n-1 */
	 if( mbedtls_mpi_cmp_int( d, 1 ) < 0)
	 {
		 if(mbedtls_mpi_cmp_mpi( d, &grp->N ) >= 0)
		 {
			 return( MBEDTLS_ERR_ECP_INVALID_KEY );
		 }
	 }

	 mbedtls_ecp_point_init( &R );
	 mbedtls_mpi_init( &k ); mbedtls_mpi_init( &e ); mbedtls_mpi_init( &t );

	 ECDSA_RS_ENTER( sig );

	 *p_sign_tries = 0;
	 do
	 {
		 if( *p_sign_tries++ > 10 )
		 {
			 ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
			 goto cleanup;
		 }

		 /*
		  * Steps 1-3: generate a suitable ephemeral keypair
		  * and set r = xR mod n
		  */
		 *p_key_tries = 0;
		 do
		 {
			 if( *p_key_tries++ > 10 )
			 {
				 ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
				 goto cleanup;
			 }

			 /* sint32 result_output_fun = mbedtls_ecp_gen_privkey( grp, pk, f_rng, p_rng );
              MBEDTLS_MPI_CHK(result);    */
			 mbedtls_mpi_read_binary(&k, &secret_key_ecdsa[GenerationKey.CurrentkeyIndex * 32], 32);              /* copying secret key to the mbedtls struct */
			 private_key_count+=32;       /* copying secret key to the mbedtls struct */

			 result_output_fun = mbedtls_ecp_mul_restartable( grp, &R, pk, &grp->G,
					 f_rng, p_rng, ECDSA_RS_ECP );
			 MBEDTLS_MPI_CHK(result_output_fun);

			 result_output_fun = mbedtls_mpi_mod_mpi( pr, &R.X, &grp->N );

			 MBEDTLS_MPI_CHK(result_output_fun);
		 }
		 while( mbedtls_mpi_cmp_int( pr, 0 ) == 0 );
		 /*
		  * Accounting for everything up to the end of the loop
		  * (step 6, but checking now avoids saving e and t)
		  */
		 /*
		  * Step 5: derive MPI from hashed message
		  */
		 result_output_fun = derive_mpi( grp, &e, buf, blen );
		 MBEDTLS_MPI_CHK(result_output_fun);

		 /*
		  * Generate a random value to blind inv_mod in next step,
		  * avoiding a potential timing leak.
		  */
		 result_output_fun = mbedtls_ecp_gen_privkey( grp, &t, f_rng, p_rng ) ;
		 MBEDTLS_MPI_CHK(result_output_fun);

		 /*
		  * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
		  */
		 result_output_fun = mbedtls_mpi_mul_mpi( s, pr, d ) ;
		 MBEDTLS_MPI_CHK(result_output_fun);

		 result_output_fun = mbedtls_mpi_add_mpi( &e, &e, s );
		 MBEDTLS_MPI_CHK(result_output_fun);

		 result_output_fun = mbedtls_mpi_mul_mpi( &e, &e, &t ) ;
		 MBEDTLS_MPI_CHK( result_output_fun);

		 result_output_fun = mbedtls_mpi_mul_mpi( pk, pk, &t ) ;
		 MBEDTLS_MPI_CHK(result_output_fun);

		 result_output_fun =  mbedtls_mpi_inv_mod( s, pk, &grp->N ) ;
		 MBEDTLS_MPI_CHK(result_output_fun);

		 result_output_fun =  mbedtls_mpi_mul_mpi( s, s, &e ) ;
		 MBEDTLS_MPI_CHK(result_output_fun);

		 result_output_fun = mbedtls_mpi_mod_mpi( s, s, &grp->N ) ;
		 MBEDTLS_MPI_CHK(result_output_fun);
	 }
	 while( mbedtls_mpi_cmp_int( s, 0 ) == 0 );

	 cleanup:
	 mbedtls_ecp_point_free( &R );
	 mbedtls_mpi_free( &k ); mbedtls_mpi_free( &e ); mbedtls_mpi_free( &t );

	 ECDSA_RS_LEAVE( sig );

	 return( ret );
 }

 /*
  * Compute ECDSA signature of a hashed message
  */
 int mbedtls_ecdsa_sign( mbedtls_ecp_group_s *const grp, mbedtls_mpi *const r, mbedtls_mpi *const s,
		 const mbedtls_mpi *const d, const unsigned char *const buf, const size_t blen,
		 sint32 (* const f_rng)(void * , uint8 * , uint32), void *const p_rng )
 {
	 ECDSA_VALIDATE_RET( grp   != NULL_PTR );
	 ECDSA_VALIDATE_RET( r     != NULL_PTR );
	 ECDSA_VALIDATE_RET( s     != NULL_PTR );
	 ECDSA_VALIDATE_RET( d     != NULL_PTR );
	 ECDSA_VALIDATE_RET( f_rng != NULL_PTR );
	 ECDSA_VALIDATE_RET( buf   != NULL_PTR || blen == 0 );

	 return( ecdsa_sign_restartable( grp, r, s, d, buf, blen,
			 f_rng, p_rng, NULL_PTR ) );
 }

 /*
  * Deterministic signature wrapper
  */
 static int ecdsa_sign_det_restartable( mbedtls_ecp_group_s *const grp,
		 mbedtls_mpi *const r, mbedtls_mpi *const s,
		 const mbedtls_mpi *const d, const unsigned char *const buf, const size_t blen,
		 const mbedtls_md_type_t md_alg,
		 const mbedtls_ecdsa_restart_ctx *const rs_ctx )
 {
	 int ret;
	 sint32 result;
	 mbedtls_hmac_drbg_context_s rng_ctx;
	 mbedtls_hmac_drbg_context_s *const p_rng = &rng_ctx;
	 unsigned char data[2 * MBEDTLS_ECP_MAX_BYTES];
	 const size_t grp_len = ( grp->nbits + 7 ) / 8;
	 const mbedtls_md_info_t_s *md_info;
	 mbedtls_mpi h;

	 if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL_PTR )
	 {
		 return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	 }

	 mbedtls_mpi_init( &h );
	 mbedtls_hmac_drbg_init( &rng_ctx );

	 ECDSA_RS_ENTER( det );

	 /* Use private key and message hash (reduced) to initialize HMAC_DRBG */

	 result =  mbedtls_mpi_write_binary( d, data, grp_len );
	 MBEDTLS_MPI_CHK(result);

	 result =  derive_mpi( grp, &h, buf, blen );
	 MBEDTLS_MPI_CHK(result);

	 result =  mbedtls_mpi_write_binary( &h, data + grp_len, grp_len );
	 MBEDTLS_MPI_CHK(result);

	 mbedtls_hmac_drbg_seed_buf( p_rng, md_info, data, 2 * grp_len );

	 ret = mbedtls_ecdsa_sign( grp, r, s, d, buf, blen,
			 &mbedtls_hmac_drbg_random, p_rng );
	 cleanup:
	 mbedtls_hmac_drbg_free( &rng_ctx );
	 mbedtls_mpi_free( &h );

	 ECDSA_RS_LEAVE( det );

	 return( ret );
 }

 /*
  * Deterministic signature wrapper
  */
 int mbedtls_ecdsa_sign_det( mbedtls_ecp_group_s *const grp, mbedtls_mpi *const r, mbedtls_mpi *const s,
		 const mbedtls_mpi *const d, const unsigned char *const buf, const size_t blen,
		 const mbedtls_md_type_t md_alg )
 {
	 ECDSA_VALIDATE_RET( grp   != NULL_PTR );
	 ECDSA_VALIDATE_RET( r     != NULL_PTR );
	 ECDSA_VALIDATE_RET( s     != NULL_PTR );
	 ECDSA_VALIDATE_RET( d     != NULL_PTR );
	 ECDSA_VALIDATE_RET( buf   != NULL_PTR || blen == 0 );

	 return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg, NULL_PTR ) );
 }

 /*
  * Verify ECDSA signature of hashed message (SEC1 4.1.4)
  * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
  */
 static int ecdsa_verify_restartable( mbedtls_ecp_group_s *const grp,
		 const unsigned char *const buf, const size_t blen,
		 const mbedtls_ecp_point_s *const Q,
		 const mbedtls_mpi *const r, const mbedtls_mpi *const s,
		 const mbedtls_ecdsa_restart_ctx *const rs_ctx )
 {
	 int ret;

	 mbedtls_mpi e, s_inv, u1, u2;
	 mbedtls_ecp_point_s R;
	 mbedtls_mpi *const pu1 = &u1, *const pu2 = &u2;
	 sint32 result_output_fun ;

	 mbedtls_ecp_point_init( &R );
	 mbedtls_mpi_init( &e ); mbedtls_mpi_init( &s_inv );
	 mbedtls_mpi_init( &u1 ); mbedtls_mpi_init( &u2 );

	 /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
	 if( grp->N.limbsPtr == NULL_PTR )
	 {
		 return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	 }

	 ECDSA_RS_ENTER( ver );

	 /*
	  * Step 1: make sure r and s are in range 1..n-1
	  */
	 if( mbedtls_mpi_cmp_int( r, 1 ) < 0)
	 {
		 if(mbedtls_mpi_cmp_mpi( r, &grp->N ) >= 0 )
		 {
			 if(mbedtls_mpi_cmp_int( s, 1 ) < 0 )
			 {
				 if(mbedtls_mpi_cmp_mpi( s, &grp->N ) >= 0)
				 {
					 ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
					 goto cleanup;
				 }
			 }
		 }

	 }

	 /*
	  * Step 3: derive MPI from hashed message
	  */
	 result_output_fun = derive_mpi( grp, &e, buf, blen );
	 MBEDTLS_MPI_CHK(result_output_fun);

	 /*
	  * Step 4: u1 = e / s mod n, u2 = r / s mod n
	  */

	 result_output_fun = mbedtls_mpi_inv_mod( &s_inv, s, &grp->N );
	 MBEDTLS_MPI_CHK(result_output_fun);

	 result_output_fun = mbedtls_mpi_mul_mpi( pu1, &e, &s_inv );
	 MBEDTLS_MPI_CHK(result_output_fun);

	 result_output_fun =  mbedtls_mpi_mod_mpi( pu1, pu1, &grp->N ) ;
	 MBEDTLS_MPI_CHK(result_output_fun);

	 result_output_fun = mbedtls_mpi_mul_mpi( pu2, r, &s_inv ) ;
	 MBEDTLS_MPI_CHK(result_output_fun);

	 result_output_fun = mbedtls_mpi_mod_mpi( pu2, pu2, &grp->N ) ;
	 MBEDTLS_MPI_CHK(result_output_fun);

	 /*
	  * Step 5: R = u1 G + u2 Q
	  */
	 result_output_fun = mbedtls_ecp_muladd_restartable( grp,
			 &R, pu1, &grp->G, pu2, Q, ECDSA_RS_ECP );
	 MBEDTLS_MPI_CHK(result_output_fun);

	 if( mbedtls_ecp_is_zero( &R ) )
	 {
		 ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
		 goto cleanup;
	 }

	 /*
	  * Step 6: convert xR to an integer (no-op)
	  * Step 7: reduce xR mod n (gives v)
	  */
	 result_output_fun = mbedtls_mpi_mod_mpi( &R.X, &R.X, &grp->N ) ;
	 MBEDTLS_MPI_CHK(result_output_fun);

	 /*
	  * Step 8: check if v (that is, R.X) is equal to r
	  */
	 if( mbedtls_mpi_cmp_mpi( &R.X, r ) != 0 )
	 {
		 ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
		 goto cleanup;
	 }

	 cleanup:
	 mbedtls_ecp_point_free( &R );
	 mbedtls_mpi_free( &e ); mbedtls_mpi_free( &s_inv );
	 mbedtls_mpi_free( &u1 ); mbedtls_mpi_free( &u2 );

	 ECDSA_RS_LEAVE( ver );

	 return( ret );
 }

 /*
  * Verify ECDSA signature of hashed message
  */
 int mbedtls_ecdsa_verify( mbedtls_ecp_group_s *const grp,
		 const unsigned char *const buf, const size_t blen,
		 const mbedtls_ecp_point_s *const Q,
		 const mbedtls_mpi *const r,
		 const mbedtls_mpi *const s)
 {
	 ECDSA_VALIDATE_RET( grp != NULL_PTR );
	 ECDSA_VALIDATE_RET( Q   != NULL_PTR );
	 ECDSA_VALIDATE_RET( r   != NULL_PTR );
	 ECDSA_VALIDATE_RET( s   != NULL_PTR );
	 ECDSA_VALIDATE_RET( buf != NULL_PTR || blen == 0 );

	 return( ecdsa_verify_restartable( grp, buf, blen, Q, r, s, NULL_PTR ) );
 }


 /*
  * Initialize context
  */
 void mbedtls_ecdsa_init( mbedtls_ecdsa_context *const ctx )
 {
	 ECDSA_VALIDATE( ctx != NULL_PTR );

	 mbedtls_ecp_keypair_init( ctx );
 }




