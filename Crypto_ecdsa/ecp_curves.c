/*
 *  Elliptic curves over GF(p): curve-specific data and functions
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


#include "ecp.h"
#include "platform_util.h"
#include <string.h>

/* Parameter validation macros based on platform_util.h */
#define ECP_VALIDATE_RET( cond )    \
		MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECP_VALIDATE( cond )        \
		MBEDTLS_INTERNAL_VALIDATE( cond )

/*
 * Conversion macros for embedded constants:
 * build lists of mbedtls_mpi_uint's from lists of unsigned char's grouped by 8, 4 or 2
 */
#define BYTES_TO_T_UINT_4( a, b, c, d )             \
		(( (mbedtls_mpi_uint) a <<  0 ) |                          \
				( (mbedtls_mpi_uint) b <<  8 ) |                          \
				( (mbedtls_mpi_uint) c << 16 ) |                          \
				( (mbedtls_mpi_uint) d << 24 ))

#define BYTES_TO_T_UINT_2( a, b )                   \
		BYTES_TO_T_UINT_4( a, b, 0, 0 )

#define BYTES_TO_T_UINT_8( a, b, c, d, e, f, g, h ) \
		BYTES_TO_T_UINT_4( a, b, c, d ),                \
		BYTES_TO_T_UINT_4( e, f, g, h )

/*
 * Note: the constants are in little-endian order
 * to be directly usable in MPIs
 */

/*============================================================================*
 * STATIC FUNCTIONS DECLARATION
\*============================================================================*/

static void ecp_mpi_load( mbedtls_mpi *const X, const mbedtls_mpi_uint *const p, const size_t len );

static void ecp_mpi_set1( mbedtls_mpi *const X );

static int ecp_group_load( mbedtls_ecp_group_s *const grp,
		const mbedtls_mpi_uint *const p, const size_t plen,
		const mbedtls_mpi_uint *const a,const size_t alen,
		const mbedtls_mpi_uint *const b,const size_t blen,
		const mbedtls_mpi_uint *const gx,const size_t gxlen,
		const mbedtls_mpi_uint *const gy,const size_t gylen,
		const mbedtls_mpi_uint *const n,const size_t nlen);

static int ecp_mod_p256( mbedtls_mpi *const N);

static void add32( uint32 *const dst, const uint32 src, signed char *const carry );

static void sub32( uint32 *const dst, const uint32 src, signed char *const carry );

static int fix_negative( mbedtls_mpi *const N, const signed char c, mbedtls_mpi *const C, const size_t bits );

/*
 * Create an MPI from embedded constants
 * (assumes len is an exact multiple of sizeof mbedtls_mpi_uint)
 */
 static void ecp_mpi_load( mbedtls_mpi *const X, const mbedtls_mpi_uint *const p, const size_t len )
 {
	 X->s = 1;
	 X->n = len / sizeof( mbedtls_mpi_uint );

	 X->limbsPtr = (mbedtls_mpi_uint *) p;
 }

 /*
  * Set an MPI to static value 1
  */
#define ONE_ARRAY_SIZE           1
 static void ecp_mpi_set1( mbedtls_mpi *const X )
 {
	 static mbedtls_mpi_uint one[ONE_ARRAY_SIZE] = { 1 };
	 X->s = 1;
	 X->n = 1;
	 X->limbsPtr = one;
 }

 /*
  * Make group available from embedded constants
  */
 static int ecp_group_load( mbedtls_ecp_group_s *const grp,
		 const mbedtls_mpi_uint *const p, const size_t plen,
		 const mbedtls_mpi_uint *const a,const size_t alen,
		 const mbedtls_mpi_uint *const b,const size_t blen,
		 const mbedtls_mpi_uint *const gx,const size_t gxlen,
		 const mbedtls_mpi_uint *const gy,const size_t gylen,
		 const mbedtls_mpi_uint *const n,const size_t nlen)
 {
	 ecp_mpi_load( &grp->P, p, plen );
	 if( a != NULL_PTR )
	 {
		 ecp_mpi_load( &grp->A, a, alen );
	 }
	 ecp_mpi_load( &grp->B, b, blen );
	 ecp_mpi_load( &grp->N, n, nlen );

	 ecp_mpi_load( &grp->G.X, gx, gxlen );
	 ecp_mpi_load( &grp->G.Y, gy, gylen );
	 ecp_mpi_set1( &grp->G.Z );

	 grp->pbits = mbedtls_mpi_bitlen( &grp->P );
	 grp->nbits = mbedtls_mpi_bitlen( &grp->N );

	 grp->h = 1;

	 return( 0 );
 }

#define NIST_MODP( P )      grp->modp = ecp_mod_ ## P;

#define LOAD_GROUP_A( G )   ecp_group_load( grp,            \
		G ## _p,  sizeof( G ## _p  ),   \
		G ## _a,  sizeof( G ## _a  ),   \
		G ## _b,  sizeof( G ## _b  ),   \
		G ## _gx, sizeof( G ## _gx ),   \
		G ## _gy, sizeof( G ## _gy ),   \
		G ## _n,  sizeof( G ## _n  ) )

#define LOAD_GROUP( G )     ecp_group_load( grp,            \
		G ## _p,  sizeof( G ## _p  ),   \
		NULL_PTR,     0,                    \
		G ## _b,  sizeof( G ## _b  ),   \
		G ## _gx, sizeof( G ## _gx ),   \
		G ## _gy, sizeof( G ## _gy ),   \
		G ## _n,  sizeof( G ## _n  ) )

 /*
  * Set a group using well-known domain parameters
  */
#define SECP256R1_P_ARRAY_SIZE                     8

 int mbedtls_ecp_group_load( mbedtls_ecp_group_s *const grp, const mbedtls_ecp_group_id id )
 {
	 /*
	  * Domain parameters for secp256r1
	  */

	 static const mbedtls_mpi_uint secp256r1_p[SECP256R1_P_ARRAY_SIZE] = {
			 BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
			 BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 ),
			 BYTES_TO_T_UINT_8( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ),
			 BYTES_TO_T_UINT_8( 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF ),
	 };
	 static const mbedtls_mpi_uint secp256r1_b[SECP256R1_P_ARRAY_SIZE] = {
			 BYTES_TO_T_UINT_8( 0x4B, 0x60, 0xD2, 0x27, 0x3E, 0x3C, 0xCE, 0x3B ),
			 BYTES_TO_T_UINT_8( 0xF6, 0xB0, 0x53, 0xCC, 0xB0, 0x06, 0x1D, 0x65 ),
			 BYTES_TO_T_UINT_8( 0xBC, 0x86, 0x98, 0x76, 0x55, 0xBD, 0xEB, 0xB3 ),
			 BYTES_TO_T_UINT_8( 0xE7, 0x93, 0x3A, 0xAA, 0xD8, 0x35, 0xC6, 0x5A ),
	 };
	 static const mbedtls_mpi_uint secp256r1_gx[SECP256R1_P_ARRAY_SIZE] = {
			 BYTES_TO_T_UINT_8( 0x96, 0xC2, 0x98, 0xD8, 0x45, 0x39, 0xA1, 0xF4 ),
			 BYTES_TO_T_UINT_8( 0xA0, 0x33, 0xEB, 0x2D, 0x81, 0x7D, 0x03, 0x77 ),
			 BYTES_TO_T_UINT_8( 0xF2, 0x40, 0xA4, 0x63, 0xE5, 0xE6, 0xBC, 0xF8 ),
			 BYTES_TO_T_UINT_8( 0x47, 0x42, 0x2C, 0xE1, 0xF2, 0xD1, 0x17, 0x6B ),
	 };
	 static const mbedtls_mpi_uint secp256r1_gy[SECP256R1_P_ARRAY_SIZE] = {
			 BYTES_TO_T_UINT_8( 0xF5, 0x51, 0xBF, 0x37, 0x68, 0x40, 0xB6, 0xCB ),
			 BYTES_TO_T_UINT_8( 0xCE, 0x5E, 0x31, 0x6B, 0x57, 0x33, 0xCE, 0x2B ),
			 BYTES_TO_T_UINT_8( 0x16, 0x9E, 0x0F, 0x7C, 0x4A, 0xEB, 0xE7, 0x8E ),
			 BYTES_TO_T_UINT_8( 0x9B, 0x7F, 0x1A, 0xFE, 0xE2, 0x42, 0xE3, 0x4F ),
	 };
	 static const mbedtls_mpi_uint secp256r1_n[SECP256R1_P_ARRAY_SIZE] = {
			 BYTES_TO_T_UINT_8( 0x51, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3 ),
			 BYTES_TO_T_UINT_8( 0x84, 0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC ),
			 BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
			 BYTES_TO_T_UINT_8( 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF ),
	 };

	 ECP_VALIDATE_RET( grp != NULL_PTR );
	 mbedtls_ecp_group_free( grp );

	 grp->id = id;

	 switch( id )
	 {
	 case MBEDTLS_ECP_DP_SECP256R1:

		 NIST_MODP( p256 )
		 return( LOAD_GROUP( secp256r1 ) );

	 default:
		 mbedtls_ecp_group_free( grp );
		 return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
	 }
 }

 /*
  * Fast reduction modulo the primes used by the NIST curves.
  *
  * These functions are critical for speed, but not needed for correct
  * operations. So, we make the choice to heavily rely on the internals of our
  * bignum library, which creates a tight coupling between these functions and
  * our MPI implementation.  However, the coupling between the ECP module and
  * MPI remains loose, since these functions can be deactivated at will.
  */

 /*
  * The reader is advised to first understand ecp_mod_p192() since the same
  * general structure is used here, but with additional complications:
  * (1) chunks of 32 bits, and (2) subtractions.
  */

 /*
  * For these primes, we need to handle data in chunks of 32 bits.
  * This makes it more complicated if we use 64 bits limbs in MPI,
  * which prevents us from using a uniform access method as for p192.
  *
  * So, we define a mini abstraction layer to access 32 bit chunks,
  * load them in 'cur' for work, and store them back from 'cur' when done.
  *
  * While at it, also define the size of N in terms of 32-bit chunks.
  */
#define LOAD32      cur = A( i );

#define MAX32       N->n
#define A( j )      N->limbsPtr[j]
#define STORE32     N->limbsPtr[i] = cur;



 /*
  * Helpers for addition and subtraction of chunks, with signed carry.
  */
 static void add32( uint32 *const dst, const uint32 src, signed char *const carry )
 {
	 *dst += src;

	 *carry += ( *dst < src );
 }

 static void sub32( uint32 *const dst, const uint32 src, signed char *const carry )
 {

	 *carry -= ( *dst < src );
	 *dst -= src;
 }

#define ADD( j )    add32( &cur, A( j ), &c )
#define SUB( j )    sub32( &cur, A( j ), &c )

 /*
  * Helpers for the main 'loop'
  * (see fix_negative for the motivation of C)
  */
#define INIT( b )                                           \
		int ret;                                                \
		signed char c = 0, cc;                                  \
		uint32 cur;                                           \
		size_t i = 0;                                 \
		const size_t bits = b;                                        \
		mbedtls_mpi C;                                                  \
		mbedtls_mpi_uint Cp[ b / 8 / sizeof( mbedtls_mpi_uint) + 1 ];               \
		C.s = 1;                                                \
		C.n = b / 8 / sizeof( mbedtls_mpi_uint) + 1;                      \
		C.limbsPtr = Cp;                                               \
		memset( Cp, 0, C.n * sizeof( mbedtls_mpi_uint ) );                \
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow( N, b * 2 / 8 / sizeof( mbedtls_mpi_uint ) ) ); \
		LOAD32;

#define NEXT                    \
		STORE32; i++; LOAD32;       \
		cc = c; c = 0;              \
		if( cc < 0 )                \
		{sub32( &cur, -cc, &c );} \
		else                        \
		{add32( &cur, cc, &c );}  \

#define LAST                                    \
		STORE32; i++;                               \
		cur = (c > 0) ? c : 0; STORE32;               \
		cur = 0; while( ++i < MAX32 ) { STORE32; }  \
		if( c < 0 ) {fix_negative( N, c, &C, bits );}

 /*
  * If the result is negative, we get it in the form
  * c * 2^(bits + 32) + N, with c negative and N positive shorter than 'bits'
  */

 static int fix_negative( mbedtls_mpi *const N, const signed char c, mbedtls_mpi *const C, const size_t bits )
 {
	 int ret;
	 sint32 result;
	 /* C = - c * 2^(bits + 32) */

	 C->limbsPtr[ C->n - 1 ] = (mbedtls_mpi_uint) -c;

	 /* N = - ( C - N ) */
	 result = mbedtls_mpi_sub_abs( N, C, N );
	 MBEDTLS_MPI_CHK(result);
	 N->s = -1;

	 cleanup:

	 return( ret );
 }

 /*
  * Fast quasi-reduction modulo p256 (FIPS 186-3 D.2.3)
  */
#define INIT_ARRAY_SIZE               256
 static int ecp_mod_p256( mbedtls_mpi *const N )
 {

	 INIT( INIT_ARRAY_SIZE )

    		ADD(  8 ); ADD(  9 );
	 SUB( 11 ); SUB( 12 ); SUB( 13 ); SUB( 14 );             NEXT /* A0 */

	 ADD(  9 ); ADD( 10 );
	 SUB( 12 ); SUB( 13 ); SUB( 14 ); SUB( 15 );             NEXT /* A1 */

	 ADD( 10 ); ADD( 11 );
	 SUB( 13 ); SUB( 14 ); SUB( 15 );                        NEXT /* A2 */

	 ADD( 11 ); ADD( 11 ); ADD( 12 ); ADD( 12 ); ADD( 13 );
	 SUB( 15 ); SUB(  8 ); SUB(  9 );                        NEXT /* A3 */

	 ADD( 12 ); ADD( 12 ); ADD( 13 ); ADD( 13 ); ADD( 14 );
	 SUB(  9 ); SUB( 10 );                                   NEXT /* A4 */

	 ADD( 13 ); ADD( 13 ); ADD( 14 ); ADD( 14 ); ADD( 15 );
	 SUB( 10 ); SUB( 11 );                                   NEXT /* A5 */

	 ADD( 14 ); ADD( 14 ); ADD( 15 ); ADD( 15 ); ADD( 14 ); ADD( 13 );
	 SUB(  8 ); SUB(  9 );                                   NEXT /* A6 */

	 ADD( 15 ); ADD( 15 ); ADD( 15 ); ADD( 8 );
	 SUB( 10 ); SUB( 11 ); SUB( 12 ); SUB( 13 );             LAST /* A7 */

	 cleanup:
	 return( ret );
 }



