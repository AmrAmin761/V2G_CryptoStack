/*
 *  Elliptic curves over GF(p): generic functions
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
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * GECC = Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
 * FIPS 186-3 http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
 * RFC 4492 for the related TLS structures and constants
 * RFC 7748 for the Curve448 and Curve25519 curve definitions
 *
 * [Curve25519] http://cr.yp.to/ecdh/curve25519-20060209.pdf
 *
 * [2] CORON, Jean-S'ebastien. Resistance against differential power analysis
 *     for elliptic curve cryptosystems. In : Cryptographic Hardware and
 *     Embedded Systems. Springer Berlin Heidelberg, 1999. p. 292-302.
 *     <http://link.springer.com/chapter/10.1007/3-540-48059-5_25>
 *
 * [3] HEDABOU, Mustapha, PINEL, Pierre, et B'EN'ETEAU, Lucien. A comb method to
 *     render ECC resistant against Side Channel Attacks. IACR Cryptology
 *     ePrint Archive, 2004, vol. 2004, p. 342.
 *     <http://eprint.iacr.org/2004/342.pdf>
 */

/**
 * \brief Function level alternative implementation.
 *
 * The MBEDTLS_ECP_INTERNAL_ALT macro enables alternative implementations to
 * replace certain functions in this module. The alternative implementations are
 * typically hardware accelerators and need to activate the hardware before the
 * computation starts and deactivate it after it finishes. The
 * mbedtls_internal_ecp_init() and mbedtls_internal_ecp_free() functions serve
 * this purpose.
 *
 * To preserve the correct functionality the following conditions must hold:
 *
 * - The alternative implementation must be activated by
 *   mbedtls_internal_ecp_init() before any of the replaceable functions is
 *   called.
 * - mbedtls_internal_ecp_free() must \b only be called when the alternative
 *   implementation is activated.
 * - mbedtls_internal_ecp_init() must \b not be called when the alternative
 *   implementation is activated.
 * - Public functions must not return while the alternative implementation is
 *   activated.
 * - Replaceable functions are guarded by \c MBEDTLS_ECP_XXX_ALT macros and
 *   before calling them an \code if( mbedtls_internal_ecp_grp_capable( grp ) )
 *   \endcode ensures that the alternative implementation supports the current
 *   group.
 */

#include "ecp.h"
#include "platform_util.h"
#include "memory_buffer_alloc.h"
#include <string.h>

/* Parameter validation macros based on platform_util.h */
#define ECP_VALIDATE_RET( cond )    \
		MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECP_VALIDATE( cond )        \
		MBEDTLS_INTERNAL_VALIDATE( cond )

#include "ecp_internal.h"

/* d = ceil( n / w ) */
#define COMB_MAX_D      (( MBEDTLS_ECP_MAX_BITS + 1 ) / 2)
/*
 * Curve types: internal for now, might be exposed later
 */
typedef enum
{
	ECP_TYPE_NONE = 0,
	ECP_TYPE_SHORT_WEIERSTRASS,    /* y^2 = x^3 + a x + b      */
	ECP_TYPE_MONTGOMERY           /* y^2 = x^3 + a x^2 + x    */
} ecp_curve_type;


static int ecp_add_mixed( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_ecp_point_s *const P, const mbedtls_ecp_point_s *const Q );

static int ecp_randomize_jac( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const pt,
		sint32 (* const f_rng)(void *, uint8 * , uint32 ), void *const p_rng );

static ecp_curve_type ecp_get_type( const mbedtls_ecp_group_s *const grp );

static int ecp_modp( mbedtls_mpi *const N, const mbedtls_ecp_group_s *const grp );

static int ecp_safe_invert_jac( const mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s *const Q,
		const unsigned char inv );

static int ecp_double_jac( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_ecp_point_s *const P );

static int ecp_normalize_jac( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const pt );

static int ecp_normalize_jac_many( const mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s *const T[], const size_t T_size );

static void ecp_comb_recode_core( unsigned char x[], const size_t d,
		const unsigned char w, const mbedtls_mpi *const m );

static int ecp_precompute_comb( const mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s T[], const mbedtls_ecp_point_s *const P,
		const unsigned char w, const size_t d,
		const mbedtls_ecp_restart_ctx *const rs_ctx );

static int ecp_select_comb( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_ecp_point_s T[], const unsigned char T_size,
		const unsigned char i );

static int ecp_mul_comb_core( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_ecp_point_s T[], const unsigned char T_size,
		const unsigned char x[], const size_t d,
		sint32 (* const f_rng)(void * , uint8 * , uint32),
		void *const p_rng,
		const mbedtls_ecp_restart_ctx *const rs_ctx );

static int ecp_comb_recode_scalar( const mbedtls_ecp_group_s *const grp,
		const mbedtls_mpi *const m,
		unsigned char k[COMB_MAX_D + 1],
		const size_t d,
		const unsigned char w,
		unsigned char *const parity_trick );


static int ecp_mul_comb_after_precomp( const mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s *const R,
		const mbedtls_mpi *const m,
		const mbedtls_ecp_point_s *const T,
		const unsigned char T_size,
		const unsigned char w,
		const size_t d,
		sint32 (* const f_rng)(void * , uint8 * , uint32),
		void *const p_rng,
		const mbedtls_ecp_restart_ctx *const rs_ctx );


static unsigned char ecp_pick_window_size( const mbedtls_ecp_group_s *const grp,
		const unsigned char p_eq_g );


static int ecp_mul_comb( mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_mpi *const m, const mbedtls_ecp_point_s *const P,
		sint32 (* const f_rng)(void * , uint8 * , uint32),
		void *const p_rng,
		const mbedtls_ecp_restart_ctx *const rs_ctx );


static int ecp_check_pubkey_sw( const mbedtls_ecp_group_s *const grp, const mbedtls_ecp_point_s *const pt );

static int mbedtls_ecp_mul_shortcuts( mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s *const R,
		const mbedtls_mpi *const m,
		const mbedtls_ecp_point_s *const P,
		const mbedtls_ecp_restart_ctx *const rs_ctx );

/*
 * List of supported curves:
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 4492 sec. 5.1.1, RFC 7071 sec. 2)
 *  - size in bits
 *  - readable name
 *
 * Curves are listed in order: largest curves first, and for a given size,
 * fastest curves first. This provides the default order for the SSL module.
 *
 * Reminder: update profiles in x509_crt.c when adding a new curves!
 */
#define ECP_SUPPORTED_CURVES_ARRAY_SIZE         12
static const mbedtls_ecp_curve_info_s ecp_supported_curves[ECP_SUPPORTED_CURVES_ARRAY_SIZE] =
{
		{ MBEDTLS_ECP_DP_SECP521R1,    25,     521,    "secp521r1"         },

		{ MBEDTLS_ECP_DP_BP512R1,      28,     512,    "brainpoolP512r1"   },

		{ MBEDTLS_ECP_DP_SECP384R1,    24,     384,    "secp384r1"         },

		{ MBEDTLS_ECP_DP_BP384R1,      27,     384,    "brainpoolP384r1"   },

		{ MBEDTLS_ECP_DP_SECP256R1,    23,     256,    "secp256r1"         },

		{ MBEDTLS_ECP_DP_SECP256K1,    22,     256,    "secp256k1"         },

		{ MBEDTLS_ECP_DP_BP256R1,      26,     256,    "brainpoolP256r1"   },

		{ MBEDTLS_ECP_DP_SECP224R1,    21,     224,    "secp224r1"         },

		{ MBEDTLS_ECP_DP_SECP224K1,    20,     224,    "secp224k1"         },

		{ MBEDTLS_ECP_DP_SECP192R1,    19,     192,    "secp192r1"         },

		{ MBEDTLS_ECP_DP_SECP192K1,    18,     192,    "secp192k1"         },

		{ MBEDTLS_ECP_DP_NONE,          0,     0,      NULL_PTR                },
};

#define ECP_NB_CURVES   (sizeof( ecp_supported_curves ) /    \
		sizeof( ecp_supported_curves[0] ))

/*
 * List of supported curves and associated info
 */
const mbedtls_ecp_curve_info_s *mbedtls_ecp_curve_list( void )
{
	return( ecp_supported_curves );
}

/*
 * List of supported curves, group ID only
 */
const mbedtls_ecp_group_id *mbedtls_ecp_grp_id_list( void )
{
	static int init_done = 0;
	static mbedtls_ecp_group_id ecp_supported_grp_id[ECP_NB_CURVES];


	if( ! init_done )
	{
		size_t i = 0;
		const mbedtls_ecp_curve_info_s *curve_info;

		for( curve_info = mbedtls_ecp_curve_list();
				curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
				curve_info++ )
		{
			ecp_supported_grp_id[i] = curve_info->grp_id;
			i++;
		}
		ecp_supported_grp_id[i] = MBEDTLS_ECP_DP_NONE;

		init_done = 1;
	}

	return( ecp_supported_grp_id );
}

/*
 * Get the curve info for the internal identifier
 */
const mbedtls_ecp_curve_info_s *mbedtls_ecp_curve_info_from_grp_id( const mbedtls_ecp_group_id grp_id )
{
	const mbedtls_ecp_curve_info_s *curve_info;

	for( curve_info = mbedtls_ecp_curve_list();
			curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
			curve_info++ )
	{
		if( curve_info->grp_id == grp_id )
		{
			return( curve_info );
		}
	}

	return( NULL_PTR );
}

/*
 * Get the curve info from the TLS identifier
 */
const mbedtls_ecp_curve_info_s *mbedtls_ecp_curve_info_from_tls_id( const uint16 tls_id )
{
	const mbedtls_ecp_curve_info_s *curve_info;

	for( curve_info = mbedtls_ecp_curve_list();
			curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
			curve_info++ )
	{

		if( curve_info->tls_id == tls_id )
		{
			return( curve_info );
		}
	}

	return( NULL_PTR );
}


/*
 * Initialize (the components of) a point
 */
void mbedtls_ecp_point_init( mbedtls_ecp_point_s *const pt )
{
	ECP_VALIDATE( pt != NULL_PTR );

	mbedtls_mpi_init( &pt->X );
	mbedtls_mpi_init( &pt->Y );
	mbedtls_mpi_init( &pt->Z );
}

/*
 * Get the type of a curve
 */
static ecp_curve_type ecp_get_type( const mbedtls_ecp_group_s *const grp )
{
	if( grp->G.X.limbsPtr == NULL_PTR )
	{
		return( ECP_TYPE_NONE );
	}

	if( grp->G.Y.limbsPtr == NULL_PTR )
	{
		return( ECP_TYPE_MONTGOMERY );
	}
	else
	{
		return( ECP_TYPE_SHORT_WEIERSTRASS );
	}
}

/*
 * Initialize (the components of) a group
 */
void mbedtls_ecp_group_init( mbedtls_ecp_group_s *const grp )
{
	ECP_VALIDATE( grp != NULL_PTR );

	grp->id = MBEDTLS_ECP_DP_NONE;
	mbedtls_mpi_init( &grp->P );
	mbedtls_mpi_init( &grp->A );
	mbedtls_mpi_init( &grp->B );
	mbedtls_ecp_point_init( &grp->G );
	mbedtls_mpi_init( &grp->N );
	grp->pbits = 0;
	grp->nbits = 0;
	grp->h = 0;
	grp->modp = NULL_PTR;
	grp->t_pre = NULL_PTR;
	grp->t_post = NULL_PTR;
	grp->t_data = NULL_PTR;
	grp->T = NULL_PTR;
	grp->T_size = 0;
}

/*
 * Initialize (the components of) a key pair
 */
void mbedtls_ecp_keypair_init( mbedtls_ecp_keypair_s *const key )
{
	ECP_VALIDATE( key != NULL_PTR );

	mbedtls_ecp_group_init( &key->grp );
	mbedtls_mpi_init( &key->d );
	mbedtls_ecp_point_init( &key->Q );
}

/*
 * Unallocate (the components of) a group
 */
void mbedtls_ecp_group_free( mbedtls_ecp_group_s *const grp )
{
	size_t i;

	if( grp == NULL_PTR )
	{
		return;
	}

	if( grp->h != (unsigned int)1 )
	{
		mbedtls_mpi_free( &grp->P );
		mbedtls_mpi_free( &grp->A );
		mbedtls_mpi_free( &grp->B );
		mbedtls_ecp_point_free( &grp->G );
		mbedtls_mpi_free( &grp->N );
	}

	if( grp->T != NULL_PTR )
	{
		for( i = 0; i < grp->T_size; i++ )
		{
			mbedtls_ecp_point_free( &grp->T[i] );
		}
		buffer_alloc_free( grp->T );
	}

	mbedtls_platform_zeroize( grp, sizeof( mbedtls_ecp_group_s ) );
}


/*
 * Unallocate (the components of) a point
 */
void mbedtls_ecp_point_free( mbedtls_ecp_point_s *const pt )
{
	if( pt == NULL_PTR )
	{
		return;
	}

	mbedtls_mpi_free( &( pt->X ) );
	mbedtls_mpi_free( &( pt->Y ) );
	mbedtls_mpi_free( &( pt->Z ) );
}

/*
 * Unallocate (the components of) a key pair
 */
void mbedtls_ecp_keypair_free( mbedtls_ecp_keypair_s *const key )
{
	if( key == NULL_PTR )
	{
		return;
	}

	mbedtls_ecp_group_free( &key->grp );
	mbedtls_mpi_free( &key->d );
	mbedtls_ecp_point_free( &key->Q );
}

/*
 * Copy the contents of a point
 */
int mbedtls_ecp_copy( mbedtls_ecp_point_s *const P, const mbedtls_ecp_point_s *const Q )
{
	int ret;
	sint32 result_output_fun;
	ECP_VALIDATE_RET( P != NULL_PTR );
	ECP_VALIDATE_RET( Q != NULL_PTR );

	result_output_fun = mbedtls_mpi_copy( &P->X, &Q->X );
	MBEDTLS_MPI_CHK(result_output_fun);

	result_output_fun = mbedtls_mpi_copy( &P->Y, &Q->Y );
	MBEDTLS_MPI_CHK(result_output_fun);

	result_output_fun = mbedtls_mpi_copy( &P->Z, &Q->Z );
	MBEDTLS_MPI_CHK(result_output_fun);

	cleanup:
	return( ret );
}

/*
 * Copy the contents of a group object
 */
int mbedtls_ecp_group_copy( mbedtls_ecp_group_s *const dst, const mbedtls_ecp_group_s *const src )
{
	ECP_VALIDATE_RET( dst != NULL_PTR );
	ECP_VALIDATE_RET( src != NULL_PTR );

	return( mbedtls_ecp_group_load( dst, src->id ) );
}

/*
 * Set point to zero
 */
int mbedtls_ecp_set_zero( mbedtls_ecp_point_s *const pt )
{
	int ret;
	sint32 result;
	ECP_VALIDATE_RET( pt != NULL_PTR );

	result = mbedtls_mpi_lset( &pt->X , 1 ) ;
	MBEDTLS_MPI_CHK(result);

	result = mbedtls_mpi_lset( &pt->Y , 1 );
	MBEDTLS_MPI_CHK(result);

	result = mbedtls_mpi_lset( &pt->Z , 0 );
	MBEDTLS_MPI_CHK(result);

	cleanup:
	return( ret );
}

/*
 * Tell if a point is zero
 */
int mbedtls_ecp_is_zero( const mbedtls_ecp_point_s *const pt )
{
	ECP_VALIDATE_RET( pt != NULL_PTR );

	return( mbedtls_mpi_cmp_int( &pt->Z, 0 ) == (sint32)0 );
}

/*
 * Compare two points lazily
 */
int mbedtls_ecp_point_cmp( const mbedtls_ecp_point_s *const P,
		const mbedtls_ecp_point_s *const Q )
{
	ECP_VALIDATE_RET( P != NULL_PTR );
	ECP_VALIDATE_RET( Q != NULL_PTR );

	if(mbedtls_mpi_cmp_mpi( &P->X, &Q->X ) == (sint32)0)
	{
		if(mbedtls_mpi_cmp_mpi( &P->Y, &Q->Y ) == (sint32)0)
		{
			if(mbedtls_mpi_cmp_mpi( &P->Z, &Q->Z ) == (sint32)0)
			{
				return( 0 );
			}
		}
	}
	return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
}


/*
 * Export a point into unsigned binary data (SEC1 2.3.3)
 */
int mbedtls_ecp_point_write_binary( const mbedtls_ecp_group_s *const grp,
		const mbedtls_ecp_point_s *const P,
		const int format,  size_t *const olen,
		unsigned char *const buf,const size_t buflen )
{
	int ret = 0;
	sint32 result;
	size_t plen;
	ECP_VALIDATE_RET( grp  != NULL_PTR );
	ECP_VALIDATE_RET( P    != NULL_PTR );
	ECP_VALIDATE_RET( olen != NULL_PTR );
	ECP_VALIDATE_RET( buf  != NULL_PTR );
	ECP_VALIDATE_RET( format == MBEDTLS_ECP_PF_UNCOMPRESSED ||
			format == MBEDTLS_ECP_PF_COMPRESSED );

	/*
	 * Common case: P == 0
	 */
	if( mbedtls_mpi_cmp_int( &P->Z, 0 ) == (sint32)0 )
	{
		if( buflen < (size_t)1 )
		{
			return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );
		}

		buf[0] = 0x00;
		*olen = 1;

		return( 0 );
	}

	plen = mbedtls_mpi_size( &grp->P );

	if( format == MBEDTLS_ECP_PF_UNCOMPRESSED )
	{
		*olen = ((size_t)2 * plen) + (size_t)1;

		if( buflen < *olen )
		{
			return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );
		}

		buf[0] = 0x04;
		result = mbedtls_mpi_write_binary( &P->X, buf + 1, plen );
		MBEDTLS_MPI_CHK(result);

		result =  mbedtls_mpi_write_binary( &P->Y, buf + 1 + plen, plen ) ;
		MBEDTLS_MPI_CHK(result);
	}

	else if( format == MBEDTLS_ECP_PF_COMPRESSED )
	{
		*olen = plen + (size_t)1;

		if( buflen < *olen )
		{
			return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );
		}

		buf[0] = (unsigned char)((uint32)0x02 + mbedtls_mpi_get_bit( &P->Y, 0 ));

		result = mbedtls_mpi_write_binary( &P->X, buf + 1, plen ) ;
		MBEDTLS_MPI_CHK(result);
	}
	else
	{
		/* No action required */
	}
	cleanup:
	return( ret );
}

/*
 * Import a point from unsigned binary data (SEC1 2.3.4)
 */
int mbedtls_ecp_point_read_binary( const mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s *const pt,
		const unsigned char *const buf,const size_t ilen )
{
	int ret;
	sint32 result_output_fun ;
	size_t plen;
	ECP_VALIDATE_RET( grp != NULL_PTR );
	ECP_VALIDATE_RET( pt  != NULL_PTR );
	ECP_VALIDATE_RET( buf != NULL_PTR );

	if( ilen < (size_t)1 )
	{
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	if(buf[0] == 0x00 )
	{
		if( ilen == (size_t)1 )
		{
			return( mbedtls_ecp_set_zero( pt ) );
		}
		else
		{
			return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
		}
	}

	plen = mbedtls_mpi_size( &grp->P );

	if( buf[0] != 0x04 )
	{
		return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
	}

	if( ilen != (((size_t)2 * plen) +(size_t)1 ))
	{
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	result_output_fun = mbedtls_mpi_read_binary( &pt->X, buf + 1, plen );
	MBEDTLS_MPI_CHK(result_output_fun);

	result_output_fun = mbedtls_mpi_read_binary( &pt->Y, buf + 1 + plen, plen );
	MBEDTLS_MPI_CHK(result_output_fun);

	result_output_fun = mbedtls_mpi_lset( &pt->Z, 1 );
	MBEDTLS_MPI_CHK(result_output_fun);

	cleanup:
	return( ret );
}

/*
 * Import a point from a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int mbedtls_ecp_tls_read_point( const mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s *const pt,
		const unsigned char **const buf, const size_t buf_len )
{
	unsigned char data_len;
	const unsigned char *buf_start;
	ECP_VALIDATE_RET( grp != NULL_PTR );
	ECP_VALIDATE_RET( pt  != NULL_PTR );
	ECP_VALIDATE_RET( buf != NULL_PTR );
	ECP_VALIDATE_RET( *buf != NULL_PTR );

	/*
	 * We must have at least two bytes (1 for length, at least one for data)
	 */
	if( buf_len < (size_t)2 )
	{
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	data_len = *(*buf)++;

	if( data_len < (unsigned char)1)
	{
		if( data_len > (buf_len - (unsigned char)1) )
		{
			return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
		}
	}

	/*
	 * Save buffer start for read_binary and update buf
	 */
	buf_start = *buf;
	*buf += data_len;

	return( mbedtls_ecp_point_read_binary( grp, pt, buf_start, data_len ) );
}

/*
 * Export a point as a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int mbedtls_ecp_tls_write_point( const mbedtls_ecp_group_s *const grp, const mbedtls_ecp_point_s *const pt,
		const int format, size_t *const olen,
		unsigned char *const buf, const size_t blen )
{
	int ret;
	ECP_VALIDATE_RET( grp  != NULL_PTR );
	ECP_VALIDATE_RET( pt   != NULL_PTR );
	ECP_VALIDATE_RET( olen != NULL_PTR );
	ECP_VALIDATE_RET( buf  != NULL_PTR );
	ECP_VALIDATE_RET( format == MBEDTLS_ECP_PF_UNCOMPRESSED ||
			format == MBEDTLS_ECP_PF_COMPRESSED );

	/*
	 * buffer length must be at least one, for our length byte
	 */
	if( blen < (size_t)1 )
	{
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	ret = mbedtls_ecp_point_write_binary( grp, pt, format,olen, buf + 1, blen - 1) ;

	if(ret != 0 )
	{
		return( ret );
	}

	/*
	 * write length to the first byte and update total length
	 */
	buf[0] = (unsigned char) *olen;
	++*olen;

	return( 0 );
}

/*
 * Set a group from an ECParameters record (RFC 4492)
 */

int mbedtls_ecp_tls_read_group( mbedtls_ecp_group_s *const grp,
		const unsigned char **const buf, const size_t len )
{
	int ret;
	mbedtls_ecp_group_id grp_id;
	ECP_VALIDATE_RET( grp  != NULL_PTR );
	ECP_VALIDATE_RET( buf  != NULL_PTR );
	ECP_VALIDATE_RET( *buf != NULL_PTR );

	ret = mbedtls_ecp_tls_read_group_id( &grp_id, buf, len );
	if( ret != 0 )
	{
		return( ret );
	}

	return( mbedtls_ecp_group_load( grp, grp_id ) );
}

/*
 * Read a group id from an ECParameters record (RFC 4492) and convert it to
 * mbedtls_ecp_group_id.
 */

int mbedtls_ecp_tls_read_group_id( mbedtls_ecp_group_id *const grp,
		const unsigned char **const buf, const size_t len )
{
	uint16 tls_id;
	const mbedtls_ecp_curve_info_s *curve_info;
	ECP_VALIDATE_RET( grp  != NULL_PTR );
	ECP_VALIDATE_RET( buf  != NULL_PTR );
	ECP_VALIDATE_RET( *buf != NULL_PTR );

	/*
	 * We expect at least three bytes (see below)
	 */
	if( len < (size_t)3 )
	{
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	/*
	 * First byte is curve_type; only named_curve is handled
	 */

	if( *(*buf)++ != MBEDTLS_ECP_TLS_NAMED_CURVE )
	{
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	/*
	 * Next two bytes are the namedcurve value
	 */

	tls_id = *(*buf)++;
	tls_id <<= 8;
	tls_id |= *(*buf)++;

	curve_info = mbedtls_ecp_curve_info_from_tls_id( tls_id ) ;
	if( curve_info == NULL_PTR )
	{
		return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
	}

	*grp = curve_info->grp_id;

	return( 0 );
}

/*
 * Write the ECParameters record corresponding to a group (RFC 4492)
 */
int mbedtls_ecp_tls_write_group( const mbedtls_ecp_group_s *const grp, size_t *const olen,
		unsigned char *buf, const size_t blen )
{
	const mbedtls_ecp_curve_info_s *curve_info;
	ECP_VALIDATE_RET( grp  != NULL_PTR );
	ECP_VALIDATE_RET( buf  != NULL_PTR );
	ECP_VALIDATE_RET( olen != NULL_PTR );

	if( ( curve_info = mbedtls_ecp_curve_info_from_grp_id( grp->id ) ) == NULL_PTR )
	{
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	/*
	 * We are going to write 3 bytes (see below)
	 */
	*olen = 3;
	if( blen < *olen )
	{
		return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );
	}

	/*
	 * First byte is curve_type, always named_curve
	 */

	*buf++ = MBEDTLS_ECP_TLS_NAMED_CURVE;

	/*
	 * Next two bytes are the namedcurve value
	 */

	buf[0] = curve_info->tls_id >> (unsigned char)8;
	buf[1] = curve_info->tls_id & (unsigned char)0xFF;

	return( 0 );
}

/*
 * Wrapper around fast quasi-modp functions, with fall-back to mbedtls_mpi_mod_mpi.
 * See the documentation of struct mbedtls_ecp_group_s.
 *
 * This function is in the critial loop for mbedtls_ecp_mul, so pay attention to perf.
 */
static int ecp_modp( mbedtls_mpi *const N, const mbedtls_ecp_group_s *const grp )
{
	int ret;
	sint32 result_output_fun ;
	if( grp->modp == NULL_PTR )
	{
		return( mbedtls_mpi_mod_mpi( N, N, &grp->P ) );
	}

	/* N->s < 0 is a much faster test, which fails only if N is 0 */
	if((((N->s) < 0) && ((mbedtls_mpi_cmp_int( N, 0 )) != 0 )) ||
			((mbedtls_mpi_bitlen( N )) > (2 * grp->pbits )))
	{
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	MBEDTLS_MPI_CHK( grp->modp( N ) );

	/* N->s < 0 is a much faster test, which fails only if N is 0 */
	while( ((N->s < 0) && (mbedtls_mpi_cmp_int( N, 0 ))) != 0 )
	{
		result_output_fun =  mbedtls_mpi_add_mpi( N, N, &grp->P ) ;
		MBEDTLS_MPI_CHK(result_output_fun);
	}

	while( mbedtls_mpi_cmp_mpi( N, &grp->P ) >= 0 )
	{
		/* we known P, N and the result are positive */
		result_output_fun = mbedtls_mpi_sub_abs( N, N, &grp->P );
		MBEDTLS_MPI_CHK(result_output_fun);
	}

	cleanup:
	return( ret );
}

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * mbedtls_mpi_mul_mpi are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a mbedtls_mpi mod p in-place, general case, to use after mbedtls_mpi_mul_mpi
 */

#define INC_MUL_COUNT


#define MOD_MUL( N )    do { MBEDTLS_MPI_CHK( ecp_modp( &N, grp ) ); INC_MUL_COUNT } \
		while( 0 )

/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */

#define MOD_SUB( N )                                \
		while( ((N.s < 0) && (mbedtls_mpi_cmp_int( &N, 0 ))) != 0 )   \
		{MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &N, &N, &grp->P ) ); }

/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_add_mpi and mbedtls_mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD( N )                                \
		while( mbedtls_mpi_cmp_mpi( &N, &grp->P ) >= 0 )        \
		{MBEDTLS_MPI_CHK(mbedtls_mpi_sub_abs( &N, &N, &grp->P ));}


/*
 * For curves in short Weierstrass form, we do all the internal operations in
 * Jacobian coordinates.
 *
 * For multiplication, we'll use a comb method with coutermeasueres against
 * SPA, hence timing attacks.
 */

/*
 * Normalize jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
 */

static int ecp_normalize_jac( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const pt )
{
	int ret;
	sint32 result;
	mbedtls_mpi Zi, ZZi;

	if( mbedtls_mpi_cmp_int( &pt->Z, 0 ) == 0 )
	{
		return( 0 );
	}

	mbedtls_mpi_init( &Zi ); mbedtls_mpi_init( &ZZi );

	/*
	 * X = X / Z^2  mod p
	 */
	result = mbedtls_mpi_inv_mod( &Zi,      &pt->Z,     &grp->P );
	MBEDTLS_MPI_CHK(result);

	result = mbedtls_mpi_mul_mpi( &ZZi,     &Zi,        &Zi     ) ;
	MBEDTLS_MPI_CHK(result); MOD_MUL( ZZi );

	result = mbedtls_mpi_mul_mpi( &pt->X,   &pt->X,     &ZZi    );
	MBEDTLS_MPI_CHK(result); MOD_MUL( pt->X );

	/*
	 * Y = Y / Z^3  mod p
	 */
	result = mbedtls_mpi_mul_mpi( &pt->Y,   &pt->Y,     &ZZi    ) ;
	MBEDTLS_MPI_CHK(result); MOD_MUL( pt->Y );

	result =  mbedtls_mpi_mul_mpi( &pt->Y,   &pt->Y,     &Zi     );
	MBEDTLS_MPI_CHK(result); MOD_MUL( pt->Y );

	/*
	 * Z = 1
	 */
	result = mbedtls_mpi_lset( &pt->Z, 1 );
	MBEDTLS_MPI_CHK(result);

	cleanup:

	mbedtls_mpi_free( &Zi ); mbedtls_mpi_free( &ZZi );

	return( ret );
}

/*
 * Normalize jacobian coordinates of an array of (pointers to) points,
 * using Montgomery's trick to perform only one inversion mod P.
 * (See for example Cohen's "A Course in Computational Algebraic Number
 * Theory", Algorithm 10.3.4.)
 *
 * Warning: fails (returning an error) if one of the points is zero!
 * This should never happen, see choice of w in ecp_mul_comb().
 *
 * Cost: 1N(t) := 1I + (6t - 3)M + 1S
 */

static int ecp_normalize_jac_many( const mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s *const T[], const size_t T_size )
{
	int ret;
	sint32 result_output_fun ;
	size_t i;
	mbedtls_mpi *c, u, Zi, ZZi;

	if( T_size < 2 )
	{
		return( ecp_normalize_jac( grp, *T ) );
	}

	if( ( c = buffer_alloc_calloc( T_size, sizeof( mbedtls_mpi ) ) ) == NULL_PTR )
	{
		return( MBEDTLS_ERR_ECP_ALLOC_FAILED );
	}

	for( i = 0; i < T_size; i++ )
	{
		mbedtls_mpi_init( &c[i] );
	}

	mbedtls_mpi_init( &u ); mbedtls_mpi_init( &Zi ); mbedtls_mpi_init( &ZZi );

	/*
	 * c[i] = Z_0 * ... * Z_i
	 */
	result_output_fun = mbedtls_mpi_copy( &c[0], &T[0]->Z );
	MBEDTLS_MPI_CHK(result_output_fun);
	for( i = 1; i < T_size; i++ )
	{
		result_output_fun = mbedtls_mpi_mul_mpi( &c[i], &c[i-1], &T[i]->Z );
		MBEDTLS_MPI_CHK(result_output_fun);
		MOD_MUL( c[i] );
	}

	/*
	 * u = 1 / (Z_0 * ... * Z_n) mod P
	 */
	result_output_fun = mbedtls_mpi_inv_mod( &u, &c[T_size-1], &grp->P );
	MBEDTLS_MPI_CHK(result_output_fun);

	for( i = T_size - 1; ; i-- )
	{
		/*
		 * Zi = 1 / Z_i mod p
		 * u = 1 / (Z_0 * ... * Z_i) mod P
		 */
		if( i == 0 ) {
			result_output_fun = mbedtls_mpi_copy( &Zi, &u );
			MBEDTLS_MPI_CHK(result_output_fun);
		}
		else
		{
			result_output_fun = mbedtls_mpi_mul_mpi( &Zi, &u, &c[i-1]  );
			MBEDTLS_MPI_CHK(result_output_fun); MOD_MUL( Zi );
			result_output_fun = mbedtls_mpi_mul_mpi( &u,  &u, &T[i]->Z );
			MBEDTLS_MPI_CHK(result_output_fun); MOD_MUL( u );
		}

		/*
		 * proceed as in normalize()
		 */
		result_output_fun = mbedtls_mpi_mul_mpi( &ZZi,     &Zi,      &Zi  );
		MBEDTLS_MPI_CHK(result_output_fun); MOD_MUL( ZZi );

		result_output_fun=  mbedtls_mpi_mul_mpi( &T[i]->X, &T[i]->X, &ZZi );
		MBEDTLS_MPI_CHK(result_output_fun); MOD_MUL( T[i]->X );

		result_output_fun =  mbedtls_mpi_mul_mpi( &T[i]->Y, &T[i]->Y, &ZZi );
		MBEDTLS_MPI_CHK(result_output_fun); MOD_MUL( T[i]->Y );

		result_output_fun = mbedtls_mpi_mul_mpi( &T[i]->Y, &T[i]->Y, &Zi  );
		MBEDTLS_MPI_CHK(result_output_fun); MOD_MUL( T[i]->Y );

		/*
		 * Post-precessing: reclaim some memory by shrinking coordinates
		 * - not storing Z (always 1)
		 * - shrinking other coordinates, but still keeping the same number of
		 *   limbs as P, as otherwise it will too likely be regrown too fast.
		 */
		result_output_fun = mbedtls_mpi_shrink( &T[i]->X, grp->P.n );
		MBEDTLS_MPI_CHK(result_output_fun);

		result_output_fun = mbedtls_mpi_shrink( &T[i]->Y, grp->P.n );
		MBEDTLS_MPI_CHK(result_output_fun);

		mbedtls_mpi_free( &T[i]->Z );

		if( i == 0 )
		{
			break;
		}
	}

	cleanup:

	mbedtls_mpi_free( &u ); mbedtls_mpi_free( &Zi ); mbedtls_mpi_free( &ZZi );
	for( i = 0; i < T_size; i++ )
	{
		mbedtls_mpi_free( &c[i] );
	}
	buffer_alloc_free( c );

	return( ret );
}

/*
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid
 */

static int ecp_safe_invert_jac( const mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s *const Q,
		const unsigned char inv )
{
	int ret;
	sint32 result_output_fun ;
	unsigned char nonzero;
	mbedtls_mpi mQY;

	mbedtls_mpi_init( &mQY );

	/* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
	result_output_fun = mbedtls_mpi_sub_mpi( &mQY, &grp->P, &Q->Y );
	MBEDTLS_MPI_CHK(result_output_fun);
	nonzero = mbedtls_mpi_cmp_int( &Q->Y, 0 ) != 0;

	result_output_fun = mbedtls_mpi_safe_cond_assign( &Q->Y, &mQY, inv & nonzero );
	MBEDTLS_MPI_CHK(result_output_fun);

	cleanup:
	mbedtls_mpi_free( &mQY );

	return( ret );
}

/*
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * Based on http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2 .
 *
 * We follow the variable naming fairly closely. The formula variations that trade a MUL for a SQR
 * (plus a few ADDs) aren't useful as our bignum implementation doesn't distinguish squaring.
 *
 * Standard optimizations are applied when curve parameter A is one of { 0, -3 }.
 *
 * Cost: 1D := 3M + 4S          (A ==  0)
 *             4M + 4S          (A == -3)
 *             3M + 6S + 1a     otherwise
 */
static int ecp_double_jac( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_ecp_point_s *const P )
{
	int ret;
	sint32 result ;
	mbedtls_mpi M, S, T, U;

	mbedtls_mpi_init( &M ); mbedtls_mpi_init( &S ); mbedtls_mpi_init( &T ); mbedtls_mpi_init( &U );

	/* Special case for A = -3 */
	if( grp->A.limbsPtr == NULL_PTR )
	{
		/* M = 3(X + Z^2)(X - Z^2) */
		result = mbedtls_mpi_mul_mpi( &S,  &P->Z,  &P->Z   );
		MBEDTLS_MPI_CHK(result);
		MOD_MUL( S );

		result = mbedtls_mpi_add_mpi( &T,  &P->X,  &S      );
		MBEDTLS_MPI_CHK(result);
		MOD_ADD( T )

		result = mbedtls_mpi_sub_mpi( &U,  &P->X,  &S      );
		MBEDTLS_MPI_CHK(result);
		MOD_SUB( U )

		result = mbedtls_mpi_mul_mpi( &S,  &T,     &U      );
		MBEDTLS_MPI_CHK(result);
		MOD_MUL( S );

		result = mbedtls_mpi_mul_int( &M,  &S,     3       );
		MBEDTLS_MPI_CHK(result);
		MOD_ADD( M )
	}
	else
	{
		/* M = 3.X^2 */
		result = mbedtls_mpi_mul_mpi( &S,  &P->X,  &P->X   );
		MBEDTLS_MPI_CHK(result);
		MOD_MUL( S );

		result = mbedtls_mpi_mul_int( &M,  &S,     3       );
		MBEDTLS_MPI_CHK(result);
		MOD_ADD( M )

		/* Optimize away for "koblitz" curves with A = 0 */
		if( mbedtls_mpi_cmp_int( &grp->A, 0 ) != 0 )
		{
			/* M += A.Z^4 */
			result = mbedtls_mpi_mul_mpi( &S,  &P->Z,  &P->Z   );
			MBEDTLS_MPI_CHK(result);
			MOD_MUL( S );

			result = mbedtls_mpi_mul_mpi( &T,  &S,     &S      );
			MBEDTLS_MPI_CHK(result);
			MOD_MUL( T );

			result = mbedtls_mpi_mul_mpi( &S,  &T,     &grp->A );
			MBEDTLS_MPI_CHK(result);
			MOD_MUL( S );

			result = mbedtls_mpi_add_mpi( &M,  &M,     &S      );
			MBEDTLS_MPI_CHK(result);
			MOD_ADD( M )
		}
	}

	/* S = 4.X.Y^2 */
	result = mbedtls_mpi_mul_mpi( &T,  &P->Y,  &P->Y   );
	MBEDTLS_MPI_CHK(result);
	MOD_MUL( T );

	result = mbedtls_mpi_shift_l( &T,  1               );
	MBEDTLS_MPI_CHK(result);
	MOD_ADD( T )

	result = mbedtls_mpi_mul_mpi( &S,  &P->X,  &T      );
	MBEDTLS_MPI_CHK(result);
	MOD_MUL( S );

	result = mbedtls_mpi_shift_l( &S,  1               );
	MBEDTLS_MPI_CHK(result);
	MOD_ADD( S )

	/* U = 8.Y^4 */
	result = mbedtls_mpi_mul_mpi( &U,  &T,     &T      ) ;
	MBEDTLS_MPI_CHK(result);
	MOD_MUL( U );

	result = mbedtls_mpi_shift_l( &U,  1               );
	MBEDTLS_MPI_CHK(result);
	MOD_ADD( U )

	/* T = M^2 - 2.S */
	result = mbedtls_mpi_mul_mpi( &T,  &M,     &M      );
	MBEDTLS_MPI_CHK(result);
	MOD_MUL( T );

	result = mbedtls_mpi_sub_mpi( &T,  &T,     &S      );
	MBEDTLS_MPI_CHK(result);
	MOD_SUB( T )

	result = mbedtls_mpi_sub_mpi( &T,  &T,     &S      );
	MBEDTLS_MPI_CHK(result);
	MOD_SUB( T )

	/* S = M(S - T) - U */
	result = mbedtls_mpi_sub_mpi( &S,  &S,     &T      );
	MBEDTLS_MPI_CHK(result);
	MOD_SUB( S )

	result = mbedtls_mpi_mul_mpi( &S,  &S,     &M      );
	MBEDTLS_MPI_CHK(result);
	MOD_MUL( S );

	result = mbedtls_mpi_sub_mpi( &S,  &S,     &U      ) ;
	MBEDTLS_MPI_CHK(result);
	MOD_SUB( S )

	/* U = 2.Y.Z */
	result = mbedtls_mpi_mul_mpi( &U,  &P->Y,  &P->Z   );
	MBEDTLS_MPI_CHK(result);
	MOD_MUL( U );

	result = mbedtls_mpi_shift_l( &U,  1               );
	MBEDTLS_MPI_CHK(result);
	MOD_ADD( U )

	result = mbedtls_mpi_copy( &R->X, &T );
	MBEDTLS_MPI_CHK(result);

	result = mbedtls_mpi_copy( &R->Y, &S );
	MBEDTLS_MPI_CHK(result);

	result = mbedtls_mpi_copy( &R->Z, &U );
	MBEDTLS_MPI_CHK(result);

	cleanup:
	mbedtls_mpi_free( &M ); mbedtls_mpi_free( &S ); mbedtls_mpi_free( &T ); mbedtls_mpi_free( &U );

	return( ret );
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Special cases: (1) P or Q is zero, (2) R is zero, (3) P == Q.
 * None of these cases can happen as intermediate step in ecp_mul_comb():
 * - at each step, P, Q and R are multiples of the base point, the factor
 *   being less than its order, so none of them is zero;
 * - Q is an odd multiple of the base point, P an even multiple,
 *   due to the choice of precomputed points in the modified comb method.
 * So branches for these cases do not leak secret information.
 *
 * We accept Q->Z being unset (saving memory in tables) as meaning 1.
 *
 * Cost: 1A := 8M + 3S
 */
static int ecp_add_mixed( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_ecp_point_s *const P, const mbedtls_ecp_point_s *const Q )
{
	int ret;
	sint32 result_output_fun ;
	mbedtls_mpi T1, T2, T3, T4, X, Y, Z;

	/*
	 * Trivial cases: P == 0 or Q == 0 (case 1)
	 */
	if( mbedtls_mpi_cmp_int( &P->Z, 0 ) == 0 )
	{
		return( mbedtls_ecp_copy( R, Q ) );
	}

	if( (((Q->Z).limbsPtr) != NULL_PTR) && (mbedtls_mpi_cmp_int( &Q->Z, 0 ) == 0 ))
	{
		return( mbedtls_ecp_copy( R, P ) );
	}

	/*
	 * Make sure Q coordinates are normalized
	 */

	if( (((Q->Z).limbsPtr) != NULL_PTR) && (mbedtls_mpi_cmp_int( &Q->Z, 1 ) != 0 ))
	{
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	mbedtls_mpi_init( &T1 ); mbedtls_mpi_init( &T2 ); mbedtls_mpi_init( &T3 ); mbedtls_mpi_init( &T4 );
	mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z );

	result_output_fun= mbedtls_mpi_mul_mpi( &T1,  &P->Z,  &P->Z );
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( T1 );

	result_output_fun = mbedtls_mpi_mul_mpi( &T2,  &T1,    &P->Z );
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( T2 );

	result_output_fun = mbedtls_mpi_mul_mpi( &T1,  &T1,    &Q->X );
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( T1 );

	result_output_fun = mbedtls_mpi_mul_mpi( &T2,  &T2,    &Q->Y ) ;
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( T2 );

	result_output_fun = mbedtls_mpi_sub_mpi( &T1,  &T1,    &P->X ) ;
	MBEDTLS_MPI_CHK(result_output_fun);
	MOD_SUB( T1 )

	result_output_fun = mbedtls_mpi_sub_mpi( &T2,  &T2,    &P->Y );
	MBEDTLS_MPI_CHK(result_output_fun);
	MOD_SUB( T2 )

	/* Special cases (2) and (3) */
	if( mbedtls_mpi_cmp_int( &T1, 0 ) == 0 )
	{
		if( mbedtls_mpi_cmp_int( &T2, 0 ) == 0 )
		{
			ret = ecp_double_jac( grp, R, P );
			goto cleanup;
		}
		else
		{
			ret = mbedtls_ecp_set_zero( R );
			goto cleanup;
		}
	}

	result_output_fun = mbedtls_mpi_mul_mpi( &Z,   &P->Z,  &T1   );
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( Z  );

	result_output_fun = mbedtls_mpi_mul_mpi( &T3,  &T1,    &T1   );
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( T3 );

	result_output_fun = mbedtls_mpi_mul_mpi( &T4,  &T3,    &T1   ) ;
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( T4 );

	result_output_fun = mbedtls_mpi_mul_mpi( &T3,  &T3,    &P->X );
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( T3 );

	result_output_fun = mbedtls_mpi_mul_int( &T1,  &T3,    2     );
	MBEDTLS_MPI_CHK(result_output_fun);
	MOD_ADD( T1 )

	result_output_fun =  mbedtls_mpi_mul_mpi( &X,   &T2,    &T2   );
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( X  );

	result_output_fun = mbedtls_mpi_sub_mpi( &X,   &X,     &T1   ) ;
	MBEDTLS_MPI_CHK(result_output_fun);
	MOD_SUB( X  )

	result_output_fun = mbedtls_mpi_sub_mpi( &X,   &X,     &T4   );
	MBEDTLS_MPI_CHK(result_output_fun);
	MOD_SUB( X  )

	result_output_fun = mbedtls_mpi_sub_mpi( &T3,  &T3,    &X    );
	MBEDTLS_MPI_CHK(result_output_fun);
	MOD_SUB( T3 )

	result_output_fun = mbedtls_mpi_mul_mpi( &T3,  &T3,    &T2   );
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( T3 );

	result_output_fun = mbedtls_mpi_mul_mpi( &T4,  &T4,    &P->Y );
	MBEDTLS_MPI_CHK(result_output_fun);  MOD_MUL( T4 );

	result_output_fun = mbedtls_mpi_sub_mpi( &Y,   &T3,    &T4   );
	MBEDTLS_MPI_CHK(result_output_fun);
	MOD_SUB( Y  )

	result_output_fun =  mbedtls_mpi_copy( &R->X, &X );
	MBEDTLS_MPI_CHK(result_output_fun);

	result_output_fun = mbedtls_mpi_copy( &R->Y, &Y );
	MBEDTLS_MPI_CHK(result_output_fun);

	result_output_fun = mbedtls_mpi_copy( &R->Z, &Z );
	MBEDTLS_MPI_CHK(result_output_fun);

	cleanup:

	mbedtls_mpi_free( &T1 ); mbedtls_mpi_free( &T2 ); mbedtls_mpi_free( &T3 ); mbedtls_mpi_free( &T4 );
	mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z );

	return( ret );
}

/*
 * Randomize jacobian coordinates:
 * (X, Y, Z) -> (l^2 X, l^3 Y, l Z) for random l
 * This is sort of the reverse operation of ecp_normalize_jac().
 *
 * This countermeasure was first suggested in [2].
 */
static int ecp_randomize_jac( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const pt,
		sint32 (* const f_rng)(void *, uint8 * , uint32 ), void *const p_rng )
{
	int ret;
	sint32 result;
	mbedtls_mpi l, ll;
	size_t p_size;
	int count = 0;


	p_size = ( grp->pbits + 7 ) / 8;
	mbedtls_mpi_init( &l ); mbedtls_mpi_init( &ll );

	/* Generate l such that 1 < l < p */
	do
	{
		result = mbedtls_mpi_fill_random( &l, p_size, f_rng, p_rng );
		MBEDTLS_MPI_CHK(result);

		while( mbedtls_mpi_cmp_mpi( &l, &grp->P ) >= 0 )
		{
			result =  mbedtls_mpi_shift_r( &l, 1 ) ;
			MBEDTLS_MPI_CHK(result);
		}


		if( count++ > 10 )
		{
			return( MBEDTLS_ERR_ECP_RANDOM_FAILED );
		}
	}
	while( mbedtls_mpi_cmp_int( &l, 1 ) <= 0 );

	/* Z = l * Z */
	result = mbedtls_mpi_mul_mpi( &pt->Z,   &pt->Z,     &l  );
	MBEDTLS_MPI_CHK(result); MOD_MUL( pt->Z );

	/* X = l^2 * X */
	result =  mbedtls_mpi_mul_mpi( &ll,      &l,         &l  );
	MBEDTLS_MPI_CHK(result); MOD_MUL( ll );

	result = mbedtls_mpi_mul_mpi( &pt->X,   &pt->X,     &ll );
	MBEDTLS_MPI_CHK(result); MOD_MUL( pt->X );

	/* Y = l^3 * Y */
	result =  mbedtls_mpi_mul_mpi( &ll,      &ll,        &l  ) ;
	MBEDTLS_MPI_CHK(result); MOD_MUL( ll );

	result = mbedtls_mpi_mul_mpi( &pt->Y,   &pt->Y,     &ll );
	MBEDTLS_MPI_CHK(result); MOD_MUL( pt->Y );

	cleanup:
	mbedtls_mpi_free( &l ); mbedtls_mpi_free( &ll );

	return( ret );
}

/*
 * Check and define parameters used by the comb method (see below for details)
 */
#if MBEDTLS_ECP_WINDOW_SIZE < 2 || MBEDTLS_ECP_WINDOW_SIZE > 7
#error "MBEDTLS_ECP_WINDOW_SIZE out of bounds"
#endif

/* number of precomputed points */
#define COMB_MAX_PRE    ( 1 << ( MBEDTLS_ECP_WINDOW_SIZE - 1 ) )

/*
 * Compute the representation of m that will be used with our comb method.
 *
 * The basic comb method is described in GECC 3.44 for example. We use a
 * modified version that provides resistance to SPA by avoiding zero
 * digits in the representation as in [3]. We modify the method further by
 * requiring that all K_i be odd, which has the small cost that our
 * representation uses one more K_i, due to carries, but saves on the size of
 * the precomputed table.
 *
 * Summary of the comb method and its modifications:
 *
 * - The goal is to compute m*P for some w*d-bit integer m.
 *
 * - The basic comb method splits m into the w-bit integers
 *   x[0] .. x[d-1] where x[i] consists of the bits in m whose
 *   index has residue i modulo d, and computes m * P as
 *   S[x[0]] + 2 * S[x[1]] + .. + 2^(d-1) S[x[d-1]], where
 *   S[i_{w-1} .. i_0] := i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + i_0 P.
 *
 * - If it happens that, say, x[i+1]=0 (=> S[x[i+1]]=0), one can replace the sum by
 *    .. + 2^{i-1} S[x[i-1]] - 2^i S[x[i]] + 2^{i+1} S[x[i]] + 2^{i+2} S[x[i+2]] ..,
 *   thereby successively converting it into a form where all summands
 *   are nonzero, at the cost of negative summands. This is the basic idea of [3].
 *
 * - More generally, even if x[i+1] != 0, we can first transform the sum as
 *   .. - 2^i S[x[i]] + 2^{i+1} ( S[x[i]] + S[x[i+1]] ) + 2^{i+2} S[x[i+2]] ..,
 *   and then replace S[x[i]] + S[x[i+1]] = S[x[i] ^ x[i+1]] + 2 S[x[i] & x[i+1]].
 *   Performing and iterating this procedure for those x[i] that are even
 *   (keeping track of carry), we can transform the original sum into one of the form
 *   S[x'[0]] +- 2 S[x'[1]] +- .. +- 2^{d-1} S[x'[d-1]] + 2^d S[x'[d]]
 *   with all x'[i] odd. It is therefore only necessary to know S at odd indices,
 *   which is why we are only computing half of it in the first place in
 *   ecp_precompute_comb and accessing it with index abs(i) / 2 in ecp_select_comb.
 *
 * - For the sake of compactness, only the seven low-order bits of x[i]
 *   are used to represent its absolute value (K_i in the paper), and the msb
 *   of x[i] encodes the sign (s_i in the paper): it is set if and only if
 *   if s_i == -1;
 *
 * Calling conventions:
 * - x is an array of size d + 1
 * - w is the size, ie number of teeth, of the comb, and must be between
 *   2 and 7 (in practice, between 2 and MBEDTLS_ECP_WINDOW_SIZE)
 * - m is the MPI, expected to be odd and such that bitlength(m) <= w * d
 *   (the result will be incorrect if these assumptions are not satisfied)
 */
static void ecp_comb_recode_core( unsigned char x[], const size_t d,
		const unsigned char w, const mbedtls_mpi *const m )
{
	size_t i, j;
	unsigned char c, cc, adjust;

	memset( x, 0, d+1 );

	/* First get the classical comb values (except for x_d = 0) */
	for( i = 0; i < d; i++ )
	{
		for( j = 0; j < w; j++ )
		{

			x[i] |= (mbedtls_mpi_get_bit(m,i + (d * j))) << j;
		}
	}

	/* Now make sure x_1 .. x_d are odd */
	c = 0;
	for( i = 1; i <= d; i++ )
	{
		/* Add carry and update it */
		cc   = x[i] & c;
		x[i] = x[i] ^ c;
		c = cc;

		/* Adjust if needed, avoiding branches */
		adjust = 1 - ( x[i] & 0x01 );
		c   |= x[i] & ( x[i-1] * adjust );
		x[i] = x[i] ^ ( x[i-1] * adjust );
		x[i-1] |= adjust << 7;
	}
}

/*
 * Precompute points for the adapted comb method
 *
 * Assumption: T must be able to hold 2^{w - 1} elements.
 *
 * Operation: If i = i_{w-1} ... i_1 is the binary representation of i,
 *            sets T[i] = i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + P.
 *
 * Cost: d(w-1) D + (2^{w-1} - 1) A + 1 N(w-1) + 1 N(2^{w-1} - 1)
 *
 * Note: Even comb values (those where P would be omitted from the
 *       sum defining T[i] above) are not needed in our adaption
 *       the comb method. See ecp_comb_recode_core().
 *
 * This function currently works in four steps:
 * (1) [dbl]      Computation of intermediate T[i] for 2-power values of i
 * (2) [norm_dbl] Normalization of coordinates of these T[i]
 * (3) [add]      Computation of all T[i]
 * (4) [norm_add] Normalization of all T[i]
 *
 * Step 1 can be interrupted but not the others; together with the final
 * coordinate normalization they are the largest steps done at once, depending
 * on the window size. Here are operation counts for P-256:
 *
 * step     (2)     (3)     (4)
 * w = 5    142     165     208
 * w = 4    136      77     160
 * w = 3    130      33     136
 * w = 2    124      11     124
 *
 * So if ECC operations are blocking for too long even with a low max_ops
 * value, it's useful to set MBEDTLS_ECP_WINDOW_SIZE to a lower value in order
 * to minimize maximum blocking time.
 */

static int ecp_precompute_comb( const mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s T[], const mbedtls_ecp_point_s *const P,
		const unsigned char w, const size_t d,
		const mbedtls_ecp_restart_ctx *const rs_ctx )
{
	int ret;
	sint32 result;
	unsigned char i;
	size_t j = 0;
	const unsigned char T_size = 1U << ( w - 1 );
	mbedtls_ecp_point_s *cur, *TT[COMB_MAX_PRE - 1];


	/*
	 * Set T[0] = P and
	 * T[2^{l-1}] = 2^{dl} P for l = 1 .. w-1 (this is not the final value)
	 */
	result = mbedtls_ecp_copy( &T[0], P );
	MBEDTLS_MPI_CHK(result);

	j = 0;

	for( ; j < (d * ( w - 1 )); j++ )
	{


		i = 1U << ( j / d );
		cur = T + i;

		if( (j % d) == 0 )
		{
			result = mbedtls_ecp_copy( cur, T + ( i >> 1 ) );
			MBEDTLS_MPI_CHK(result);
		}

		result = ecp_double_jac( grp, cur, cur );
		MBEDTLS_MPI_CHK(result);
	}

	/*
	 * Normalize current elements in T. As T has holes,
	 * use an auxiliary array of pointers to elements in T.
	 */
	j = 0;
	for( i = 1; i < T_size; i <<= 1 )
	{
		TT[j++] = T + i;
	}



	result = ecp_normalize_jac_many( grp, TT, j );
	MBEDTLS_MPI_CHK(result);


	/*
	 * Compute the remaining ones using the minimal number of additions
	 * Be careful to update T[2^l] only after using it!
	 */


	for( i = 1; i < T_size; i <<= 1 )
	{
		j = i;
		while( j-- )
		{
			result = ecp_add_mixed( grp, &T[i + j], &T[j], &T[i] );
			MBEDTLS_MPI_CHK(result);
		}
	}

	/*
	 * Normalize final elements in T. Even though there are no holes now, we
	 * still need the auxiliary array for homogeneity with the previous
	 * call. Also, skip T[0] which is already normalised, being a copy of P.
	 */
	for( j = 0; (j + 1) < T_size; j++ )
	{
		TT[j] = T + j + 1;
	}



	result = ecp_normalize_jac_many( grp, TT, j ) ;
	MBEDTLS_MPI_CHK(result);

	cleanup:

	return( ret );
}

/*
 * Select precomputed point: R = sign(i) * T[ abs(i) / 2 ]
 *
 * See ecp_comb_recode_core() for background
 */
static int ecp_select_comb( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_ecp_point_s T[], const unsigned char T_size,
		const unsigned char i )
{
	int ret;
	sint32 result_output_fun ;
	unsigned char  j;
	/* Ignore the "sign" bit and scale down */
	const unsigned char ii =  ( i & (unsigned char)0x7Fu ) >> 1;

	/* Read the whole table to thwart cache-based timing attacks */
	for( j = 0; j < T_size; j++ )
	{
		result_output_fun = mbedtls_mpi_safe_cond_assign( &R->X, &T[j].X, j == ii );
		MBEDTLS_MPI_CHK(result_output_fun);
		result_output_fun = mbedtls_mpi_safe_cond_assign( &R->Y, &T[j].Y, j == ii ) ;
		MBEDTLS_MPI_CHK(result_output_fun);
	}

	/* Safely invert result if i is "negative" */
	result_output_fun = ecp_safe_invert_jac( grp, R, i >> 7 );
	MBEDTLS_MPI_CHK(result_output_fun);

	cleanup:
	return( ret );
}

/*
 * Core multiplication algorithm for the (modified) comb method.
 * This part is actually common with the basic comb method (GECC 3.44)
 *
 * Cost: d A + d D + 1 R
 */

static int ecp_mul_comb_core( const mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_ecp_point_s T[], const unsigned char T_size,
		const unsigned char x[], const size_t d,
		sint32 (* const f_rng)(void * , uint8 * , uint32),
		void *const p_rng,
		const mbedtls_ecp_restart_ctx *const rs_ctx )
{
	int ret;
	mbedtls_ecp_point_s Txi;
	size_t i;
	sint32 result;

	mbedtls_ecp_point_init( &Txi );

	{
		/* Start with a non-zero point and randomize its coordinates */
		i = d;

		result = ecp_select_comb( grp, R, T, T_size, x[i] );
		MBEDTLS_MPI_CHK(result);

		result = mbedtls_mpi_lset( &R->Z, 1 );
		MBEDTLS_MPI_CHK(result);

		if( f_rng != 0 )
		{
			result = ecp_randomize_jac( grp, R, f_rng, p_rng );
			MBEDTLS_MPI_CHK(result);
		}
	}

	while( i != 0 )
	{

		--i;
		result = ecp_double_jac( grp, R, R );
		MBEDTLS_MPI_CHK(result);

		result = ecp_select_comb( grp, &Txi, T, T_size, x[i] );
		MBEDTLS_MPI_CHK(result);

		result = ecp_add_mixed( grp, R, R, &Txi );
		MBEDTLS_MPI_CHK(result);
	}

	cleanup:

	mbedtls_ecp_point_free( &Txi );
	return( ret );
}

/*
 * Recode the scalar to get constant-time comb multiplication
 *
 * As the actual scalar recoding needs an odd scalar as a starting point,
 * this wrapper ensures that by replacing m by N - m if necessary, and
 * informs the caller that the result of multiplication will be negated.
 *
 * This works because we only support large prime order for Short Weierstrass
 * curves, so N is always odd hence either m or N - m is.
 *
 * See ecp_comb_recode_core() for background.
 */
static int ecp_comb_recode_scalar( const mbedtls_ecp_group_s *const grp,
		const mbedtls_mpi *const m,
		unsigned char k[COMB_MAX_D + 1],
		const size_t d,
		const unsigned char w,
		unsigned char *const parity_trick )
{
	int ret;
	sint32 result;
	mbedtls_mpi M, mm;

	mbedtls_mpi_init( &M );
	mbedtls_mpi_init( &mm );

	/* N is always odd (see above), just make extra sure */
	if( mbedtls_mpi_get_bit( &grp->N, 0 ) != 1 )
	{
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	/* do we need the parity trick? */
	*parity_trick = ( mbedtls_mpi_get_bit( m, 0 ) == 0 );

	/* execute parity fix in constant time */
	result = mbedtls_mpi_copy( &M, m );
	MBEDTLS_MPI_CHK(result);
	result = mbedtls_mpi_sub_mpi( &mm, &grp->N, m );
	MBEDTLS_MPI_CHK(result);
	result = mbedtls_mpi_safe_cond_assign( &M, &mm, *parity_trick );
	MBEDTLS_MPI_CHK(result);

	/* actual scalar recoding */
	ecp_comb_recode_core( k, d, w, &M );

	cleanup:
	mbedtls_mpi_free( &mm );
	mbedtls_mpi_free( &M );

	return( ret );
}

/*
 * Perform comb multiplication (for short Weierstrass curves)
 * once the auxiliary table has been pre-computed.
 *
 * Scalar recoding may use a parity trick that makes us compute -m * P,
 * if that is the case we'll need to recover m * P at the end.
 */
static int ecp_mul_comb_after_precomp( const mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s *const R,
		const mbedtls_mpi *const m,
		const mbedtls_ecp_point_s *const T,
		const unsigned char T_size,
		const unsigned char w,
		const size_t d,
		sint32 (* const f_rng)(void * , uint8 * , uint32),
		void *const p_rng,
		const mbedtls_ecp_restart_ctx *const rs_ctx )
{
	int ret;
	sint32 result;
	unsigned char parity_trick;
	unsigned char k[COMB_MAX_D + 1];
	mbedtls_ecp_point_s *const RR = R;

	result = ecp_comb_recode_scalar( grp, m, k, d, w,
			&parity_trick );
	MBEDTLS_MPI_CHK(result);

	result = ecp_mul_comb_core( grp, RR, T, T_size, k, d,
			f_rng, p_rng, rs_ctx ) ;
	MBEDTLS_MPI_CHK(result);

	result = ecp_safe_invert_jac( grp, RR, parity_trick );
	MBEDTLS_MPI_CHK(result);

	result = ecp_normalize_jac( grp, RR );
	MBEDTLS_MPI_CHK(result);


	cleanup:
	return( ret );
}

/*
 * Pick window size based on curve size and whether we optimize for base point
 */
static unsigned char ecp_pick_window_size( const mbedtls_ecp_group_s *const grp,
		const unsigned char p_eq_g )
{
	unsigned char w;

	/*
	 * Minimize the number of multiplications, that is minimize
	 * 10 * d * w + 18 * 2^(w-1) + 11 * d + 7 * w, with d = ceil( nbits / w )
	 * (see costs of the various parts, with 1S = 1M)
	 */
	w = ((grp->nbits) >= 384) ? 5 : 4;

	/*
	 * If P == G, pre-compute a bit more, since this may be re-used later.
	 * Just adding one avoids upping the cost of the first mul too much,
	 * and the memory cost too.
	 */
	if( p_eq_g )
	{
		w++;
	}

	/*
	 * Make sure w is within bounds.
	 * (The last test is useful only for very small curves in the test suite.)
	 */
	if( w > MBEDTLS_ECP_WINDOW_SIZE )
	{
		w = MBEDTLS_ECP_WINDOW_SIZE;
	}

	if( w >= grp->nbits )
	{
		w = 2;
	}

	return( w );
}

/*
 * Multiplication using the comb method - for curves in short Weierstrass form
 *
 * This function is mainly responsible for administrative work:
 * - managing the restart context if enabled
 * - managing the table of precomputed points (passed between the below two
 *   functions): allocation, computation, ownership tranfer, freeing.
 *
 * It delegates the actual arithmetic work to:
 *      ecp_precompute_comb() and ecp_mul_comb_with_precomp()
 *
 * See comments on ecp_comb_recode_core() regarding the computation strategy.
 */
static int ecp_mul_comb( mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_mpi *const m, const mbedtls_ecp_point_s *const P,
		sint32 (* const f_rng)(void * , uint8 * , uint32),
		void *const p_rng,
		const mbedtls_ecp_restart_ctx *const rs_ctx )
{
	int ret;
	sint32 result;
	unsigned char w, i;
	size_t d;
	unsigned char T_size, T_ok;
	mbedtls_ecp_point_s *T;

	/* Is P the base point ? */
#if MBEDTLS_ECP_FIXED_POINT_OPTIM == 1
	const unsigned char p_eq_g = (((mbedtls_mpi_cmp_mpi( &(P->Y), &((grp->G).Y ))) == 0) &&
			((mbedtls_mpi_cmp_mpi( &(P->X), &((grp->G.X ))) == 0 )));
#else
	const unsigned char p_eq_g = 0;
#endif

	/* Pick window size and deduce related sizes */
	w = ecp_pick_window_size( grp, p_eq_g );
	T_size = 1U << ( w - 1 );
	d = (((grp->nbits) + w) - 1 ) / w;

	/* Pre-computed table: do we have it already for the base point? */
	if( p_eq_g && ((grp->T) != NULL_PTR))
	{
		/* second pointer to the same table, will be deleted on exit */
		T = grp->T;
		T_ok = 1;
	}
	else
		/* Allocate table if we didn't have any */
	{
		T = buffer_alloc_calloc( T_size, sizeof( mbedtls_ecp_point_s ) );
		if( T == NULL_PTR )
		{
			ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
			goto cleanup;
		}

		for( i = 0; i < T_size; i++ )
		{
			mbedtls_ecp_point_init( &T[i] );
		}

		T_ok = 0;
	}

	/* Compute table (or finish computing it) if not done already */

	if( !T_ok )
	{
		result = ecp_precompute_comb( grp, T, P, w, d, rs_ctx );
		MBEDTLS_MPI_CHK(result);

		if( p_eq_g )
		{
			/* almost transfer ownership of T to the group, but keep a copy of
			 * the pointer to use for calling the next function more easily */
			grp->T = T;
			grp->T_size = T_size;
		}
	}

	/* Actual comb multiplication using precomputed points */
	result = ecp_mul_comb_after_precomp( grp, R, m,
			T, T_size, w, d,
			f_rng, p_rng, rs_ctx ) ;
	MBEDTLS_MPI_CHK(result);

	cleanup:

	/* does T belong to the group? */
	if( T == grp->T )
	{
		T = NULL_PTR;
	}


	/* did T belong to us? then let's destroy it! */
	if( T != NULL_PTR )
	{
		for( i = 0; i < T_size; i++ )
		{
			mbedtls_ecp_point_free( &T[i] );
		}
		buffer_alloc_free( T );
	}

	/* prevent caller from using invalid value */
	if( ret != 0 )
	{
		mbedtls_ecp_point_free( R );
	}


	return( ret );
}



/*
 * Restartable multiplication R = m * P
 */
int mbedtls_ecp_mul_restartable( mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_mpi *const m, const mbedtls_ecp_point_s *const P,
		sint32 (* const f_rng)(void * , uint8 * , uint32), void *const p_rng,
		const mbedtls_ecp_restart_ctx *const rs_ctx )
{
	int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
	sint32 result;

	ECP_VALIDATE_RET( grp != NULL_PTR );
	ECP_VALIDATE_RET( R   != NULL_PTR );
	ECP_VALIDATE_RET( m   != NULL_PTR );
	ECP_VALIDATE_RET( P   != NULL_PTR );

	{
		/* Common sanity checks */
		result = mbedtls_ecp_check_privkey( grp, m );
		MBEDTLS_MPI_CHK(result);

		result = mbedtls_ecp_check_pubkey( grp, P );
		MBEDTLS_MPI_CHK(result);
	}

	ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;


	if( ecp_get_type( grp ) == ECP_TYPE_SHORT_WEIERSTRASS )
	{
		result = ecp_mul_comb( grp, R, m, P, f_rng, p_rng, rs_ctx );
		MBEDTLS_MPI_CHK(result);
	}


	cleanup:

	return( ret );
}


/*
 * Check that an affine point is valid as a public key,
 * short weierstrass curves (SEC1 3.2.3.1)
 */
static int ecp_check_pubkey_sw( const mbedtls_ecp_group_s *const grp, const mbedtls_ecp_point_s *const pt )
{
	int ret;
	sint32 result;
	mbedtls_mpi YY, RHS;

	/* pt coordinates must be normalized for our checks */
	if( ((mbedtls_mpi_cmp_int( &(pt->X), 0 )) < 0) ||
			((mbedtls_mpi_cmp_int( &(pt->Y), 0 )) < 0) ||
			((mbedtls_mpi_cmp_mpi( &(pt->X), &(grp->P))) >= 0) ||
			((mbedtls_mpi_cmp_mpi( &(pt->Y), &(grp->P))) >= 0) )
	{
		return( MBEDTLS_ERR_ECP_INVALID_KEY );
	}

	mbedtls_mpi_init( &YY ); mbedtls_mpi_init( &RHS );

	/*
	 * YY = Y^2
	 * RHS = X (X^2 + A) + B = X^3 + A X + B
	 */
	result =mbedtls_mpi_mul_mpi( &YY,  &pt->Y,   &pt->Y  );
	MBEDTLS_MPI_CHK(result);  MOD_MUL( YY  );

	result = mbedtls_mpi_mul_mpi( &RHS, &pt->X,   &pt->X  );
	MBEDTLS_MPI_CHK(result);  MOD_MUL( RHS );

	/* Special case for A = -3 */
	if( grp->A.limbsPtr == NULL_PTR )
	{
		result = mbedtls_mpi_sub_int( &RHS, &RHS, 3       );
		MBEDTLS_MPI_CHK(result);
		MOD_SUB( RHS )
	}
	else
	{
		result = mbedtls_mpi_add_mpi( &RHS, &RHS, &grp->A );
		MBEDTLS_MPI_CHK(result);
		MOD_ADD( RHS )
	}
	result =  mbedtls_mpi_mul_mpi( &RHS, &RHS,     &pt->X  ) ;
	MBEDTLS_MPI_CHK(result);  MOD_MUL( RHS );

	result = mbedtls_mpi_add_mpi( &RHS, &RHS,     &grp->B );
	MBEDTLS_MPI_CHK(result);
	MOD_ADD( RHS )

	if( mbedtls_mpi_cmp_mpi( &YY, &RHS ) != 0 )
	{
		ret = MBEDTLS_ERR_ECP_INVALID_KEY;
	}

	cleanup:

	mbedtls_mpi_free( &YY ); mbedtls_mpi_free( &RHS );

	return( ret );
}


/*
 * R = m * P with shortcuts for m == 1 and m == -1
 * NOT constant-time - ONLY for short Weierstrass!
 */
static int mbedtls_ecp_mul_shortcuts( mbedtls_ecp_group_s *const grp,
		mbedtls_ecp_point_s *const R,
		const mbedtls_mpi *const m,
		const mbedtls_ecp_point_s *const P,
		const mbedtls_ecp_restart_ctx *const rs_ctx )
{
	int ret;
	sint32 result;
	if( mbedtls_mpi_cmp_int( m, 1 ) == 0 )
	{
		result = mbedtls_ecp_copy( R, P );
		MBEDTLS_MPI_CHK(result);
	}
	else if( mbedtls_mpi_cmp_int( m, -1 ) == 0 )
	{
		result = mbedtls_ecp_copy( R, P );
		MBEDTLS_MPI_CHK(result);
		if( mbedtls_mpi_cmp_int( &R->Y, 0 ) != 0 )
		{
			result = mbedtls_mpi_sub_mpi( &R->Y, &grp->P, &R->Y );
			MBEDTLS_MPI_CHK(result);
		}
	}
	else
	{
		result = mbedtls_ecp_mul_restartable( grp, R, m, P,
				NULL_PTR, NULL_PTR, rs_ctx );
		MBEDTLS_MPI_CHK(result);
	}

	cleanup:
	return( ret );
}

/*
 * Restartable linear combination
 * NOT constant-time
 */
int mbedtls_ecp_muladd_restartable(
		mbedtls_ecp_group_s *const grp, mbedtls_ecp_point_s *const R,
		const mbedtls_mpi *const m, const mbedtls_ecp_point_s *const P,
		const mbedtls_mpi *const n, const mbedtls_ecp_point_s *const Q,
		const mbedtls_ecp_restart_ctx *const rs_ctx )
{
	int ret;
	sint32 result;
	mbedtls_ecp_point_s mP;
	mbedtls_ecp_point_s *const pmP = &mP;
	mbedtls_ecp_point_s *const pR = R;

	ECP_VALIDATE_RET( grp != NULL_PTR );
	ECP_VALIDATE_RET( R   != NULL_PTR );
	ECP_VALIDATE_RET( m   != NULL_PTR );
	ECP_VALIDATE_RET( P   != NULL_PTR );
	ECP_VALIDATE_RET( n   != NULL_PTR );
	ECP_VALIDATE_RET( Q   != NULL_PTR );

	if( ecp_get_type( grp ) != ECP_TYPE_SHORT_WEIERSTRASS )
	{
		return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
	}

	mbedtls_ecp_point_init( &mP );

	result = mbedtls_ecp_mul_shortcuts( grp, pmP, m, P, rs_ctx );
	MBEDTLS_MPI_CHK(result);

	result = mbedtls_ecp_mul_shortcuts( grp, pR,  n, Q, rs_ctx );
	MBEDTLS_MPI_CHK(result);

	result = ecp_add_mixed( grp, pR, pmP, pR );
	MBEDTLS_MPI_CHK(result);

	result = ecp_normalize_jac( grp, pR );
	MBEDTLS_MPI_CHK(result);

	cleanup:
	mbedtls_ecp_point_free( &mP );

	return( ret );
}

/*
 * Check that a point is valid as a public key
 */
int mbedtls_ecp_check_pubkey( const mbedtls_ecp_group_s *const grp,
		const mbedtls_ecp_point_s *const pt )
{
	ECP_VALIDATE_RET( grp != NULL_PTR );
	ECP_VALIDATE_RET( pt  != NULL_PTR );

	/* Must use affine coordinates */
	if( mbedtls_mpi_cmp_int( &pt->Z, 1 ) != 0 )
	{
		return( MBEDTLS_ERR_ECP_INVALID_KEY );
	}


	if( ecp_get_type( grp ) == ECP_TYPE_SHORT_WEIERSTRASS )
	{
		return( ecp_check_pubkey_sw( grp, pt ) );
	}

	return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
}

/*
 * Check that an mbedtls_mpi is valid as a private key
 */
int mbedtls_ecp_check_privkey( const mbedtls_ecp_group_s *const grp,
		const mbedtls_mpi *const d )
{
	ECP_VALIDATE_RET( grp != NULL_PTR );
	ECP_VALIDATE_RET( d   != NULL_PTR );


	if( ecp_get_type( grp ) == ECP_TYPE_SHORT_WEIERSTRASS )
	{
		/* see SEC1 3.2 */
		if( (mbedtls_mpi_cmp_int( d, 1 ) < 0 )||
				(mbedtls_mpi_cmp_mpi( d, &grp->N ) >= 0 ))
		{
			return( MBEDTLS_ERR_ECP_INVALID_KEY );
		}
		else
		{
			return( 0 );
		}
	}


	return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
}

/*
 * Generate a private key
 */
int mbedtls_ecp_gen_privkey( const mbedtls_ecp_group_s *const grp,
		mbedtls_mpi *const d,
		sint32 (* const f_rng)(void * , uint8 * , uint32),
		void *const p_rng )
{
	int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
	size_t n_size;
	sint32 result_output_fun;

	ECP_VALIDATE_RET( grp   != NULL_PTR );
	ECP_VALIDATE_RET( d     != NULL_PTR );
	ECP_VALIDATE_RET( f_rng != NULL_PTR );

	n_size = ( grp->nbits + 7 ) / 8;


	if( ecp_get_type( grp ) == ECP_TYPE_SHORT_WEIERSTRASS )
	{
		/* SEC1 3.2.1: Generate d such that 1 <= n < N */
		int count = 0;

		/*
		 * Match the procedure given in RFC 6979 (deterministic ECDSA):
		 * - use the same byte ordering;
		 * - keep the leftmost nbits bits of the generated octet string;
		 * - try until result is in the desired range.
		 * This also avoids any biais, which is especially important for ECDSA.
		 */
		do
		{
			result_output_fun = mbedtls_mpi_fill_random( d, n_size, f_rng, p_rng );
			MBEDTLS_MPI_CHK(result_output_fun);

			result_output_fun =  mbedtls_mpi_shift_r( d, (8 * n_size) - (grp->nbits) );
			MBEDTLS_MPI_CHK(result_output_fun);

			/*
			 * Each try has at worst a probability 1/2 of failing (the msb has
			 * a probability 1/2 of being 0, and then the result will be < N),
			 * so after 30 tries failure probability is a most 2**(-30).
			 *
			 * For most curves, 1 try is enough with overwhelming probability,
			 * since N starts with a lot of 1s in binary, but some curves
			 * such as secp224k1 are actually very close to the worst case.
			 */
			if( ++count > 30 )
			{
				return( MBEDTLS_ERR_ECP_RANDOM_FAILED );
			}
		}
		while( ((mbedtls_mpi_cmp_int( d, 1 )) < 0) ||
				((mbedtls_mpi_cmp_mpi( d, &(grp->N) )) >= 0) );
	}
	cleanup:
	return( ret );
}




