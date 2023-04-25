/*
 *  Multi-precision integer library
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
 *  The following sources were referenced in the design of this Multi-precision
 *  Integer library:
 *
 *  [1] Handbook of Applied Cryptography - 1997
 *      Menezes, van Oorschot and Vanstone
 *
 *  [2] Multi-Precision Math
 *      Tom St Denis
 *      https://github.com/libtom/libtommath/blob/develop/tommath.pdf
 *
 *  [3] GNU Multi-Precision Arithmetic Library
 *      https://gmplib.org/manual/index.html
 *
 */

#include "bignum.h"


#include <string.h>
#include "platform_util.h"
#include "bn_mul.h"
#include "memory_buffer_alloc.h"

#define MPI_VALIDATE_RET( cond )                                       \
		MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_MPI_BAD_INPUT_DATA )

#define ciL            (sizeof(mbedtls_mpi_uint))   /* chars in limb  */
#define biL            (ciL << 3)                   /* bits  in limb  */
#define biH            (ciL << 2)                   /* half limb size */

#define MPI_SIZE_T_MAX  ( (uint32) -1 ) /* SIZE_T_MAX is not standard */


#define MPI_int_MAX    ( (uint32) -1 )              /* uint32_MAX is not standard */
#define UINT32_MAX     4294967295U
#define BIGNUM_32BITS  0xFFFFFFFFUL
/*
 * Convert between bits/chars and number of limbs
 * Divide first in order to avoid potential overflows
 */

#define BITS_TO_LIMBS(bits)    (((bits) / (uint32) biL ) + (uint32) ( ( (bits) % (uint32) biL ) != 0UL ))                     
#define CHARS_TO_LIMBS(chars)  (((uint32)(((uint32)(chars)) / ((uint32)ciL))) + ((uint32)((((uint32)(chars)) % ((uint32)ciL)) != 0UL)))



static void mpi_sub_hlp(const uint32 n, const mbedtls_mpi_uint* s, mbedtls_mpi_uint *d);
static void mpi_mul_hlp(uint32 cntr, const mbedtls_mpi_uint* s, mbedtls_mpi_uint *d,
		const mbedtls_mpi_uint b);
static sint32 mpi_montred(mbedtls_mpi* const A, const mbedtls_mpi* const N,
		const mbedtls_mpi_uint mm, const mbedtls_mpi* const T);
static sint32 mpi_montmul(mbedtls_mpi* const A, const mbedtls_mpi* const B,
		const mbedtls_mpi* const N, const mbedtls_mpi_uint mm, const mbedtls_mpi* const T);
static void mpi_montg_init(mbedtls_mpi_uint* const mm, const mbedtls_mpi* const N);
static void mbedtls_mpi_zeroize(mbedtls_mpi_uint* const ptr, const uint32 n);
static mbedtls_mpi_uint mbedtls_int_div_int(mbedtls_mpi_uint u1,
		mbedtls_mpi_uint u0, mbedtls_mpi_uint d, mbedtls_mpi_uint* const r);
static uint32 mbedtls_clz(const mbedtls_mpi_uint x);

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_mpi_zeroize(mbedtls_mpi_uint* const ptr, const uint32 n)
{
	uint32 counter;
	for (counter = 0UL;counter < n;counter++)
	{
		ptr[counter] = 0UL;
	}
}
/*
 * Initialize one MPI
 */
void mbedtls_mpi_init(mbedtls_mpi* const X)
{
	if (X != NULL_PTR)
	{
		X->s = (sint32) 1;
		X->n = (uint32) 0;
		X->limbsPtr = NULL_PTR;
	}
}

/*
 * Resize down as much as possible,
 * while keeping at least the specified number of limbs
 */
sint32 mbedtls_mpi_shrink( mbedtls_mpi * const X, const uint32 nblimbs )
{
	mbedtls_mpi_uint *p;
	uint32 i;
	MPI_VALIDATE_RET( X != NULL_PTR );

	if( nblimbs > (uint32) MBEDTLS_MPI_MAX_LIMBS )
	{
		return( MBEDTLS_ERR_MPI_ALLOC_FAILED );
	}

	/* Actually resize up in this case */
	if( X->n <= nblimbs )
	{
		return( mbedtls_mpi_grow( X, nblimbs ) );
	}

	for( i = X->n - 1; i > 0; i-- )
	{
		if( X->limbsPtr[i] != 0 )
		{
			break;
		}
	}
	i++;

	if( i < nblimbs )
	{
		i = nblimbs;
	}

	p = (mbedtls_mpi_uint*)buffer_alloc_calloc( i, ciL ) ;

	if( p == NULL_PTR )
	{
		return( MBEDTLS_ERR_MPI_ALLOC_FAILED );
	}

	if( X->limbsPtr != NULL_PTR )
	{
		memcpy( p, X->limbsPtr, i * ciL );
		mbedtls_mpi_zeroize( X->limbsPtr, X->n );
		buffer_alloc_free( X->limbsPtr );
	}

	X->n = i;
	X->limbsPtr = p;

	return( 0 );
}

/*
 * Unallocate one MPI
 */
void mbedtls_mpi_free(mbedtls_mpi* const X)
{
	if (X != NULL_PTR)
	{
		if (X->limbsPtr != NULL_PTR)
		{
			buffer_alloc_free(X->limbsPtr);
		}

		X->s = (sint32) 1;
		X->n = (uint32) 0;
		X->limbsPtr = NULL_PTR;
	}
}

/*
 * Enlarge to the specified number of limbs
 */
sint32 mbedtls_mpi_grow(mbedtls_mpi* const X, const uint32 nblimbs)
{
	mbedtls_mpi_uint *ptr;
	sint32 ret = 0;

	if (nblimbs > (uint32) MBEDTLS_MPI_MAX_LIMBS)
	{
		ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
	}
	else
	{
		if (X->n < nblimbs)
		{
			ptr = (mbedtls_mpi_uint*) buffer_alloc_calloc(nblimbs, (uint32) ciL);
			if (ptr == NULL_PTR)
			{
				ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
			}
			else
			{

				if (X->limbsPtr != NULL_PTR)
				{
					(void)memcpy(ptr, X->limbsPtr, X->n * (uint32) ciL);
					mbedtls_mpi_zeroize(X->limbsPtr, X->n);
					buffer_alloc_free(X->limbsPtr);
				}

				X->n = nblimbs;
				X->limbsPtr = ptr;
			}
		}
	}

	return (ret);
}

/*
 * Conditionally assign X = Y, without leaking information
 * about whether the assignment was made or not.
 * (Leaking information about the respective sizes of X and Y is ok however.)
 */
sint32 mbedtls_mpi_safe_cond_assign( mbedtls_mpi * const X, const mbedtls_mpi * const Y, uint8 assign )
{
	int ret = 0;
	sint32 result = 0;
	uint32 i;
	MPI_VALIDATE_RET( X != NULL_PTR );
	MPI_VALIDATE_RET( Y != NULL_PTR );

	/* make sure assign is 0 or 1 in a time-constant manner */

	assign = (assign | (unsigned char)-assign) >> 7;
	result = mbedtls_mpi_grow( X, Y->n );
	MBEDTLS_MPI_CHK(result);

	X->s = ((X->s) * ( 1 - assign )) + ((Y->s) * assign);

	for( i = 0; i < Y->n; i++ )
	{
		X->limbsPtr[i] = ((X->limbsPtr[i]) * ( 1 - assign )) + ((Y->limbsPtr[i]) * assign);
	}

	for( ; i < X->n; i++ )
	{
		X->limbsPtr[i] *= ( 1 - assign );
	}

	cleanup:
	return( ret );
}

/*
 * Conditionally swap X and Y, without leaking information
 * about whether the swap was made or not.
 * Here it is not ok to simply swap the pointers, which whould lead to
 * different memory access patterns when X and Y are used afterwards.
 */
sint32 mbedtls_mpi_safe_cond_swap( mbedtls_mpi * const X, mbedtls_mpi * const Y, uint8 swap )
{
	int ret, s;
	sint32 result = 0;
	uint32 i;
	mbedtls_mpi_uint tmp;
	MPI_VALIDATE_RET( X != NULL_PTR );
	MPI_VALIDATE_RET( Y != NULL_PTR );

	if( X == Y )
	{
		return( 0 );
	}

	/* make sure swap is 0 or 1 in a time-constant manner */
	swap = (swap | (unsigned char)-swap) >> 7;
	result = mbedtls_mpi_grow( X, Y->n );
	MBEDTLS_MPI_CHK(result);
	result = mbedtls_mpi_grow( Y, X->n );
	MBEDTLS_MPI_CHK(result);

	s = X->s;
	X->s = ((X->s) * ( 1 - swap )) + ((Y->s) * swap);
	Y->s = ((Y->s) * ( 1 - swap )) + (s * swap);


	for( i = 0; i < X->n; i++ )
	{
		tmp = X->limbsPtr[i];
		X->limbsPtr[i] = ((X->limbsPtr[i]) * ( 1 - swap )) + ((Y->limbsPtr[i]) * swap);
		Y->limbsPtr[i] = ((Y->limbsPtr[i]) * ( 1 - swap )) + (tmp * swap);
	}

	cleanup:
	return( ret );
}


/*
 * Copy the contents of Y into X
 */
sint32 mbedtls_mpi_copy(mbedtls_mpi* const X, const mbedtls_mpi* const Y)
{
	sint32 ret = 0;
	uint32 cntr;

	if (X == Y)
	{
		/* Do Nothing as ret variable already initialized to ZERO */
	}
	else
	{

		if (Y->limbsPtr == NULL_PTR)
		{
			mbedtls_mpi_free(X);
			/* NULL_PTR pointer is not acceptable */
			ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
		}
		else
		{

			for (cntr = (uint32) (Y->n - 1UL); cntr > 0UL; cntr--)
			{
				if (Y->limbsPtr[cntr] != 0UL)
				{
					break;
				}
			}
			cntr++;

			X->s = Y->s;
			/* The smallest value of cntr is 1.
			 * X->n equal 0.
			 */
			ret = mbedtls_mpi_grow(X, cntr);
			if ((ret == (sint32)0) && (X->limbsPtr != NULL_PTR))
			{
				(void)memset(X->limbsPtr, 0, X->n * (uint32) ciL);
				(void)memcpy(X->limbsPtr, Y->limbsPtr, cntr * (uint32) ciL);

			}

		}
	}
	return (ret);
}

/*
 * Set a bit to a specific value of 0 or 1
 */
sint32 mbedtls_mpi_set_bit( mbedtls_mpi * const X, const uint32 pos, const uint8 val )
{
	int ret = 0;
	sint32 result = 0;
	const uint32 off = pos / biL;
	const uint32 idx = pos % biL;
	MPI_VALIDATE_RET( X != NULL_PTR );

	if( (val != 0) && (val != 1) )
	{
		return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
	}

	if( ((X->n) * biL) <= pos )
	{
		if( val == 0 )
		{
			return( 0 );
		}
		result = mbedtls_mpi_grow( X, (off + 1) ) ;
		MBEDTLS_MPI_CHK(result);
	}

	X->limbsPtr[off] &= ~( (mbedtls_mpi_uint) 0x01 << idx );
	X->limbsPtr[off] |= (mbedtls_mpi_uint) val << idx;

	cleanup:

	return( ret );
}

/*
 * Set value from integer
 */
sint32 mbedtls_mpi_lset(mbedtls_mpi* const X, const mbedtls_mpi_sint z)
{
	sint32 ret = 0;
	ret = mbedtls_mpi_grow(X, (uint32) 1);
	if ((ret == (sint32)0) && (X->limbsPtr != NULL_PTR))
	{
		(void)memset(X->limbsPtr, 0, X->n * (uint32) ciL);

		X->limbsPtr[0] =  (mbedtls_mpi_uint) ((z < (sint32)0) ?  -z : z);
		X->s = (z < (sint32)0) ? (sint32)-1 : (sint32)1;
	}
	return (ret);
}
/*
 * Return the number of less significant zero-bits
 */
uint32 mbedtls_mpi_lsb(const mbedtls_mpi* const X)
{
	uint32 cntr, cntr2, count = 0;
	uint8 foundFlag = 0;

	for (cntr = (uint32) 0; cntr < X->n; cntr++)
	{
		for (cntr2 = (uint32) 0; cntr2 < (uint32) biL; cntr2++)
		{
			if (((X->limbsPtr[cntr] >> cntr2) & (uint32) 1) != 0UL)
			{
				foundFlag = (uint8) 1;
				break;
			}
			count++;
		}
		if ((uint32)foundFlag != 0UL)
		{
			break;
		}
	}

	if ((uint32)foundFlag == 0UL)
	{
		count = (uint32)0;
	}
	return (count);
}

/*
 * Count leading zero bits in a given integer
 */
static uint32 mbedtls_clz(const mbedtls_mpi_uint x)
{
	uint32 cntr;
	mbedtls_mpi_uint mask = (mbedtls_mpi_uint) 1 << ((uint32)biL - 1UL);

	for (cntr = (uint32) 0; cntr < (uint32) biL; cntr++)
	{
		if ((x & mask) != 0UL)
		{
			break;
		}

		mask =  mask >> (mbedtls_mpi_uint) 1;
	}

	return cntr;
}

/*
 * Return the number of bits
 */
uint32 mbedtls_mpi_bitlen(const mbedtls_mpi* const X)
{
	uint32 cntr, remainingLimbBits, ret = 0;

	if (X->n == 0UL)
	{
		/* Do Nothing as ret variable already initialized to ZERO */
	}
	else
	{

		for (cntr = X->n - (uint32) 1; cntr > 0UL; cntr--)
		{
			if (X->limbsPtr[cntr] != 0UL)
			{
				break;
			}
		}

		remainingLimbBits = (uint32) biL - mbedtls_clz(X->limbsPtr[cntr]);
		ret = (uint32) (cntr * (uint32) biL) + remainingLimbBits;
	}

	return ret;
}

/*
 * Return the total size in bytes
 */
uint32 mbedtls_mpi_size(const mbedtls_mpi* const X)
{

	return ((mbedtls_mpi_bitlen(X) + (uint32) 7) >> 3);
}

/*
 * Import X from unsigned binary data, big endian
 */
sint32 mbedtls_mpi_read_binary(mbedtls_mpi* const X, const uint8* const buf, const uint32 buflen)
{
	sint32 ret;
	uint32 cntr, cntr2, N;

	for (N = (uint32) 0; N < buflen; N++)
	{
		if ((uint32)buf[N] != 0UL)
		{
			break;
		}
	}

	ret = mbedtls_mpi_grow(X, CHARS_TO_LIMBS(((buflen) - (N))));

	if (ret == (sint32)0)
	{
		ret = mbedtls_mpi_lset(X, 0);
	}

	if (ret == (sint32)0)
	{
		cntr2 = (uint32) 0;
		for (cntr = buflen; cntr > N; cntr--)
		{
			X->limbsPtr[cntr2 / (uint32) ciL] |= (mbedtls_mpi_uint) buf[cntr
																		- (uint32) 1] << ((cntr2 % (uint32) ciL) << 3);
			cntr2++;
		}
	}

	return (ret);
}

/*
 * Export X into unsigned binary data, big endian
 */
sint32 mbedtls_mpi_write_binary(const mbedtls_mpi* const X, uint8* const buf, const uint32 buflen)
{
	uint32 cntr, cntr2, N;
	sint32 ret = 0;

	N = mbedtls_mpi_size(X);

	if (buflen < N)
	{
		ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
	}
	else
	{
		(void)memset(buf, 0, (uint32) buflen);
		cntr2 = 0;
		cntr = buflen - (uint32) 1;
		for (N = mbedtls_mpi_size(X); N > 0UL; N--)
		{
			buf[cntr] = (uint8) (X->limbsPtr[cntr2 / (uint32) ciL]
											 >> ((cntr2 % (uint32) ciL) << 3));
			cntr--;
			cntr2++;
		}
	}
	return (ret);
}

/*
 * Left-shift: X <<= count
 */
sint32 mbedtls_mpi_shift_l(mbedtls_mpi* const X, const uint32 count)
{
	sint32 ret = 0;
	uint32 cntr;
	const uint32 v0 = count / (uint32) biL;
	const uint32 t1 = count & (uint32) ((uint32)biL - 1UL);

	mbedtls_mpi_uint r0 = 0, r1;

	cntr = mbedtls_mpi_bitlen(X) + count;

	if ((X->n * (uint32) biL) < cntr)
	{
		ret = mbedtls_mpi_grow(X, (uint32) BITS_TO_LIMBS(cntr));
	}

	/*
	 * shift by count / limb_size
	 */
	if ((v0 > 0UL) && (ret == (sint32)0))
	{
		for (cntr = X->n; cntr > v0; cntr--)
		{
			X->limbsPtr[cntr - (uint32) 1] = X->limbsPtr[cntr - v0 - (uint32) 1];
		}

		for (; cntr > 0UL; cntr--)
		{
			X->limbsPtr[cntr - (uint32) 1] = (mbedtls_mpi_uint) 0;
		}
	}

	/*
	 * shift by count % limb_size
	 */
	if ((t1 > 0UL) && (ret == (sint32)0))
	{
		for (cntr = v0; cntr < X->n; cntr++)
		{
			r1 = X->limbsPtr[cntr] >> ((uint32) biL - t1);
			X->limbsPtr[cntr] <<= t1;
			X->limbsPtr[cntr] |= r0;
			r0 = r1;
		}
	}

	return (ret);
}

/*
 * Right-shift: X >>= count
 */
sint32 mbedtls_mpi_shift_r(mbedtls_mpi* const X, const uint32 count)
{
	uint32 cntr;
	const uint32 v0 = count / (uint32) biL;
	const uint32 v1 = count & (uint32) ((uint32)biL - 1UL);

	sint32 ret = 0;
	mbedtls_mpi_uint r0 = 0, r1;

	if ((v0 > X->n) || ((v0 == X->n) && (v1 > 0UL)))
	{
		ret = mbedtls_mpi_lset(X, 0);
	}
	else
	{
		/*
		 * shift by count / limb_size
		 */
		if (v0 > 0UL)
		{
			for (cntr = (uint32)0; cntr < (X->n - v0); cntr++)
			{
				X->limbsPtr[cntr] = X->limbsPtr[cntr + v0];
			}

			for (; cntr < X->n; cntr++)
			{
				X->limbsPtr[cntr] = (mbedtls_mpi_uint) 0;
			}
		}

		/*
		 * shift by count % limb_size
		 */
		if (v1 > 0UL)
		{
			for (cntr = X->n; cntr > 0UL; cntr--)
			{
				r1 = X->limbsPtr[cntr - (uint32) 1] << ((uint32) biL - v1);
				X->limbsPtr[cntr - (uint32) 1] >>= v1;
				X->limbsPtr[cntr - (uint32) 1] |= r0;
				r0 = r1;
			}
		}
	}
	return (ret);
}

/*
 * Compare unsigned values
 */

sint32 mbedtls_mpi_cmp_abs(const mbedtls_mpi* const X, const mbedtls_mpi* const Y)
{
	uint32 cntr, cntr2, cntr_temp;
	sint32 ret = 0;

	for (cntr = X->n; cntr > 0UL; cntr--)
	{
		if (X->limbsPtr[cntr - (uint32) 1] != 0UL)
		{
			break;
		}
	}
	for (cntr2 = Y->n; cntr2 > 0UL; cntr2--)
	{
		if (Y->limbsPtr[cntr2 - (uint32) 1] != 0UL)
		{
			break;
		}
	}
	cntr_temp = cntr + cntr2;
	if ((cntr_temp != 0UL) && (cntr > cntr2))
	{
		ret = (sint32) 1;
	}
	else if ((cntr_temp != 0UL) && (cntr2 > cntr))
	{
		ret = (sint32) -1;
	}
	else
	{
		for (; cntr > 0UL; cntr--)
		{
			if (X->limbsPtr[cntr - (uint32) 1] > Y->limbsPtr[cntr - (uint32) 1])
			{
				ret = 1;
			}
			if (X->limbsPtr[cntr - (uint32) 1] < Y->limbsPtr[cntr - (uint32) 1])
			{
				ret = -1;
			}
			if ((ret == (sint32)1) || (ret == (sint32)-1))
			{
				break;
			}
		}
	}
	return (ret);
}


/*
 * Compare signed values
 */
sint32 mbedtls_mpi_cmp_mpi(const mbedtls_mpi* const X, const mbedtls_mpi* const Y)
{
	uint32 cntr, cntr2;
	sint32 ret = 0;

	for (cntr = X->n; cntr > 0UL; cntr--)
	{
		if (X->limbsPtr[cntr - (uint32) 1] != 0UL)
		{
			break;
		}
	}

	for (cntr2 = Y->n; cntr2 > 0UL; cntr2--)
	{
		if (Y->limbsPtr[cntr2 - (uint32) 1] != 0UL)
		{
			break;
		}
	}

	if ((cntr == 0UL) && (cntr2 == 0UL))
	{
		/* Do Nothing as ret variable already initialized to ZERO */
	}
	else
	{
		if (cntr > cntr2)
		{
			ret = X->s;
		}
		else
		{
			if (cntr2 > cntr)
			{
				ret = -Y->s;
			}
			else
			{

				if ((X->s > (sint32)0) && (Y->s < (sint32)0))
				{
					ret = (sint32) 1;
				}
				else
				{
					if ((Y->s > (sint32)0) && (X->s < (sint32)0))
					{
						ret = (sint32) -1;
					}
					else
					{

						for (; cntr > 0UL; cntr--)
						{
							if (X->limbsPtr[cntr - (uint32) 1]
											> Y->limbsPtr[cntr - (uint32) 1])
							{
								ret = X->s;
							}
							if (X->limbsPtr[cntr - (uint32) 1]
											< Y->limbsPtr[cntr - (uint32) 1])
							{
								ret = -X->s;
							}
							if ((ret == X->s)||(ret == -X->s))
							{
								break;
							}
						}
					}
				}
			}
		}
	}
	return (ret);
}

/*
 * Compare signed values
 */
sint32 mbedtls_mpi_cmp_int(const mbedtls_mpi* const X, const mbedtls_mpi_sint z)
{
	mbedtls_mpi Y;
	mbedtls_mpi_uint ptr[1];

	*ptr =(mbedtls_mpi_uint) ((z < (sint32)0) ? -z : z);
	Y.s = (z < (sint32)0) ? (sint32)-1 : (sint32)1;
	Y.n = (uint32) 1;
	Y.limbsPtr = ptr;

	return (mbedtls_mpi_cmp_mpi(X, &Y));
}

/*
 * Unsigned addition: X = |A| + |B|  (HAC 14.7)
 */
sint32 mbedtls_mpi_add_abs(mbedtls_mpi* const X, const mbedtls_mpi* A,
		const mbedtls_mpi* B)
{
	sint32 ret = 0;
	uint32 cntr, cntr2;
	mbedtls_mpi_uint *Blimbs, *Xlimbs, carry, tmp;

	if (X == B)
	{
		const mbedtls_mpi* const T = A;
		A = X;
		B = T;
	}

	if (X != A)
	{
		ret = mbedtls_mpi_copy(X, A);
	}

	if (ret == (sint32)0)
	{
		/*
		 * X should always be positive as a result of unsigned additions.
		 */
		X->s = (sint32) 1;

		for (cntr2 = B->n; cntr2 > 0UL; cntr2--)
		{
			if (B->limbsPtr[cntr2 - (uint32) 1] != 0UL)
			{
				break;
			}
		}

		ret = mbedtls_mpi_grow(X, cntr2);
		if (!(ret != (sint32)0))
		{
			Blimbs = B->limbsPtr;
			Xlimbs = X->limbsPtr;
			carry = (mbedtls_mpi_uint) 0;

			/*
			 * tmp is used because it might happen that Xlimbs == Blimbs
			 */
			for (cntr = 0UL; cntr < cntr2; cntr++)
			{
				tmp = *Blimbs;
				*Xlimbs += carry;
				carry = (mbedtls_mpi_uint) (*Xlimbs < carry);
				*Xlimbs += tmp;
				carry += (mbedtls_mpi_uint) (*Xlimbs < tmp);

				Blimbs++;
				Xlimbs++;
			}

			while (carry != 0UL)
			{
				if (cntr >= X->n)
				{
					ret = mbedtls_mpi_grow(X, cntr + (uint32) 1);
					if (ret != (sint32)0)
					{
						break;
					}
					Xlimbs = X->limbsPtr + cntr;
				}

				*Xlimbs += carry;
				carry = (mbedtls_mpi_uint) (*Xlimbs < carry);
				cntr++;
				Xlimbs++;
			}
		}
	}

	return (ret);
}

/*
 * Helper for mbedtls_mpi subtraction
 */
static void mpi_sub_hlp(const uint32 n, const mbedtls_mpi_uint* s, mbedtls_mpi_uint *d)
{
	uint32 cntr = 0UL;
	mbedtls_mpi_uint carry = 0UL, z;

	for (; cntr < n; cntr++)
	{
		z = (mbedtls_mpi_uint) (*d < carry);
		*d -= carry;
		carry = (mbedtls_mpi_uint) (*d < *s) + z;
		*d -= *s;

		s++;
		d++;
	}

	while (carry != 0UL)
	{
		z = (mbedtls_mpi_uint) (*d < carry);
		*d -= carry;
		carry = z;
		cntr++;
		d++;
	}
}

/*
 * Unsigned subtraction: X = |A| - |B|  (HAC 14.9)
 */
sint32 mbedtls_mpi_sub_abs(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi *B)
{
	mbedtls_mpi TB;
	sint32 ret = (sint32)0;
	uint32 N;
	sint32 ret_cmp_abs;

	ret_cmp_abs = mbedtls_mpi_cmp_abs(A, B);

	if (ret_cmp_abs < (sint32)0)
	{
		ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
	}
	else
	{
		mbedtls_mpi_init(&TB);

		if (X == B)
		{
			ret = mbedtls_mpi_copy(&TB, B);
			if (!(ret != (sint32)0))
			{
				B = &TB;
			}
		}

		if (ret == (sint32)0)
		{
			if (X != A)
			{
				ret = mbedtls_mpi_copy(X, A);
			}

			if (ret == (sint32)0)
			{
				/*
				 * X should always be positive as a result of unsigned subtractions.
				 */
				X->s = (sint32) 1;

				ret = (sint32) 0;

				for (N = B->n; N > 0UL; N--)
				{
					if (B->limbsPtr[N - (uint32) 1] != 0UL)
					{
						break;
					}
				}

				mpi_sub_hlp(N, B->limbsPtr, X->limbsPtr);
			}

		}

		mbedtls_mpi_free(&TB);
	}
	return (ret);
}

/*
 * Signed addition: X = A + B
 */
sint32 mbedtls_mpi_add_mpi(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi* const B)
{
	const sint32 S = A->s;
	sint32 ret;

	if ((A->s * B->s) < (sint32)0)
	{
		ret = mbedtls_mpi_cmp_abs(A, B);
		if (ret >= (sint32)0)
		{
			ret = mbedtls_mpi_sub_abs(X, A, B);
			if (!(ret != (sint32)0))
			{
				X->s = S;
			}
		}
		else
		{
			ret = mbedtls_mpi_sub_abs(X, B, A);
			if (!(ret != (sint32)0))
			{
				X->s = -S;
			}

		}

	}
	else
	{
		ret = mbedtls_mpi_add_abs(X, A, B);
		if (!(ret != (sint32)0))
		{
			X->s = S;
		}
	}

	return (ret);
}

/*
 * Signed subtraction: X = A - B
 */
sint32 mbedtls_mpi_sub_mpi(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi* const B)
{
	sint32 ret;
	const sint32 S = A->s;

	if ((A->s * B->s) > (sint32)0)
	{
		ret = mbedtls_mpi_cmp_abs(A, B);
		if (ret >= (sint32)0)
		{
			ret = mbedtls_mpi_sub_abs(X, A, B);
			if (ret == (sint32)0)
			{
				X->s = S;
			}
		}
		else
		{
			ret = mbedtls_mpi_sub_abs(X, B, A);
			if (ret == (sint32)0)
			{
				X->s = -S;
			}
		}
	}
	else
	{
		ret = mbedtls_mpi_add_abs(X, A, B);
		if (ret == (sint32)0)
		{
			X->s = S;
		}
	}

	return (ret);
}
/*
 * Signed subtraction: X = A - b
 */
sint32 mbedtls_mpi_sub_int(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi_sint b)
{
	mbedtls_mpi B;
	mbedtls_mpi_uint ptr[1];

	ptr[0] = (mbedtls_mpi_uint) ((b < (sint32)0) ? -b : b);
	B.s = (b < (sint32)0) ? (sint32)-1 : (sint32)1;
	B.n = (uint32)1;
	B.limbsPtr = ptr;

	return (mbedtls_mpi_sub_mpi(X, A, &B));
}

/*
 * Helper for mbedtls_mpi multiplication
 */
static void mpi_mul_hlp(uint32 cntr, const mbedtls_mpi_uint* s, mbedtls_mpi_uint *d,
		const mbedtls_mpi_uint b)
{
	mbedtls_mpi_uint carry = 0UL;

	for (; cntr >= 16UL; cntr = cntr - 16UL)
	{
		mbedtls_mpi_uint s0, s1, b0, b1;
		mbedtls_mpi_uint r0, r1, rx, ry;
		b0 = (( (b) << (biH) ) >> (biH));
		b1 = ( (b) >> (biH) );
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
	}

	for (; cntr >=  8UL; cntr =  cntr - 8UL)
	{
		mbedtls_mpi_uint s0, s1, b0, b1;
		mbedtls_mpi_uint r0, r1, rx, ry;
		b0 = (( (b) << (biH) ) >> (biH));
		b1 = ( (b) >> (biH) );
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
		MULADDC_CORE;
	}

	for (; cntr > 0UL; cntr--)
	{
		mbedtls_mpi_uint s0, s1, b0, b1;
		mbedtls_mpi_uint r0, r1, rx, ry;
		b0 = (( (b) << (biH) ) >> (biH));
		b1 = ( (b) >> (biH) );
		MULADDC_CORE;
	}

	do
	{
		*d += carry;
		carry = (mbedtls_mpi_uint) (*d < carry);
		d++;
	} while (carry != 0UL);
}

/*
 * Baseline multiplication: X = A * B  (HAC 14.12)
 */
sint32 mbedtls_mpi_mul_mpi(mbedtls_mpi* const X, const mbedtls_mpi *A,
		const mbedtls_mpi *B)
{
	sint32 ret = 0;
	uint32 cntr, cntr2;
	mbedtls_mpi TA, TB;

	mbedtls_mpi_init(&TA);
	mbedtls_mpi_init(&TB);

	if (X == A)
	{
		ret = mbedtls_mpi_copy(&TA, A);
		if (!(ret != (sint32)0))
		{
			A = &TA;
		}
	}
	if (ret == (sint32)0)
	{

		if (X == B)
		{
			ret = mbedtls_mpi_copy(&TB, B);
			if (!(ret != (sint32)0))
			{
				B = &TB;
			}
		}

		if (ret == (sint32)0)
		{

			for (cntr = A->n; cntr > 0UL; cntr--)
			{
				if (A->limbsPtr[cntr - 1UL] != 0UL)
				{
					break;
				}
			}

			for (cntr2 = B->n; cntr2 > 0UL; cntr2--)
			{
				if (B->limbsPtr[cntr2 - 1UL] != 0UL)
				{
					break;
				}
			}

			ret = mbedtls_mpi_grow(X, cntr + cntr2);
			if (ret == (sint32)0)
			{
				ret = mbedtls_mpi_lset(X, 0);
			}

			if (ret == (sint32)0)
			{
				cntr++;
				for (; cntr2 > 0UL; cntr2--)
				{
					mpi_mul_hlp(cntr - 1UL, A->limbsPtr,
							X->limbsPtr + (cntr2 - 1UL),
							B->limbsPtr[cntr2 - 1UL]);
				}

				X->s = A->s * B->s;
			}
		}
	}

	mbedtls_mpi_free(&TB);
	mbedtls_mpi_free(&TA);
	return (ret);
}


/*
 * Baseline multiplication: X = A * b
 */
sint32 mbedtls_mpi_mul_int(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi_uint b)
{
	mbedtls_mpi b_tmp;
	mbedtls_mpi_uint ptr[1];

	b_tmp.s = (sint32) 1;
	b_tmp.n = (uint32) 1;
	b_tmp.limbsPtr = ptr;
	ptr[0] = b;

	return (mbedtls_mpi_mul_mpi(X, A, &b_tmp));
}

/*
 * Unsigned integer divide - double mbedtls_mpi_uint dividend, u1/u0, and
 * mbedtls_mpi_uint divisor, d
 */
static mbedtls_mpi_uint mbedtls_int_div_int(mbedtls_mpi_uint u1,
		mbedtls_mpi_uint u0, mbedtls_mpi_uint d, mbedtls_mpi_uint* const r)
{
	const mbedtls_mpi_uint radix = (mbedtls_mpi_uint) 1 << biH;
	const mbedtls_mpi_uint uint_halfword_mask =
			(mbedtls_mpi_uint) (((mbedtls_mpi_uint) 1 << (mbedtls_mpi_uint) biH)
					- (mbedtls_mpi_uint) 1);
	mbedtls_mpi_uint d0, d1, q0, q1, rAX, r0, quotient;
	mbedtls_mpi_uint u0_msw, u0_lsw;
	uint32 S;

	/*
	 * Check for overflow
	 */
	if ((0UL == d) || (u1 >= d))
	{
		if (r != NULL_PTR)
		{
			*r = (mbedtls_mpi_uint) BIGNUM_32BITS;
		}

		quotient = (mbedtls_mpi_uint) BIGNUM_32BITS;
	}
	else
	{
		/*
		 * Algorithm D, Section 4.3.1 - The Art of Computer Programming
		 *   Vol. 2 - Seminumerical Algorithms, Knuth
		 */

		/*
		 * Normalize the divisor, d, and dividend, u0, u1
		 */
		S = mbedtls_clz(d);
		d = d << S;

		u1 = u1 << S;
		/* The shifting by (biL - S) will not exceed 32 as bil is a macro with value equal to 32
		 * and s is the return value from function mbedtls_clz() which also not exceed 32.
		 * In other hand the shifting result by (biL - 1) is 31.
		 */
		u1 |= ( u0 >> ((uint32) biL - S) ) & (uint32)((uint32)-(mbedtls_mpi_sint) S >> (uint32)( (uint32)biL - (uint32)1U));
		u0 = u0 << S;

		d1 = d >> biH;
		d0 = d & uint_halfword_mask;

		u0_msw = u0 >> biH;
		u0_lsw = u0 & uint_halfword_mask;

		/*
		 * Find the first quotient and remainder
		 */
		q1 = u1 / d1;
		r0 = u1 - (d1 * q1);

		while ((q1 >= radix) || ((q1 * d0) > ((radix * r0) + u0_msw)))
		{
			q1 = q1 -(mbedtls_mpi_uint) 1;
			r0 += d1;

			if (r0 >= radix)
			{
				break;
			}
		}

		rAX = (u1 * radix) + (u0_msw - (q1 * d));
		q0 = rAX / d1;
		r0 = rAX - (q0 * d1);

		while ((q0 >= radix) || ((q0 * d0) > ((radix * r0) + u0_lsw)))
		{
			q0 -= (mbedtls_mpi_uint) 1;
			r0 += d1;

			if (r0 >= radix)
			{
				break;
			}
		}

		if (r != NULL_PTR)
		{
			*r = ((rAX * radix) + (u0_lsw - (q0 * d))) >> S;
		}
		quotient = (q1 * radix) + q0;
	}
	return quotient;
}

/*
 * Division by mbedtls_mpi: A = Q * B + R  (HAC 14.20)
 */
sint32 mbedtls_mpi_div_mpi(mbedtls_mpi* const Q, mbedtls_mpi* const R, const mbedtls_mpi* const A,
		const mbedtls_mpi* const B)
{
	sint32 ret = 0;
	uint32 cntr, N, t, bitLen;
	uint8 errFoundFlag = 0;
	mbedtls_mpi X, Y, Z, T1, T2;
	sint32 ret_cmp;

	ret_cmp = mbedtls_mpi_cmp_int(B, 0);

	if (ret_cmp == (sint32)0)
	{
		ret = MBEDTLS_ERR_MPI_DIVISION_BY_ZERO;
	}
	else
	{
		mbedtls_mpi_init(&X);
		mbedtls_mpi_init(&Y);
		mbedtls_mpi_init(&Z);
		mbedtls_mpi_init(&T1);
		mbedtls_mpi_init(&T2);

		ret_cmp = mbedtls_mpi_cmp_abs(A, B);

		if (ret_cmp < (sint32)0)
		{
			if (Q != NULL_PTR)
			{
				ret = mbedtls_mpi_lset(Q, 0);

			}

			if (ret == (sint32)0)
			{
				if (R != NULL_PTR)
				{
					ret = mbedtls_mpi_copy(R, A);

				}
				if (ret == (sint32)0)
				{
					ret = (sint32) 0;
				}

			}

		}
		else
		{
			ret = mbedtls_mpi_copy(&X, A);
			if (ret == (sint32)0)
			{
				ret = mbedtls_mpi_copy(&Y, B);
			}

			if (ret == (sint32)0)
			{
				X.s = (sint32)1;
				Y.s = (sint32)1;

				ret = mbedtls_mpi_grow(&Z, A->n + 2UL);
				if (ret == (sint32)0)
				{
					ret = mbedtls_mpi_lset(&Z, 0);

					if (ret == (sint32)0)
					{

						ret = mbedtls_mpi_grow(&T1, 2UL);
						if (ret == (sint32)0)
						{

							ret = mbedtls_mpi_grow(&T2, 3UL);
						}
					}
				}

				if (ret == (sint32)0)
				{
					bitLen = mbedtls_mpi_bitlen(&Y) % biL;
					if (bitLen < (uint32) ((uint32)biL - 1UL))
					{
						bitLen = (uint32)biL - 1UL - bitLen;

						ret = mbedtls_mpi_shift_l(&X, bitLen);
						if (ret == (sint32)0)
						{
							ret = mbedtls_mpi_shift_l(&Y, bitLen);
						}
					}
					else
					{
						bitLen = (uint32) 0;
					}

					if (ret == (sint32)0)
					{
						N = X.n - (uint32) 1;
						t = Y.n - (uint32) 1;
						ret = mbedtls_mpi_shift_l(&Y, (uint32) biL * (N - t));
						if (!(ret != (sint32)0))
						{
							ret_cmp = mbedtls_mpi_cmp_mpi(&X, &Y);
							while (ret_cmp >= (sint32)0)
							{
								Z.limbsPtr[N - t]++;
								ret = mbedtls_mpi_sub_mpi(&X, &X, &Y);
								if (ret != (sint32)0)
								{
									break;
								}
								ret_cmp = mbedtls_mpi_cmp_mpi(&X, &Y);
							}
							if (ret == (sint32)0)
							{
								ret = mbedtls_mpi_shift_r(&Y, (uint32) biL * (uint32) (N - t));
								if (!(ret != (sint32)0))
								{

									for (cntr = N; cntr > t; cntr--)
									{
										if (X.limbsPtr[cntr] >= Y.limbsPtr[t])
										{
											Z.limbsPtr[cntr - t - (uint32) 1] = BIGNUM_32BITS;
										}
										else
										{
											Z.limbsPtr[cntr - t - (uint32) 1] = mbedtls_int_div_int(
													X.limbsPtr[cntr], X.limbsPtr[cntr - (uint32) 1],
													Y.limbsPtr[t],
													NULL_PTR);
										}

										Z.limbsPtr[cntr - t - (uint32) 1]++;
										do
										{
											Z.limbsPtr[cntr - t - (uint32) 1]--;

											ret = mbedtls_mpi_lset(&T1, 0);
											if (ret == (sint32)0)
											{
												T1.limbsPtr[0] =
														(t < (uint32) 1) ?
																(mbedtls_mpi_uint) 0 :
																Y.limbsPtr[t - (uint32) 1];
												T1.limbsPtr[1] = Y.limbsPtr[t];

												ret = mbedtls_mpi_mul_int(&T1, &T1, Z.limbsPtr[cntr - t - 1UL]);

												if (ret == (sint32)0)
												{
													ret = mbedtls_mpi_lset(&T2, 0);
												}

												if (ret == (sint32)0)
												{
													T2.limbsPtr[0] = (cntr < 2) ? 0UL : X.limbsPtr[cntr - 2];
													T2.limbsPtr[1] = (cntr < 1) ? 0UL : X.limbsPtr[cntr - 1];
													T2.limbsPtr[2] = X.limbsPtr[cntr];
												}
												else
												{
													errFoundFlag = ((uint8) 1);
												}
											}
											else
											{
												errFoundFlag = (uint8)1;
											}

											if ((uint32)errFoundFlag == (uint32)1)
											{
												break;
											}
											ret_cmp = mbedtls_mpi_cmp_mpi(&T1, &T2);
										} while (ret_cmp > (sint32)0);

										if ((uint32)errFoundFlag != 1UL)
										{
											ret = mbedtls_mpi_mul_int(&T1, &Y, Z.limbsPtr[cntr - t - 1UL]);
											if (ret == (sint32)0)
											{
												ret = mbedtls_mpi_shift_l(&T1, biL * (cntr - t - 1UL));
												if (ret == (sint32)0)
												{
													ret = mbedtls_mpi_sub_mpi(&X, &X, &T1);
												}
											}

											if (ret == (sint32)0)
											{
												const sint32 mpi_cmp_int_ret = mbedtls_mpi_cmp_int(&X, (sint32)0);
												if ( mpi_cmp_int_ret < (sint32)0)
												{
													ret = mbedtls_mpi_copy(&T1, &Y);
													if (ret == (sint32)0)
													{
														ret = mbedtls_mpi_shift_l(&T1, biL * (cntr - t - 1UL));
														if (ret == (sint32)0)
														{
															ret = mbedtls_mpi_add_mpi(&X, &X, &T1);
														}
													}

													if (ret == (sint32)0)
													{
														Z.limbsPtr[cntr - t - 1UL]--;
													}
													else
													{
														errFoundFlag = (uint8)1;
													}
												}
											}
											else
											{
												errFoundFlag = (uint8)1;
											}
										}
									}

									if ((Q != NULL_PTR) && ((uint32)errFoundFlag != 1UL))
									{
										ret = mbedtls_mpi_copy(Q, &Z);
										if (ret == (sint32)0)
										{
											Q->s = A->s * B->s;
										}
										else
										{
											errFoundFlag = ((uint8) 1);
										}
									}

									if ((R != NULL_PTR) && ((uint32)errFoundFlag != 1UL))
									{
										ret = mbedtls_mpi_shift_r(&X, bitLen);
										if (ret == (sint32)0)
										{
											X.s = A->s;
										}
										else
										{
											errFoundFlag = ((uint8) 1);
										}
										ret = mbedtls_mpi_copy(R, &X);
										if ((ret == (sint32)0) && ((uint32)errFoundFlag != 1UL))
										{
											ret_cmp = mbedtls_mpi_cmp_int(R, 0);
											if (ret_cmp == (sint32)0)
											{
												R->s = ((sint32) 1);
											}
										}
									}
								}
							}
						}
					}
				}
			}

			mbedtls_mpi_free(&X);
			mbedtls_mpi_free(&Y);
			mbedtls_mpi_free(&Z);
			mbedtls_mpi_free(&T1);
			mbedtls_mpi_free(&T2);
		}
	}
	return (ret);
}
/*
 * Modulo: R = A mod B
 */
sint32 mbedtls_mpi_mod_mpi(mbedtls_mpi* const R, const mbedtls_mpi* const A,
		const mbedtls_mpi* const B)
{
	sint32 ret = 0;
	sint32 ret_cmp = 0;

	ret = mbedtls_mpi_cmp_int(B, 0);
	if (ret < (sint32)0)
	{
		ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
	}
	else
	{
		ret = mbedtls_mpi_div_mpi( NULL_PTR, R, A, B);
		if (ret == (sint32)0)
		{
			ret_cmp = mbedtls_mpi_cmp_int(R, 0);
			while (ret_cmp < (sint32)0)
			{
				ret = mbedtls_mpi_add_mpi(R, R, B);
				if (ret != (sint32)0)
				{
					break;
				}

				ret_cmp = mbedtls_mpi_cmp_int(R, 0);
			}

			ret_cmp = mbedtls_mpi_cmp_mpi(R, B);
			while (ret_cmp >= (sint32)0)
			{
				ret = mbedtls_mpi_sub_mpi(R, R, B);
				if (ret != (sint32)0)
				{
					break;
				}
				ret_cmp = mbedtls_mpi_cmp_mpi(R, B);
			}
		}
	}

	return (ret);
}
/*
 * Fast Montgomery initialization (thanks to Tom St Denis)
 */
static void mpi_montg_init(mbedtls_mpi_uint* const mm, const mbedtls_mpi* const N)
{
	mbedtls_mpi_uint x;
	const mbedtls_mpi_uint m0 = N->limbsPtr[0];
	sint32 cntr;

	x = m0;
	x += (((m0 + 2UL) & (uint32)4) << 1UL);
	for (cntr = (sint32) biL; cntr >= (sint32)8; cntr = (sint32)((uint32)cntr / (uint32)2))
	{

		x *= (mbedtls_mpi_uint)2 - (m0 * x);
	}

	*mm = ~x + 1UL;
}

/*
 * Montgomery multiplication: A = A * B * R^-1 mod N  (HAC 14.36)
 */
static sint32 mpi_montmul(mbedtls_mpi* const A, const mbedtls_mpi* const B,
		const mbedtls_mpi* const N, const mbedtls_mpi_uint mm, const mbedtls_mpi* const T)
{
	uint32 cntr, k, m;
	sint32 ret = 0;
	mbedtls_mpi_uint u0, u1, *d;
	sint32 ret_cmp_abs;

	if ((T->n < (N->n + 1UL)) || (T->limbsPtr == NULL_PTR))
	{
		ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
	}
	else
	{
		(void)memset(T->limbsPtr, 0, T->n * (uint32) ciL);

		d = T->limbsPtr;
		k = N->n;
		m = (B->n < k) ? B->n : k;

		for (cntr = (uint32) 0; cntr < k; cntr++)
		{

			/*
			 * T = (T + u0*B + u1*N) / 2^biL
			 */
			u0 = A->limbsPtr[cntr];
			u1 = (d[0] + (u0 * B->limbsPtr[0])) * mm;

			mpi_mul_hlp(m, B->limbsPtr, d, u0);
			mpi_mul_hlp(k, N->limbsPtr, d, u1);

			*d = u0;
			d++;
			d[k + (uint32) 1] = (mbedtls_mpi_uint) 0;
		}

		(void)memcpy(A->limbsPtr, d, (k + (uint32) 1) * (uint32) ciL);

		ret_cmp_abs = mbedtls_mpi_cmp_abs(A, N);

		if (ret_cmp_abs >= (sint32)0)
		{
			mpi_sub_hlp(k, N->limbsPtr, A->limbsPtr);
		}
		else
		{
			/* prevent timing attacks */
			mpi_sub_hlp(k, A->limbsPtr, T->limbsPtr);
		}
	}
	return (ret);
}

/*
 * Montgomery reduction: A = A * R^-1 mod N
 */
static sint32 mpi_montred(mbedtls_mpi* const A, const mbedtls_mpi* const N,
		const mbedtls_mpi_uint mm, const mbedtls_mpi* const T)
{
	mbedtls_mpi_uint z = (mbedtls_mpi_uint) 1;
	mbedtls_mpi U;

	U.n = (uint32) z;
	U.s = (sint32) z;
	U.limbsPtr = &z;

	return (mpi_montmul(A, &U, N, mm, T));
}

/*
 * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
 */
sint32 mbedtls_mpi_exp_mod(mbedtls_mpi* const X, const mbedtls_mpi* A,
		const mbedtls_mpi* const E, const mbedtls_mpi* const N, mbedtls_mpi* const RR)
{
	sint32 ret = 0, mpi_cmp_int = 0;
	uint32 wbits, wsize;
	uint32 cntr, size, nblimbs;
	uint32 bufsize, nbits;
	mbedtls_mpi_uint ei, mm, state;
	mbedtls_mpi RRtmp, T, W[2 << 8], Apos;
	uint32 neg;
	mpi_cmp_int = mbedtls_mpi_cmp_int(N, (sint32)0);

	if(((((mpi_cmp_int < ((sint32)0)))) != (sint32)0) ||
			((((((N->limbsPtr[0])) & 1UL))) != (sint32)0))
	{
		ret = mbedtls_mpi_cmp_int(E, 0);

		if (ret < (sint32)0)
		{
			ret = (sint32)MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
		}
	}
	else
	{
		ret = (sint32)MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
	}

	if (ret == (sint32)MBEDTLS_ERR_MPI_BAD_INPUT_DATA)
	{
	}
	else
	{
		/*
		 * Init temps and window size
		 */
		mpi_montg_init(&mm, N);
		mbedtls_mpi_init(&RRtmp);
		mbedtls_mpi_init(&T);
		mbedtls_mpi_init(&Apos);
		(void)memset(W, 0, sizeof(W));

		cntr = mbedtls_mpi_bitlen(E);

		wsize = (cntr > (uint32) 671)  ? ((uint32) 6) :
				((cntr > (uint32) 239) ? ((uint32) 5) :
						((cntr > (uint32) 79)  ? ((uint32) 4) :
								((cntr > (uint32) 23)  ? ((uint32) 3) : ((uint32) 1))));

		size = N->n + 1UL;

		ret = mbedtls_mpi_grow(X, size);
		if (ret == (sint32)0)
		{
			ret = mbedtls_mpi_grow(&W[1], size);
			if (ret == (sint32)0)
			{

				ret = mbedtls_mpi_grow(&T, size * 2UL);
			}
		}

		if (ret == (sint32)0)
		{
			/*
			 * Compensate for negative A (and correct at the end)
			 */
			neg = (A->s == (sint32)-1);
			if (neg == 1UL)
			{
				ret = mbedtls_mpi_copy(&Apos, A);
				if (ret == (sint32)0)
				{
					Apos.s = (sint32)1;
					A = &Apos;
				}
			}
			if (ret == (sint32)0)
			{
				/*
				 * If 1st call, pre-compute R^2 mod N
				 */
				if ((RR == NULL_PTR) || (RR->limbsPtr == NULL_PTR))
				{
					ret = mbedtls_mpi_lset(&RRtmp, 1UL);
					if (ret == (sint32)0)
					{

						ret = mbedtls_mpi_shift_l(&RRtmp, N->n * 2UL * biL);
						if (ret == (sint32)0)
						{
							ret = mbedtls_mpi_mod_mpi(&RRtmp, &RRtmp, N);
						}
					}

					if (ret != (sint32)0)
					{
						if (RR != NULL_PTR)
						{
							(void)memcpy(RR, &RRtmp, sizeof(mbedtls_mpi));
						}
					}

				}
				else
				{
					(void)memcpy(&RRtmp, RR, sizeof(mbedtls_mpi));
				}

				if (ret == (sint32)0)
				{
					/*
					 * W[1] = A * R^2 * R^-1 mod N = A * R mod N
					 */
					ret = mbedtls_mpi_cmp_mpi(A, N);
					if (ret >= (sint32)0)
					{
						ret = mbedtls_mpi_mod_mpi(&W[1], A, N);
					}
					else
					{
						ret = mbedtls_mpi_copy(&W[1], A);
					}

					if (ret == (sint32)0)
					{
						ret = mpi_montmul(&W[1], &RRtmp, N, mm, &T);

						if (ret == (sint32)0)
						{
							/*
							 * X = R^2 * R^-1 mod N = R mod N
							 */
							ret = mbedtls_mpi_copy(X, &RRtmp);

							if (ret == (sint32)0)
							{
								ret = mpi_montred(X, N, mm, &T);
							}
						}
					}

					if (ret == (sint32)0)
					{
						if (wsize > 1UL)
						{
							/*
							 * W[1 << (wsize - 1)] = W[1] ^ (wsize - 1)
							 */
							size = 1UL << (wsize - 1UL);

							ret = mbedtls_mpi_grow(&W[size], N->n + 1UL);
							if (ret == (sint32)0)
							{
								ret = mbedtls_mpi_copy(&W[size], &W[1]);
							}

							if (ret == (sint32)0)
							{
								for (cntr = 0UL; cntr < (wsize - 1UL); cntr++)
								{
									ret = mpi_montmul(&W[size], &W[size], N, mm, &T);
									if (ret != (sint32)0)
									{
										break;
									}
								}

								/*
								 * W[cntr] = W[cntr - 1] * W[1]
								 */
								for (cntr = size + 1UL; cntr < (1UL << wsize); cntr++)
								{
									ret = mbedtls_mpi_grow(&W[cntr], N->n + 1UL);
									if (ret == (sint32)0)
									{
										ret = mbedtls_mpi_copy(&W[cntr], &W[cntr - 1UL]);
										if (ret == (sint32)0)
										{
											ret = mpi_montmul(&W[cntr], &W[1], N, mm, &T);
										}
									}

									if (ret != (sint32)0)
									{
										break;
									}
								}
							}
						}

						if (ret == (sint32)0)
						{
							nblimbs = E->n;
							bufsize = 0UL;
							nbits =   0UL;
							wbits =   0UL;
							state = (mbedtls_mpi_uint)0;

							while (1UL)
							{
								if (bufsize == 0UL)
								{
									if (nblimbs == 0UL)
									{
										break;
									}

									nblimbs--;

									bufsize = sizeof(mbedtls_mpi_uint) << 3;
								}

								bufsize--;

								ei = (E->limbsPtr[nblimbs] >> bufsize) & 1UL;

								/*
								 * skip leading 0s
								 */
								if ((ei == 0UL) && (state == 0UL))
								{

									continue;
								}

								if ((ei == 0UL) && (state == 1UL))
								{
									/*
									 * out of window, square X
									 */
									ret = mpi_montmul(X, X, N, mm, &T);
									if (ret != (sint32)0)
									{
										break;
									}
									else
									{

										continue;
									}
								}

								/*
								 * add ei to current window
								 */

								state = 2UL;

								nbits++;
								wbits |= (ei << (wsize - nbits));

								if (nbits == wsize)
								{
									/*
									 * X = X^wsize R^-1 mod N
									 */
									for (cntr = 0; cntr < wsize; cntr++)
									{
										ret = mpi_montmul(X, X, N, mm, &T);
										if (ret != (sint32)0)
										{
											break;
										}
									}
									if (ret == (sint32)0)
									{
										/*
										 * X = X * W[wbits] R^-1 mod N
										 */
										ret = mpi_montmul(X, &W[wbits], N, mm, &T);
										if (ret == (sint32)0)
										{
											state--;
											nbits = 0UL;
											wbits = 0UL;
										}
									}
								}
							}

							if (ret == (sint32)0)
							{
								/*
								 * process the remaining bits
								 */
								for (cntr = 0UL; cntr < nbits; cntr++)
								{
									ret = mpi_montmul(X, X, N, mm, &T);

									if (ret == (sint32)0)
									{
										wbits <<= 1UL;

										if ((wbits & (1UL << wsize)) != 0UL)
										{
											ret = mpi_montmul(X, &W[1], N, mm, &T);
										}
									}

									if (ret != (sint32)0)
									{
										break;
									}
								}

								if (ret == (sint32)0)
								{
									/*
									 * X = A^E * R * R^-1 mod N = A^E mod N
									 */
									ret = mpi_montred(X, N, mm, &T);
									if (ret == (sint32)0)
									{
										if ((neg != 0UL) && (E->n != 0UL) && (E->limbsPtr[0] != 0UL))
										{
											X->s = -1;
											ret = (mbedtls_mpi_add_mpi(X, N, X));
										}
									}
								}
							}
						}
					}
				}
			}
		}

		for (cntr = (1UL << (wsize - (uint32) 1)); cntr < (1UL << wsize); cntr++)
		{
			mbedtls_mpi_free(&W[cntr]);
		}

		mbedtls_mpi_free(&W[1]);
		mbedtls_mpi_free(&T);
		mbedtls_mpi_free(&Apos);

		if ((RR == NULL_PTR) || (RR->limbsPtr == NULL_PTR))
		{
			mbedtls_mpi_free(&RRtmp);
		}
	}
	return ret;
}

/*
 * Greatest common divisor: G = gcd(A, B)  (HAC 14.54)
 */
sint32 mbedtls_mpi_gcd(mbedtls_mpi* const G, const mbedtls_mpi* const A,
		const mbedtls_mpi* const B)
{
	sint32 ret = 0;
	sint32 ret_cmp = 0;
	uint32 lz, lzt;
	mbedtls_mpi TG, TA, TB;
	uint8 brk = 0;

	mbedtls_mpi_init(&TG);
	mbedtls_mpi_init(&TA);
	mbedtls_mpi_init(&TB);

	ret = mbedtls_mpi_copy(&TA, A);
	if (ret == (sint32)0)
	{
		ret = mbedtls_mpi_copy(&TB, B);
	}

	if (ret == (sint32)0)
	{
		lz = mbedtls_mpi_lsb(&TA);
		lzt = mbedtls_mpi_lsb(&TB);

		if (lzt < lz)
		{
			lz = lzt;
		}

		ret = mbedtls_mpi_shift_r(&TA, lz);
		if (ret == (sint32)0)
		{
			ret = mbedtls_mpi_shift_r(&TB, lz);
		}

		if (ret == (sint32)0)
		{
			TA.s = (sint32) 1;
			TB.s = (sint32) 1;

			ret_cmp = mbedtls_mpi_cmp_int(&TA, 0);
			while (ret_cmp != (sint32)0)
			{
				ret = mbedtls_mpi_shift_r(&TA, mbedtls_mpi_lsb(&TA));
				if (ret == (sint32)0)
				{
					ret = mbedtls_mpi_shift_r(&TB, mbedtls_mpi_lsb(&TB));
				}

				if (ret != (sint32)0)
				{
					brk = (uint8)1;
				}
				if((uint32)brk == (uint32)0)
				{
					ret = mbedtls_mpi_cmp_mpi(&TA, &TB);
					if (ret >= (sint32)0)
					{
						ret = mbedtls_mpi_sub_abs(&TA, &TA, &TB);
						if (ret == (sint32)0)
						{
							ret = mbedtls_mpi_shift_r(&TA, 1);
						}

						if (ret != (sint32)0)
						{
							brk = (uint8)1;
						}
					}
					else
					{
						ret = mbedtls_mpi_sub_abs(&TB, &TB, &TA);
						if (ret == (sint32)0)
						{
							ret = mbedtls_mpi_shift_r(&TB, 1);
						}

						if (ret != (sint32)0)
						{
							brk = (uint8)1;
						}
					}
				}

				if((uint32)brk == (uint32)1)
				{
					break;
				}

				ret_cmp = mbedtls_mpi_cmp_int(&TA, 0);
			}

			if (ret == (sint32)0)
			{
				ret = mbedtls_mpi_shift_l(&TB, lz);
				if (ret == (sint32)0)
				{
					ret = mbedtls_mpi_copy(G, &TB);
				}
			}
		}
	}

	mbedtls_mpi_free(&TG);
	mbedtls_mpi_free(&TA);
	mbedtls_mpi_free(&TB);

	return (ret);
}

/*
 * Fill X with size bytes of random.
 *
 * Use a temporary bytes representation to make sure the result is the same
 * regardless of the platform endianness (useful when f_rng is actually
 * deterministic, eg for tests).
 */
sint32 mbedtls_mpi_fill_random(mbedtls_mpi* const X, const uint32 size,
		sint32 (*const f_rng)(void * p_rng, uint8 * buf, uint32 size), void* const p_rng)
{
	sint32 ret = 0;
	uint8 buf[1024];

	if (size >  1024)
	{
		ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
	}
	else
	{
		ret = f_rng(p_rng, buf, size);
		if (ret == (sint32)0)
		{
			ret = mbedtls_mpi_read_binary(X, buf, size);
		}
	}

	return (ret);
}

/*
 * Get a specific bit
 */
uint32 mbedtls_mpi_get_bit( const mbedtls_mpi * const X, const uint32 pos )
{
	MPI_VALIDATE_RET( X != NULL_PTR );

	if( ((X->n) * biL) <= pos )
	{
		return( 0 );
	}

	return( ( X->limbsPtr[pos / biL] >> ( pos % biL ) ) & 0x01 );
}

/*
 * Signed addition: X = A + b
 */
sint32 mbedtls_mpi_add_int( mbedtls_mpi * const X, const mbedtls_mpi * const A, const mbedtls_mpi_sint b )
{
	mbedtls_mpi Z;
	mbedtls_mpi_uint p[1];
	MPI_VALIDATE_RET( X != NULL_PTR );
	MPI_VALIDATE_RET( A != NULL_PTR );


	p[0] = ( b < 0 ) ? -b : b;
	Z.s = ( b < 0 ) ? -1 : 1;
	Z.n = 1;
	Z.limbsPtr = p;

	return( mbedtls_mpi_add_mpi( X, A, &Z ) );
}

/*
 * Modular inverse: X = A^-1 mod N  (HAC 14.61 / 14.64)
 */
sint32 mbedtls_mpi_inv_mod(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi* const N)
{
	sint32 ret = 0;
	sint32 ret_cmp = 0;
	mbedtls_mpi G, TA, TU, U1, U2, TB, TV, V1, V2;
	sint32 mpi_cmp_int = 0;
	ret = mbedtls_mpi_cmp_int(N, (mbedtls_mpi_sint) 1);
	if (ret <= (sint32)0)
	{
		ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
	}
	else
	{
		mbedtls_mpi_init(&TA);
		mbedtls_mpi_init(&TU);
		mbedtls_mpi_init(&U1);
		mbedtls_mpi_init(&U2);
		mbedtls_mpi_init(&G);
		mbedtls_mpi_init(&TB);
		mbedtls_mpi_init(&TV);
		mbedtls_mpi_init(&V1);
		mbedtls_mpi_init(&V2);
		ret = mbedtls_mpi_gcd(&G, A, N);
		if (ret == (sint32)0)
		{
			ret = mbedtls_mpi_cmp_int(&G, (mbedtls_mpi_sint) 1);
			if (ret != (sint32)0)
			{
				ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
			}
			else
			{
				ret = mbedtls_mpi_mod_mpi(&TA, A, N);
				if (ret == (sint32)0)
				{
					ret = mbedtls_mpi_copy(&TU, &TA);
					if (ret == (sint32)0)
					{
						ret = mbedtls_mpi_copy(&TB, N);
						if (ret == (sint32)0)
						{
							ret = mbedtls_mpi_copy(&TV, N);
							if (ret == (sint32)0)
							{
								ret = mbedtls_mpi_lset(&U1, 1);
								if (ret == (sint32)0)
								{
									ret = mbedtls_mpi_lset(&U2, 0);
									if (ret == (sint32)0)
									{
										ret = mbedtls_mpi_lset(&V1, 0);
										if (ret == (sint32)0)
										{
											ret = mbedtls_mpi_lset(&V2, 1);
										}
									}
								}
							}
						}
					}
				}

				if (ret == (sint32)0)
				{
					do
					{
						while ((TU.limbsPtr[0] & 1UL) == 0UL)
						{
							ret = mbedtls_mpi_shift_r(&TU, 1);
							if (ret == (sint32)0)
							{
								if (((U1.limbsPtr[0] & 1UL) != 0UL) || ((U2.limbsPtr[0] & 1UL) != 0UL))
								{
									ret = mbedtls_mpi_add_mpi(&U1, &U1, &TB);

									if (ret == (sint32)0)
									{
										ret = mbedtls_mpi_sub_mpi(&U2, &U2, &TA);
									}
								}
								if (ret == (sint32)0)
								{
									ret = mbedtls_mpi_shift_r(&U1, 1);

									if (ret == (sint32)0)
									{
										ret = mbedtls_mpi_shift_r(&U2, 1);
									}
								}
							}
							if (ret != (sint32)0)
							{
								break;
							}
						}

						if (ret == (sint32)0)
						{
							while ((TV.limbsPtr[0] & 1UL) == 0UL)
							{
								ret = mbedtls_mpi_shift_r(&TV, 1);
								if (ret == (sint32)0)
								{
									if (((V1.limbsPtr[0] & 1UL) != 0UL) || ((V2.limbsPtr[0] & 1UL) != 0UL))
									{
										ret = mbedtls_mpi_add_mpi(&V1, &V1, &TB);
										if (ret == (sint32)0)
										{
											ret = mbedtls_mpi_sub_mpi(&V2, &V2, &TA);
										}
									}

									if (ret == (sint32)0)
									{
										ret = mbedtls_mpi_shift_r(&V1, 1);
										if (ret == (sint32)0)
										{
											ret = mbedtls_mpi_shift_r(&V2, 1);
										}
									}
								}

								if (ret != (sint32)0)
								{
									break;
								}
							}

							if (ret == (sint32)0)
							{
								ret = mbedtls_mpi_cmp_mpi(&TU, &TV);
								if (ret >= (sint32)0)
								{
									ret = mbedtls_mpi_sub_mpi(&TU, &TU, &TV);
									if (ret == (sint32)0)
									{
										ret = mbedtls_mpi_sub_mpi(&U1, &U1, &V1);
										if (ret == (sint32)0)
										{
											ret = mbedtls_mpi_sub_mpi(&U2, &U2, &V2);
										}
									}
								}
								else
								{
									ret = mbedtls_mpi_sub_mpi(&TV, &TV, &TU);
									if (ret == (sint32)0)
									{

										ret = mbedtls_mpi_sub_mpi(&V1, &V1, &U1);
										if (ret == (sint32)0)
										{
											ret = mbedtls_mpi_sub_mpi(&V2, &V2, &U2);
										}
									}
								}

								if (ret == (sint32)0)
								{
									mpi_cmp_int = mbedtls_mpi_cmp_int(&TU, 0);
								}
							}
						}
						if (ret != (sint32)0)
						{
							break;
						}
					} while (mpi_cmp_int != (sint32)0);

					ret_cmp = mbedtls_mpi_cmp_int(&V1, 0);
					while (ret_cmp < (sint32)0)
					{
						ret = mbedtls_mpi_add_mpi(&V1, &V1, N);
						if (ret != (sint32)0)
						{
							break;
						}

						ret_cmp = mbedtls_mpi_cmp_int(&V1, 0);
					}

					ret_cmp = mbedtls_mpi_cmp_mpi(&V1, N);
					while (ret_cmp >= (sint32)0)
					{
						ret = mbedtls_mpi_sub_mpi(&V1, &V1, N);
						if (ret != (sint32)0)
						{
							break;
						}

						ret_cmp = mbedtls_mpi_cmp_mpi(&V1, N);
					}

					ret = mbedtls_mpi_copy(X, &V1);
				}
			}
		}

		mbedtls_mpi_free(&TA);
		mbedtls_mpi_free(&TU);
		mbedtls_mpi_free(&U1);
		mbedtls_mpi_free(&U2);
		mbedtls_mpi_free(&G);
		mbedtls_mpi_free(&TB);
		mbedtls_mpi_free(&TV);
		mbedtls_mpi_free(&V1);
		mbedtls_mpi_free(&V2);
	}
	return (ret);
}




