/**
 * \file bignum.h
 *
 * \brief  Multi-precision integer library
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


#ifndef MBEDTLS_BIGNUM_H
#define MBEDTLS_BIGNUM_H


#include "Crypto_Types_General.h"

#define MBEDTLS_ERR_MPI_FILE_IO_ERROR                     (-0x0002)  /**< An error occurred while reading from or writing to a file. */
#define MBEDTLS_ERR_MPI_BAD_INPUT_DATA                    (-0x0004)  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_MPI_INVALID_CHARACTER                 (-0x0006)  /**< There is an invalid character in the digit string. */
#define MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL                  (-0x0008)  /**< The buffer is too small to write to. */
#define MBEDTLS_ERR_MPI_NEGATIVE_VALUE                    (-0x000A)  /**< The input arguments are negative or result in illegal output. */
#define MBEDTLS_ERR_MPI_DIVISION_BY_ZERO                  (-0x000C)  /**< The input argument for division is zero, which is not allowed. */
#define MBEDTLS_ERR_MPI_NOT_ACCEPTABLE                    (-0x000E)  /**< The input arguments are not acceptable. */
#define MBEDTLS_ERR_MPI_ALLOC_FAILED                      (-0x0010)  /**< Memory allocation failed. */

#define MBEDTLS_MPI_CHK(f) do { if( ( ret = f ) != 0 ) {goto cleanup;} } while( 0 )
/*
 * Maximum size MPIs are allowed to grow to in number of limbs.
 */
#define MBEDTLS_MPI_MAX_LIMBS                             10000

#define MBEDTLS_MPI_MAX_BITS                              ( 8 * 1024 )    /**< Maximum number of bits for usable MPIs. */

/*
 * When reading from files with mbedtls_mpi_read_file() and writing to files with
 * mbedtls_mpi_write_file() the buffer should have space
 * for a (short) label, the MPI (in the provided radix), the newline
 * characters and the '\0'.
 *
 * By default we assume at least a 10 char label, a minimum radix of 10
 * (decimal) and a maximum of 4096 bit numbers (1234 decimal chars).
 * Autosized at compile time for at least a 10 char label, a minimum radix
 * of 10 (decimal) for a number of MBEDTLS_MPI_MAX_BITS size.
 *
 * This used to be statically sized to 1250 for a maximum of 4096 bit
 * numbers (1234 decimal chars).
 *
 * Calculate using the formula:
 *  MBEDTLS_MPI_RW_BUFFER_SIZE = ceil(MBEDTLS_MPI_MAX_BITS / ln(10) * ln(2)) +
 *                                LabelSize + 6
 */
#define MBEDTLS_MPI_MAX_BITS_SCALE100          (100 * MBEDTLS_MPI_MAX_BITS)
#define MBEDTLS_LN_2_DIV_LN_10_SCALE100                332
#define MBEDTLS_MPI_RW_BUFFER_SIZE             (((MBEDTLS_MPI_MAX_BITS_SCALE100 + MBEDTLS_LN_2_DIV_LN_10_SCALE100 - 1)\
		/ MBEDTLS_LN_2_DIV_LN_10_SCALE100) + 10 + 6 )

/*
 * Define the base integer type, architecture-wise.
 *
 * 32-bit integers can be forced on 64-bit arches (eg. for testing purposes)
 * by defining MBEDTLS_HAVE_INT32 and undefining MBEDTLS_HAVE_ASM
 */
typedef  sint32 mbedtls_mpi_sint;
typedef uint32 mbedtls_mpi_uint;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          MPI structure
 */


typedef struct
{
	sint32 s;              /*!<  integer sign      */
	uint32 n;           /*!<  total # of limbs  */
	mbedtls_mpi_uint *limbsPtr;          /*!<  pointer to limbs  */
}
mbedtls_mpi;


/**
 * \brief           Initialize one MPI (make internal references valid)
 *                  This just makes it ready to be set or freed,
 *                  but does not define a value for the MPI.
 *
 * \param X         One MPI to initialize.
 */
void mbedtls_mpi_init(mbedtls_mpi* const X);

/**
 * \brief          Unallocate one MPI
 *
 * \param X        One MPI to unallocate.
 */
void mbedtls_mpi_free(mbedtls_mpi* const X);

/**
 * \brief          Enlarge to the specified number of limbs
 *
 * \param X        MPI to grow
 * \param nblimbs  The target number of limbs
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_grow(mbedtls_mpi* const X, const uint32 nblimbs);

/**
 * \brief          Resize down, keeping at least the specified number of limbs
 *
 * \param X        MPI to shrink
 * \param nblimbs  The minimum number of limbs to keep
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_shrink( mbedtls_mpi * const X, const uint32 nblimbs );

/**
 * \brief          Copy the contents of Y into X
 *
 * \param X        Destination MPI
 * \param Y        Source MPI
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_copy(mbedtls_mpi* const X, const mbedtls_mpi* const Y);

/**
 * \brief          Swap the contents of X and Y
 *
 * \param X        First MPI value
 * \param Y        Second MPI value
 */
void mbedtls_mpi_swap( mbedtls_mpi *X, mbedtls_mpi *Y );

/**
 * \brief          Safe conditional assignement X = Y if assign is 1
 *
 * \param X        MPI to conditionally assign to
 * \param Y        Value to be assigned
 * \param assign   1: perform the assignment, 0: keep X's original value
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *
 * \note           This function is equivalent to
 *                      if( assign ) mbedtls_mpi_copy( X, Y );
 *                 except that it avoids leaking any information about whether
 *                 the assignment was done or not (the above code may leak
 *                 information through branch prediction and/or memory access
 *                 patterns analysis).
 */
sint32 mbedtls_mpi_safe_cond_assign( mbedtls_mpi * const X, const mbedtls_mpi * const Y, uint8 assign );

/**
 * \brief          Safe conditional swap X <-> Y if swap is 1
 *
 * \param X        First mbedtls_mpi value
 * \param Y        Second mbedtls_mpi value
 * \param assign   1: perform the swap, 0: keep X and Y's original values
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *
 * \note           This function is equivalent to
 *                      if( assign ) mbedtls_mpi_swap( X, Y );
 *                 except that it avoids leaking any information about whether
 *                 the assignment was done or not (the above code may leak
 *                 information through branch prediction and/or memory access
 *                 patterns analysis).
 */
sint32 mbedtls_mpi_safe_cond_swap( mbedtls_mpi * const X, mbedtls_mpi * const Y, uint8 swap );

/**
 * \brief          Set value from integer
 *
 * \param X        MPI to set
 * \param z        Value to use
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_lset(mbedtls_mpi* const X, const mbedtls_mpi_sint z);

/**
 * \brief          Get a specific bit from X
 *
 * \param X        MPI to use
 * \param pos      Zero-based index of the bit in X
 *
 * \return         Either a 0 or a 1
 */
uint32 mbedtls_mpi_get_bit( const mbedtls_mpi * const X, const uint32 pos );

/**
 * \brief          Set a bit of X to a specific value of 0 or 1
 *
 * \note           Will grow X if necessary to set a bit to 1 in a not yet
 *                 existing limb. Will not grow if bit should be set to 0
 *
 * \param X        MPI to use
 * \param pos      Zero-based index of the bit in X
 * \param val      The value to set the bit to (0 or 1)
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *                 MBEDTLS_ERR_MPI_BAD_INPUT_DATA if val is not 0 or 1
 */
sint32 mbedtls_mpi_set_bit( mbedtls_mpi * const X, const uint32 pos, const uint8 val );

/**
 * \brief          Return the number of zero-bits before the least significant
 *                 '1' bit
 *
 * Note: Thus also the zero-based index of the least significant '1' bit
 *
 * \param X        MPI to use
 */
uint32 mbedtls_mpi_lsb(const mbedtls_mpi* const X);

/**
 * \brief          Return the number of bits up to and including the most
 *                 significant '1' bit'
 *
 * Note: Thus also the one-based index of the most significant '1' bit
 *
 * \param X        MPI to use
 */
uint32 mbedtls_mpi_bitlen(const mbedtls_mpi* const X);

/**
 * \brief          Return the total size in bytes
 *
 * \param X        MPI to use
 */
uint32 mbedtls_mpi_size(const mbedtls_mpi* const X);

/**
 * \brief          Import X from unsigned binary data, big endian
 *
 * \param X        Destination MPI
 * \param buf      Input buffer
 * \param buflen   Input buffer size
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_read_binary(mbedtls_mpi* const X, 
		const uint8* const buf, const uint32 buflen);

/**
 * \brief          Export X into unsigned binary data, big endian.
 *                 Always fills the whole buffer, which will start with zeros
 *                 if the number is smaller.
 *
 * \param X        Source MPI
 * \param buf      Output buffer
 * \param buflen   Output buffer size
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if buf isn't large enough
 */
sint32 mbedtls_mpi_write_binary(const mbedtls_mpi* const X, 
		uint8* const buf, const uint32 buflen);

/**
 * \brief          Left-shift: X <<= count
 *
 * \param X        MPI to shift
 * \param count    Amount to shift
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_shift_l(mbedtls_mpi* const X, const uint32 count);

/**
 * \brief          Right-shift: X >>= count
 *
 * \param X        MPI to shift
 * \param count    Amount to shift
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_shift_r(mbedtls_mpi* const X, const uint32 count);

/**
 * \brief          Compare unsigned values
 *
 * \param X        Left-hand MPI
 * \param Y        Right-hand MPI
 *
 * \return         1 if |X| is greater than |Y|,
 *                -1 if |X| is lesser  than |Y| or
 *                 0 if |X| is equal to |Y|
 */
sint32 mbedtls_mpi_cmp_abs(const mbedtls_mpi* const X, const mbedtls_mpi* const Y);

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand MPI
 * \param Y        Right-hand MPI
 *
 * \return         1 if X is greater than Y,
 *                -1 if X is lesser  than Y or
 *                 0 if X is equal to Y
 */
sint32 mbedtls_mpi_cmp_mpi(const mbedtls_mpi* const X, const mbedtls_mpi* const Y);

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand MPI
 * \param z        The integer value to compare to
 *
 * \return         1 if X is greater than z,
 *                -1 if X is lesser  than z or
 *                 0 if X is equal to z
 */
sint32 mbedtls_mpi_cmp_int(const mbedtls_mpi* const X, const mbedtls_mpi_sint z);

/**
 * \brief          Unsigned addition: X = |A| + |B|
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_add_abs(mbedtls_mpi* const X, 
		const mbedtls_mpi* A, const mbedtls_mpi* B);

/**
 * \brief          Unsigned subtraction: X = |A| - |B|
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_NEGATIVE_VALUE if B is greater than A
 */
sint32 mbedtls_mpi_sub_abs(mbedtls_mpi* const X, 
		const mbedtls_mpi* const A, const mbedtls_mpi *B);

/**
 * \brief          Signed addition: X = A + B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_add_mpi(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi* const B);

/**
 * \brief          Signed subtraction: X = A - B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_sub_mpi(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi* const B);


/**
 * \brief          Signed addition: X = A + b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to add
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_add_int( mbedtls_mpi * const X, const mbedtls_mpi * const A, const mbedtls_mpi_sint b );

/**
 * \brief          Signed subtraction: X = A - b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to subtract
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_sub_int(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi_sint b);

/**
 * \brief          Baseline multiplication: X = A * B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_mul_mpi(mbedtls_mpi* const X, const mbedtls_mpi *A,
		const mbedtls_mpi *B);

/**
 * \brief          Baseline multiplication: X = A * b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The unsigned integer value to multiply with
 *
 * \note           b is unsigned
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_mul_int(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi_uint b);

/**
 * \brief          Division by mbedtls_mpi: A = Q * B + R
 *
 * \param Q        Destination MPI for the quotient
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *                 MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if B == 0
 *
 * \note           Either Q or R can be NULL.
 */
sint32 mbedtls_mpi_div_mpi(mbedtls_mpi* const Q, mbedtls_mpi* const R,
		const mbedtls_mpi* const A, const mbedtls_mpi* const B);

/**
 * \brief          Division by int: A = Q * b + R
 *
 * \param Q        Destination MPI for the quotient
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param b        Integer to divide by
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *                 MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if b == 0
 *
 * \note           Either Q or R can be NULL.
 */
sint32 mbedtls_mpi_div_int( mbedtls_mpi *Q, mbedtls_mpi *R, 
		const mbedtls_mpi *A, mbedtls_mpi_sint b );

/**
 * \brief          Modulo: R = A mod B
 *
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *                 MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if B == 0,
 *                 MBEDTLS_ERR_MPI_NEGATIVE_VALUE if B < 0
 */
sint32 mbedtls_mpi_mod_mpi(mbedtls_mpi* const R, 
		const mbedtls_mpi* const A, const mbedtls_mpi* const B);

/**
 * \brief          Modulo: r = A mod b
 *
 * \param r        Destination mbedtls_mpi_uint
 * \param A        Left-hand MPI
 * \param b        Integer to divide by
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *                 MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if b == 0,
 *                 MBEDTLS_ERR_MPI_NEGATIVE_VALUE if b < 0
 */
sint32 mbedtls_mpi_mod_int( mbedtls_mpi_uint *r, 
		const mbedtls_mpi *A, mbedtls_mpi_sint b );

/**
 * \brief          Sliding-window exponentiation: X = A^E mod N
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param E        Exponent MPI
 * \param N        Modular MPI
 * \param _RR      Speed-up MPI used for recalculations
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *                 MBEDTLS_ERR_MPI_BAD_INPUT_DATA if N is negative or even or
 *                 if E is negative
 *
 * \note           _RR is used to avoid re-computing R*R mod N across
 *                 multiple calls, which speeds up things a bit. It can
 *                 be set to NULL if the extra performance is unneeded.
 */
sint32 mbedtls_mpi_exp_mod(mbedtls_mpi* const X, const mbedtls_mpi* A,
		const mbedtls_mpi* const E, const mbedtls_mpi* const N, mbedtls_mpi* const RR);

/**
 * \brief          Fill an MPI X with size bytes of random
 *
 * \param X        Destination MPI
 * \param size     Size in bytes
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_fill_random(mbedtls_mpi* const X, const uint32 size,
		sint32 (* const f_rng)(void * p_rng, uint8 * buf, uint32 size), void* const p_rng);

/**
 * \brief          Greatest common divisor: G = gcd(A, B)
 *
 * \param G        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
sint32 mbedtls_mpi_gcd(mbedtls_mpi* const G, const mbedtls_mpi* const A,
		const mbedtls_mpi* const B);

/**
 * \brief          Modular inverse: X = A^-1 mod N
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param N        Right-hand MPI
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *                 MBEDTLS_ERR_MPI_BAD_INPUT_DATA if N is <= 1,
                   MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if A has no inverse mod N.
 */
sint32 mbedtls_mpi_inv_mod(mbedtls_mpi* const X, const mbedtls_mpi* const A,
		const mbedtls_mpi* const N);


/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
sint32 mbedtls_mpi_self_test( sint32 verbose );

#ifdef __cplusplus
}
#endif

#endif /* bignum.h */
