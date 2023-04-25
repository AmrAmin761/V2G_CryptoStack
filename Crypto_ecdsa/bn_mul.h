/**
 * \file bn_mul.h
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

#ifndef MBEDTLS_BN_MUL_H
#define MBEDTLS_BN_MUL_H

#include "bignum.h"


#define MULADDC_CORE                                                    \
		do                                                                      \
		{                                                                       \
			s0 = ( *s << (mbedtls_mpi_uint) (biH) ) >> (mbedtls_mpi_uint) (biH);\
			s1 = ( *s >> (mbedtls_mpi_uint) (biH) ) ; s++;                      \
			rx = s0 * b1; r0 = s0 * b0;                                         \
			ry = s1 * b0; r1 = s1 * b1;                                         \
			r1 += ( rx >> (biH) );                                              \
			r1 += ( ry >> (biH) );                                              \
			rx <<= ((mbedtls_mpi_uint) (biH)); ry <<= (mbedtls_mpi_uint) (biH); \
			r0 += rx; r1 += (mbedtls_mpi_uint) (r0 < rx);                       \
			r0 += ry; r1 += (mbedtls_mpi_uint) (r0 < ry);                       \
			r0 +=  carry; r1 += (mbedtls_mpi_uint) (r0 <  carry);               \
			r0 += *d; r1 += (mbedtls_mpi_uint) (r0 < *d);                       \
			carry = r1; *d = r0;                                                \
			(d++);                                                              \
		}while(0)

#endif
