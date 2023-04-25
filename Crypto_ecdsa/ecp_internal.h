/**
 * \file ecp_internal.h
 *
 * \brief Function declarations for alternative implementation of elliptic curve
 * point arithmetic.
 */
/*
 *  Copyright (C) 2016, ARM Limited, All Rights Reserved
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
 * [1] BERNSTEIN, Daniel J. Curve25519: new Diffie-Hellman speed records.
 *     <http://cr.yp.to/ecdh/curve25519-20060209.pdf>
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
 *
 * [4] Certicom Research. SEC 2: Recommended Elliptic Curve Domain Parameters.
 *     <http://www.secg.org/sec2-v2.pdf>
 *
 * [5] HANKERSON, Darrel, MENEZES, Alfred J., VANSTONE, Scott. Guide to Elliptic
 *     Curve Cryptography.
 *
 * [6] Digital Signature Standard (DSS), FIPS 186-4.
 *     <http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
 *
 * [7] Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer
 *     Security (TLS), RFC 4492.
 *     <https://tools.ietf.org/search/rfc4492>
 *
 * [8] <http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html>
 *
 * [9] COHEN, Henri. A Course in Computational Algebraic Number Theory.
 *     Springer Science & Business Media, 1 Aug 2000
 */

#ifndef MBEDTLS_ECP_INTERNAL_H
#define MBEDTLS_ECP_INTERNAL_H

#include <string.h>

/**
 * \brief           Indicate if the Elliptic Curve Point module extension can
 *                  handle the group.
 *
 * \param grp       The pointer to the elliptic curve group that will be the
 *                  basis of the cryptographic computations.
 *
 * \return          Non-zero if successful.
 */
unsigned char mbedtls_internal_ecp_grp_capable( const mbedtls_ecp_group_s *grp );

/**
 * \brief           Initialise the Elliptic Curve Point module extension.
 *
 *                  If mbedtls_internal_ecp_grp_capable returns true for a
 *                  group, this function has to be able to initialise the
 *                  module for it.
 *
 *                  This module can be a driver to a crypto hardware
 *                  accelerator, for which this could be an initialise function.
 *
 * \param grp       The pointer to the group the module needs to be
 *                  initialised for.
 *
 * \return          0 if successful.
 */
int mbedtls_internal_ecp_init( const mbedtls_ecp_group_s *grp );

/**
 * \brief           Frees and deallocates the Elliptic Curve Point module
 *                  extension.
 *
 * \param grp       The pointer to the group the module was initialised for.
 */
void mbedtls_internal_ecp_free( const mbedtls_ecp_group_s *grp );


#endif /* ecp_internal.h */

