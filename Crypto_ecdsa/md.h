 /**
 * \file md.h
 *
 * \brief This file contains the generic message-digest wrapper.
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */


#ifndef MBEDTLS_MD_H
#define MBEDTLS_MD_H

   
#include <string.h>
   
#define MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE                (-0x5080)  /**< The selected feature is not available. */
#define MBEDTLS_ERR_MD_BAD_INPUT_DATA                     (-0x5100)  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_MD_ALLOC_FAILED                       (-0x5180)  /**< Failed to allocate memory. */
#define MBEDTLS_ERR_MD_FILE_IO_ERROR                      (-0x5200)  /**< Opening or reading of file failed. */

/* MBEDTLS_ERR_MD_HW_ACCEL_FAILED is deprecated and should not be used. */
#define MBEDTLS_ERR_MD_HW_ACCEL_FAILED                    (-0x5280)  /**< MD hardware accelerator failed. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief     Supported message digests.
 *
 * \warning   MD2, MD4, MD5 and SHA-1 are considered weak message digests and
 *            their use constitutes a security risk. We recommend considering
 *            stronger message digests instead.
 *
 */
typedef enum {
    MBEDTLS_MD_NONE=0,    /**< None. */
    MBEDTLS_MD_MD2,       /**< The MD2 message digest. */
    MBEDTLS_MD_MD4,       /**< The MD4 message digest. */
    MBEDTLS_MD_MD5,       /**< The MD5 message digest. */
    MBEDTLS_MD_SHA1,      /**< The SHA-1 message digest. */
    MBEDTLS_MD_SHA224,    /**< The SHA-224 message digest. */
    MBEDTLS_MD_SHA256,    /**< The SHA-256 message digest. */
    MBEDTLS_MD_SHA384,    /**< The SHA-384 message digest. */
    MBEDTLS_MD_SHA512,    /**< The SHA-512 message digest. */
    MBEDTLS_MD_RIPEMD160 /**< The RIPEMD-160 message digest. */
} mbedtls_md_type_t;

#define MBEDTLS_MD_MAX_SIZE         32  /* longest known is SHA256 or less */

/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 */
typedef struct mbedtls_md_info_t
{
    /** Digest identifier */
    mbedtls_md_type_t type;

    /** Name of the message digest */
    const char * name;

    /** Output length of the digest function in bytes */
    int size;

    /** Block length of the digest function in bytes */
    int block_size;

    /** Digest initialisation function */
    int (*starts_func)( void *const ctx );

    /** Digest update function */
    int (*update_func)( void *const ctx, const unsigned char *const input, const size_t ilen );

    /** Digest finalisation function */
    int (*finish_func)( void *const ctx, unsigned char *const output );

    /** Generic digest function */
    int (*digest_func)( const unsigned char *const input, const size_t ilen,
                        unsigned char *const output );

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *const ctx );

    /** Clone state from a context */
    void (*clone_func)( void *const dst, const void *const src );

    /** Internal use only */
    int (*process_func)( void *const ctx, const unsigned char *const data );
}
mbedtls_md_info_t_s;

/**
 * The generic message-digest context.
 */
typedef struct mbedtls_md_context_t
{
    /** Information about the associated message digest. */
    const mbedtls_md_info_t_s *md_info;

    /** The digest-specific context. */
    void *md_ctx;

    /** The HMAC part of the context. */
    void *hmac_ctx;
} mbedtls_md_context_t_s;

/**
 * \brief           This function returns the message-digest information
 *                  associated with the given digest type.
 *
 * \param md_type   The type of digest to search for.
 *
 * \return          The message-digest information associated with \p md_type.
 * \return          NULL if the associated message-digest information is not found.
 */
const mbedtls_md_info_t_s *mbedtls_md_info_from_type( const mbedtls_md_type_t md_type );

/**
 * \brief           This function clears the internal structure of \p ctx and
 *                  frees any embedded internal structure, but does not free
 *                  \p ctx itself.
 *
 *                  If you have called mbedtls_md_setup() on \p ctx, you must
 *                  call mbedtls_md_free() when you are no longer using the
 *                  context.
 *                  Calling this function if you have previously
 *                  called mbedtls_md_init() and nothing else is optional.
 *                  You must not call this function if you have not called
 *                  mbedtls_md_init().
 */
void mbedtls_md_free( mbedtls_md_context_t_s *const ctx );



/**
 * \brief           This function selects the message digest algorithm to use,
 *                  and allocates internal structures.
 *
 *                  It should be called after mbedtls_md_init() or
 *                  mbedtls_md_free(). Makes it necessary to call
 *                  mbedtls_md_free() later.
 *
 * \param ctx       The context to set up.
 * \param md_info   The information structure of the message-digest algorithm
 *                  to use.
 * \param hmac      Defines if HMAC is used. 0: HMAC is not used (saves some memory),
 *                  or non-zero: HMAC is used with this context.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 * \return          #MBEDTLS_ERR_MD_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_md_setup( mbedtls_md_context_t_s *const ctx, const mbedtls_md_info_t_s *const md_info, const int hmac );

/**
 * \brief           This function extracts the message-digest size from the
 *                  message-digest information structure.
 *
 * \param md_info   The information structure of the message-digest algorithm
 *                  to use.
 *
 * \return          The size of the message-digest output in Bytes.
 */
unsigned int mbedtls_md_get_size( const mbedtls_md_info_t_s *const md_info );

/**
 * \brief           This function sets the HMAC key and prepares to
 *                  authenticate a new message.
 *
 *                  Call this function after mbedtls_md_setup(), to use
 *                  the MD context for an HMAC calculation, then call
 *                  mbedtls_md_hmac_update() to provide the input data, and
 *                  mbedtls_md_hmac_finish() to get the HMAC value.
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 * \param key       The HMAC secret key.
 * \param keylen    The length of the HMAC key in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int mbedtls_md_hmac_starts( mbedtls_md_context_t_s *const ctx, const unsigned char *key,
                    size_t keylen );

/**
 * \brief           This function feeds an input buffer into an ongoing HMAC
 *                  computation.
 *
 *                  Call mbedtls_md_hmac_starts() or mbedtls_md_hmac_reset()
 *                  before calling this function.
 *                  You may call this function multiple times to pass the
 *                  input piecewise.
 *                  Afterwards, call mbedtls_md_hmac_finish().
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 * \param input     The buffer holding the input data.
 * \param ilen      The length of the input data.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int mbedtls_md_hmac_update( mbedtls_md_context_t_s *const ctx, const unsigned char *const input, const size_t ilen );

/**
 * \brief           This function finishes the HMAC operation, and writes
 *                  the result to the output buffer.
 *
 *                  Call this function after mbedtls_md_hmac_starts() and
 *                  mbedtls_md_hmac_update() to get the HMAC value. Afterwards
 *                  you may either call mbedtls_md_free() to clear the context,
 *                  or call mbedtls_md_hmac_reset() to reuse the context with
 *                  the same HMAC key.
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 * \param output    The generic HMAC checksum result.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int mbedtls_md_hmac_finish( mbedtls_md_context_t_s *const ctx, unsigned char *const output );

/**
 * \brief           This function prepares to authenticate a new message with
 *                  the same key as the previous HMAC operation.
 *
 *                  You may call this function after mbedtls_md_hmac_finish().
 *                  Afterwards call mbedtls_md_hmac_update() to pass the new
 *                  input.
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int mbedtls_md_hmac_reset( mbedtls_md_context_t_s *const ctx );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_MD_H */
