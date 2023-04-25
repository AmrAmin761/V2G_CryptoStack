/**
 * \file memory_buffer_alloc.h
 *
 * \brief Buffer-based memory allocator
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

#ifndef MBEDTLS_MEMORY_BUFFER_ALLOC_H
#define MBEDTLS_MEMORY_BUFFER_ALLOC_H


#include "Crypto_Types_General.h"


/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * \{
 */

#define MBEDTLS_MEMORY_ALIGN_MULTIPLE       4 /**< Align on multiples of this value */

#define MBEDTLS_BUFFER_ALLOCATION_CONTEXT_SIZE       20 /**< Size in bytes of buffer allocation context */

/* \} name SECTION: Module settings */

#define MBEDTLS_MEMORY_VERIFY_NONE          0U
#define MBEDTLS_MEMORY_VERIFY_ALLOC         (1U << 0U)
#define MBEDTLS_MEMORY_VERIFY_FREE          (1U << 1U)
#define MBEDTLS_MEMORY_VERIFY_ALWAYS        (MBEDTLS_MEMORY_VERIFY_ALLOC | MBEDTLS_MEMORY_VERIFY_FREE)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief   Initialize use of stack-based memory allocator.
 *          The stack-based allocator does memory management inside the
 *          presented buffer and does not call calloc() and free().
 *          It sets the global mbedtls_calloc() and mbedtls_free() pointers
 *          to its own functions.
 *          (Provided mbedtls_calloc() and mbedtls_free() are thread-safe if
 *           MBEDTLS_THREADING_C is defined)
 *
 * \note    This code is not optimized and provides a straight-forward
 *          implementation of a stack-based memory allocator.
 *
 * \param buf   buffer to use as heap
 * \param len   size of the buffer
 */
void mbedtls_memory_buffer_alloc_init(uint8 *buf, uint32 len);

/**
 * \brief   Initialize use of stack-based memory allocator.
 *          The stack-based allocator does memory management inside the
 *          presented buffer and does not call calloc() and free().
 *          It sets the global mbedtls_calloc() and mbedtls_free() pointers
 *          to its own functions.
 *          (Provided mbedtls_calloc() and mbedtls_free() are thread-safe if
 *           MBEDTLS_THREADING_C is defined)
 *
 * \note    This code is not optimized and provides a straight-forward
 *          implementation of a stack-based memory allocator.
 *
 * \param ptr   pointer to free
 */
void buffer_alloc_free(void* const ptr);

/**
 * \brief   Allocate and zero-initialize array.
 *          Allocates a block of memory for an array of n elements, each of them size bytes long,
 *          and initializes all its bits to zero.
 *
 * \note    This code is not optimized and provides a straight-forward
 *          implementation of a stack-based memory allocator.
 *
 * \param n      Number of elements to allocate.
 * \param size   Size of each element.
 *
 * \return         array address if successful, or NULL if allocation failed
 */
void *buffer_alloc_calloc(const uint32 n, const uint32 size);
/**
 * \brief   Copy stack-based memory allocator data in exportPtr.
 *
 * \note    This code is not optimized and provides a straight-forward
 *          implementation of a stack-based memory allocator.
 *
 * \param exportPtr   buffer to save heap data into
 */
void mbedtls_memory_buffer_alloc_exportHeapData(void* const exportPtr);

/**
 * \brief   load stack-based memory allocator data from loadPtr.
 *
 * \note    This code is not optimized and provides a straight-forward
 *          implementation of a stack-based memory allocator.
 *
 * \param loadPtr   buffer to load heap data from
 */
void mbedtls_memory_buffer_alloc_loadHeapData(const void* const loadPtr);

/**
 * \brief   Deinitialize use of stack-based memory allocator.
 */
void mbedtls_memory_buffer_alloc_free( void );



#endif /* memory_buffer_alloc.h */
