/*
 *  Buffer-based memory allocator
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
#include "memory_buffer_alloc.h"

#include <string.h>

#define MAGIC1       (uint32) (0xFF00AA55U)
#define MAGIC2       (uint32) (0xEE119966U)

typedef struct str_memory_header memory_header;
struct str_memory_header
{
	uint32 magic1;
	uint32 size;
	uint32 alloc;
	memory_header *prev;
	memory_header *next;
	memory_header *prev_free;
	memory_header *next_free;
	uint32 magic2;
};

typedef struct
{
	uint8 *buf;
	uint32 len;
	memory_header *first;
	memory_header *first_free;
	uint16 verify;
} buffer_alloc_ctx;



static buffer_alloc_ctx heap;




static sint16 verify_header(const memory_header* const hdr);
static sint16 verify_chain(void);
static sint16 verify_header(const memory_header* const hdr)
{
	sint16 ret = 0;
	if ((hdr->magic1 != MAGIC1) || (hdr->magic2 != MAGIC2) ||
			(hdr->alloc > 1UL)      || ( (hdr->prev != NULL_PTR) && (hdr->prev == hdr->next) ) ||
			( (hdr->prev_free != NULL_PTR) && (hdr->prev_free == hdr->next_free) ))
	{
		ret = (sint16)1;
	}
	else
	{
		/* Do Nothing as ret variable already initialized to ZERO */
	}
	return (ret);
}

static sint16 verify_chain(void)
{
	memory_header *prv = heap.first, *cur = heap.first->next;
	sint16 ret = 0;
	sint16 verify_ret = 0;

	verify_ret = verify_header(heap.first);

	if ((((((sint32)verify_ret) != ((sint32)0)))) || (((heap.first->prev) != NULL_PTR)))
	{
		ret = (sint16) 1;
	}
	else
	{
		while (cur != NULL_PTR)
		{
			verify_ret = verify_header(cur);

			if (((((sint32)verify_ret) != ((sint32)0))) || (((cur->prev) != prv)))
			{
				ret = (sint16) 1;
				break;
			}

			prv = cur;
			cur = cur->next;
		}

	}
	return (ret);
}

void *buffer_alloc_calloc(const uint32 n, const uint32 size)
{
	memory_header *new, *cur = heap.first_free;
	uint8 *uint8_ptr;
	void *ret = NULL_PTR;
	uint32 original_len, Len;
	uint16 VerifyChain;

	if ((heap.buf == NULL_PTR) || (heap.first == NULL_PTR))
	{
		ret = NULL_PTR;
	}
	else
	{

		original_len = n * size;
		Len = n * size;

		if ((n != 0UL)&& ((Len / n) != size))
		{
			ret = NULL_PTR;
		}
		else
		{

			if ((Len % (uint32) MBEDTLS_MEMORY_ALIGN_MULTIPLE) != 0UL)
			{
				Len -= Len % (uint32) MBEDTLS_MEMORY_ALIGN_MULTIPLE;
				Len = Len + (uint32) MBEDTLS_MEMORY_ALIGN_MULTIPLE;
			}

			/* Find block that fits*/

			while (cur != NULL_PTR)
			{
				if (cur->size >= Len)
				{
					break;
				}

				cur = cur->next_free;
			}

			if ((cur == NULL_PTR) || (cur->alloc != 0UL))
			{
				ret = NULL_PTR;
			}
			else
			{
				/* Found location, split block if > memory_header + 4 room left*/

				if ((cur->size - Len) < ( (uint32) sizeof(memory_header) +
						(uint32) MBEDTLS_MEMORY_ALIGN_MULTIPLE))
				{
					cur->alloc = 1UL;

					/*Remove from free_list*/

					if (cur->prev_free != NULL_PTR)
					{
						cur->prev_free->next_free = cur->next_free;
					}
					else
					{
						heap.first_free = cur->next_free;
					}

					if (cur->next_free != NULL_PTR)
					{
						cur->next_free->prev_free = cur->prev_free;
					}
					cur->prev_free = NULL_PTR;
					cur->next_free = NULL_PTR;

					VerifyChain = (uint16)verify_chain();

					if ((((((uint32)(heap.verify)) & ((uint32)MBEDTLS_MEMORY_VERIFY_ALLOC)) != 0UL)) &&
							(((uint32)VerifyChain) != 0UL))
					{
						/* Do Nothing as ret variable already initialized to NULL_PTR */
					}
					else
					{

						ret = (uint8 *) (void*)cur + sizeof(memory_header);
						(void)memset(ret, 0, (size_t)original_len);
					}
				}
				else
				{

					uint8_ptr = (uint8 *) (void*)cur + sizeof(memory_header) + Len;
					new = (memory_header *) (void*)uint8_ptr;

					new->size = cur->size - Len - sizeof(memory_header);
					new->alloc = 0UL;
					new->prev = cur;
					new->next = cur->next;
					new->magic1 =  MAGIC1;
					new->magic2 =  MAGIC2;

					if (new->next != NULL_PTR)
					{
						new->next->prev = new;
					}
					/*Replace cur with new in free_list*/

					new->prev_free = cur->prev_free;
					new->next_free = cur->next_free;
					if (new->prev_free != NULL_PTR)
					{
						new->prev_free->next_free = new;
					}
					else
					{
						heap.first_free = new;
					}
					if (new->next_free != NULL_PTR)
					{
						new->next_free->prev_free = new;
					}
					cur->alloc = (uint32)1;
					cur->size = Len;
					cur->next = new;
					cur->prev_free = NULL_PTR;
					cur->next_free = NULL_PTR;

					VerifyChain = (uint16) verify_chain();

					if ((((((uint32)(heap.verify)) & ((uint32)MBEDTLS_MEMORY_VERIFY_ALLOC)) != 0UL)) &&
							(((uint32)VerifyChain) != 0UL))
					{
						ret = NULL_PTR;
					}
					else
					{

						ret = (uint8 *)(void*)cur + sizeof(memory_header);
						(void)memset(ret, 0, (size_t)original_len);
					}
				}
			}
		}
	}

	return (ret);
}

void buffer_alloc_free(void* const ptr)
{
	memory_header *hdr, *old = NULL_PTR;
	uint8 *ptr_local = (uint8 *) ptr;
	sint16 ret_verifyheader = 0;

	if (!(((ptr == NULL_PTR) || (heap.buf == NULL_PTR) || (heap.first == NULL_PTR))
			|| ((ptr_local < heap.buf) || (ptr_local > (&heap.buf[0] + heap.len)))))
	{

		ptr_local -= sizeof(memory_header);
		hdr = (memory_header *) (void*)ptr_local;

		ret_verifyheader = verify_header(hdr);
		if((((((sint32)ret_verifyheader) == ((sint32)0)))) && (((hdr->alloc) == 1UL)))
		{
			hdr->alloc = 0UL;

			/*Regroup with block before*/

			if ((hdr->prev != NULL_PTR) && (hdr->prev->alloc == 0UL))
			{
				hdr->prev->size += ((uint32)sizeof(memory_header) + hdr->size);
				hdr->prev->next = hdr->next;
				old = hdr;
				hdr = hdr->prev;

				if (hdr->next != NULL_PTR)
				{
					hdr->next->prev = hdr;
				}
			}

			/*Regroup with block after*/

			if ((hdr->next != NULL_PTR) && (hdr->next->alloc == 0UL))
			{
				hdr->size += ((uint32)sizeof(memory_header) + hdr->next->size);
				old = hdr->next;
				hdr->next = hdr->next->next;

				if ((hdr->prev_free != NULL_PTR) || (hdr->next_free != NULL_PTR))
				{
					if (hdr->prev_free != NULL_PTR)
					{
						hdr->prev_free->next_free = hdr->next_free;
					}
					else
					{
						heap.first_free = hdr->next_free;
					}

					if (hdr->next_free != NULL_PTR)
					{
						hdr->next_free->prev_free = hdr->prev_free;
					}
				}

				hdr->prev_free = old->prev_free;
				hdr->next_free = old->next_free;

				if (hdr->prev_free != NULL_PTR)
				{
					hdr->prev_free->next_free = hdr;
				}
				else
				{
					heap.first_free = hdr;
				}

				if (hdr->next_free != NULL_PTR)
				{
					hdr->next_free->prev_free = hdr;
				}

				if (hdr->next != NULL_PTR)
				{
					hdr->next->prev = hdr;
				}

			}

			/* Prepend to free_list if we have not merged*/
			/*(Does not have to stay in same order as prev / next list)*/

			if (old == NULL_PTR)
			{
				hdr->next_free = heap.first_free;
				if (heap.first_free != NULL_PTR)
				{
					heap.first_free->prev_free = hdr;
				}
				heap.first_free = hdr;
			}
		}
	}
}

void mbedtls_memory_buffer_alloc_init(uint8 *buf, uint32 len)
{
	(void)memset(&heap, 0, sizeof(buffer_alloc_ctx));
	(void)memset(buf, 0, (size_t)len);

	/* Check memory alignment, Casting pointer is allowed when addressing memory */

	if ((uint32)(((uint32) &buf[0]) % (uint32) MBEDTLS_MEMORY_ALIGN_MULTIPLE) != 0UL)
	{
		/* Check memory alignment, Casting pointer is allowed when addressing memory */
		/* Adjust len first since buf is used in the computation */

		len -= (uint32) ( (uint32) MBEDTLS_MEMORY_ALIGN_MULTIPLE - ( (uint32) buf % (uint32) MBEDTLS_MEMORY_ALIGN_MULTIPLE) );

		/* Check memory alignment, Casting pointer is allowed when addressing memory */

		buf = buf + (uint32) ( (uint32) MBEDTLS_MEMORY_ALIGN_MULTIPLE - ( (uint32) buf % (uint32) MBEDTLS_MEMORY_ALIGN_MULTIPLE) );
	}

	heap.buf = buf;
	heap.len = len;

	heap.first = (memory_header *) (void*)buf;
	heap.first->size = len - (uint32)sizeof(memory_header);
	heap.first->magic1 = (uint32) MAGIC1;
	heap.first->magic2 = (uint32) MAGIC2;
	heap.first_free = heap.first;
}

void mbedtls_memory_buffer_alloc_exportHeapData(void* const exportPtr)
{		/* Destination */  /* Source */
	(void)memcpy(exportPtr, &heap, sizeof(heap));
}
void mbedtls_memory_buffer_alloc_loadHeapData(const void* const loadPtr)
{
	(void)memcpy(&heap, loadPtr, sizeof(heap));
}


