/**
 * \file mbedtls_md.c
 *
 * \brief Generic message digest wrapper for mbed TLS
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


#include "md.h"
#include "md_internal.h"
#include "platform_util.h"
#include "memory_buffer_alloc.h"
#include <string.h>



int mbedtls_md_setup( mbedtls_md_context_t_s *const ctx, const mbedtls_md_info_t_s *const md_info, const int hmac )
{
    if( (md_info == NULL_PTR) || (ctx == NULL_PTR) )
    {
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    }
   
    ctx->md_ctx = md_info->ctx_alloc_func();
    if( (ctx->md_ctx) == NULL_PTR )
    {
        return( MBEDTLS_ERR_MD_ALLOC_FAILED );
    }

    if( hmac != 0 )
    {
        ctx->hmac_ctx = buffer_alloc_calloc( 2, md_info->block_size );
        if( ctx->hmac_ctx == NULL_PTR )
        {
            md_info->ctx_free_func( ctx->md_ctx );
            return( MBEDTLS_ERR_MD_ALLOC_FAILED );
        }
    }

    ctx->md_info = md_info;

    return( 0 );
}



void mbedtls_md_free( mbedtls_md_context_t_s *const ctx )
{
    if( (ctx == NULL_PTR) || ((ctx->md_info) == NULL_PTR) )
    {
        return;
    }

    if( ctx->md_ctx != NULL_PTR )
    {
        ctx->md_info->ctx_free_func( ctx->md_ctx );
    }

    if( ctx->hmac_ctx != NULL_PTR )
    {
        mbedtls_platform_zeroize( ctx->hmac_ctx,
                                  (unsigned int)2 * (unsigned int)ctx->md_info->block_size );
        buffer_alloc_free( ctx->hmac_ctx );
    }

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_md_context_t_s ) );
}
const mbedtls_md_info_t_s *mbedtls_md_info_from_type( const mbedtls_md_type_t md_type )
{
    switch( md_type )
    {

        case MBEDTLS_MD_SHA256:
            return( &mbedtls_sha256_info );

        default:
            return( NULL_PTR );
    }
}
int mbedtls_md_hmac_starts( mbedtls_md_context_t_s *const ctx, const unsigned char *key, size_t keylen )
{
    int ret;
    unsigned char sum[MBEDTLS_MD_MAX_SIZE];
    unsigned char *ipad, *opad;
    size_t i;

    if( (ctx == NULL_PTR) || ((ctx->md_info) == NULL_PTR) || ((ctx->hmac_ctx) == NULL_PTR) )
    {
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    }

    if( keylen > (size_t) ctx->md_info->block_size )
    {
        ret = ctx->md_info->starts_func( ctx->md_ctx );
        if( ret != 0 )
        {
            goto cleanup;
        }
        
        ret = ctx->md_info->update_func( ctx->md_ctx, key, keylen );
        if( ret != 0 )
        {
            goto cleanup;
        }
        
        ret = ctx->md_info->finish_func( ctx->md_ctx, sum );
        if( ret != 0 )
        {
            goto cleanup;
        }

        keylen = (unsigned int)ctx->md_info->size;
        key = sum;
    }

    ipad = (unsigned char *) ctx->hmac_ctx;
    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    memset( ipad, 0x36, (unsigned int)ctx->md_info->block_size );
    memset( opad, 0x5C, (unsigned int)ctx->md_info->block_size );

    for( i = 0; i < keylen; i++ )
    {
        ipad[i] = (unsigned char)( ipad[i] ^ key[i] );
        opad[i] = (unsigned char)( opad[i] ^ key[i] );
    }
    
    ret = ctx->md_info->starts_func( ctx->md_ctx ) ;
    if( ret != 0 )
    {
        goto cleanup;
    }
    
    ret = ctx->md_info->update_func( ctx->md_ctx, ipad,
                                           (unsigned int)ctx->md_info->block_size );
    if( ret != 0 )
      {
        goto cleanup;
      }

cleanup:
    mbedtls_platform_zeroize( sum, sizeof( sum ) );

    return( ret );
}



int mbedtls_md_hmac_finish( mbedtls_md_context_t_s *const ctx, unsigned char *const output )
{
    int ret;
    unsigned char tmp[MBEDTLS_MD_MAX_SIZE];
    unsigned char *opad;

    if( (ctx == NULL_PTR) || ((ctx->md_info) == NULL_PTR) || ((ctx->hmac_ctx) == NULL_PTR) )
    {
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    }

    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    ret = ctx->md_info->finish_func( ctx->md_ctx, tmp );
    if( ret != 0 )
    {
        return( ret );
    }
    
    ret = ctx->md_info->starts_func( ctx->md_ctx );
    if( ret != 0 )
    {
        return( ret );
    }
    
    ret = ctx->md_info->update_func( ctx->md_ctx, opad,
                                           (unsigned int)ctx->md_info->block_size ) ;
    if( ret != 0 )
      {
        return( ret );
      }
      
    ret = ctx->md_info->update_func( ctx->md_ctx, tmp,
                                           (unsigned int)ctx->md_info->size );
    if( ret != 0 )
      {
        return( ret );
      }
      
    return( ctx->md_info->finish_func( ctx->md_ctx, output ) );
}

int mbedtls_md_hmac_update( mbedtls_md_context_t_s *const ctx, const unsigned char *const input, const size_t ilen )
{
    if( (ctx == NULL_PTR) || ((ctx->md_info) == NULL_PTR) || ((ctx->hmac_ctx) == NULL_PTR) )
    {
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    }

    return( ctx->md_info->update_func( ctx->md_ctx, input, ilen ) );
}

int mbedtls_md_hmac_reset( mbedtls_md_context_t_s *const ctx )
{
    int ret;
    unsigned char *ipad;

    if( (ctx == NULL_PTR) || ((ctx->md_info) == NULL_PTR) || ((ctx->hmac_ctx) == NULL_PTR) )
    {
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    }

    ipad = (unsigned char *) ctx->hmac_ctx;
    
    ret = ctx->md_info->starts_func( ctx->md_ctx );
    if( ret != 0 )
    {
        return( ret );
    }
    return( ctx->md_info->update_func( ctx->md_ctx, ipad,
                                       (unsigned int)ctx->md_info->block_size ) );
}

unsigned int mbedtls_md_get_size( const mbedtls_md_info_t_s *const md_info )
{
    if( md_info == NULL_PTR )
    {
        return( 0 );
    }

    return (unsigned int)md_info->size;
}


