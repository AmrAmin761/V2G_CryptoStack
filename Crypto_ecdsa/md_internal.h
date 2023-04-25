/**
 * \file md_internal.h
 *
 * \brief Message digest wrappers.
 *
 * \warning This in an internal header. Do not include directly.
 */
/*
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
#ifndef MBEDTLS_MD_WRAP_H
#define MBEDTLS_MD_WRAP_H

#include "md.h"


#ifdef __cplusplus
extern "C" {
#endif

extern const mbedtls_md_info_t_s mbedtls_sha256_info;


#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_MD_WRAP_H */
