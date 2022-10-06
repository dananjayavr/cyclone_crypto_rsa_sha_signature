/**
 * @file crypto_config.h
 * @brief CycloneCRYPTO configuration file
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2021 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.1.0
 **/

#ifndef _CRYPTO_CONFIG_H
#define _CRYPTO_CONFIG_H

#define GPL_LICENSE_TERMS_ACCEPTED


//Desired trace level (for debugging purposes)
#define CRYPTO_TRACE_LEVEL TRACE_LEVEL_INFO

//Multiple precision integer support
#define MPI_SUPPORT ENABLED
//Assembly optimizations for time-critical routines
#define MPI_ASM_SUPPORT DISABLED // DISABLED for Linux/GCC to get rid of undefined reference error in CMake

//Base64 encoding support
#define BASE64_SUPPORT ENABLED
//Base64url encoding support
#define BASE64URL_SUPPORT DISABLED

//MD2 hash support
#define MD2_SUPPORT ENABLED
//MD4 hash support
#define MD4_SUPPORT ENABLED
//MD5 hash support
#define MD5_SUPPORT ENABLED
//RIPEMD-128 hash support
#define RIPEMD128_SUPPORT ENABLED
//RIPEMD-160 hash support
#define RIPEMD160_SUPPORT ENABLED
//SHA-1 hash support
#define SHA1_SUPPORT ENABLED
//SHA-224 hash support
#define SHA224_SUPPORT ENABLED
//SHA-256 hash support
#define SHA256_SUPPORT ENABLED
//SHA-384 hash support
#define SHA384_SUPPORT ENABLED
//SHA-512 hash support
#define SHA512_SUPPORT ENABLED
//SHA-512/224 hash support
#define SHA512_224_SUPPORT ENABLED
//SHA-512/256 hash support
#define SHA512_256_SUPPORT ENABLED
//SHA3-224 hash support
#define SHA3_224_SUPPORT ENABLED
//SHA3-256 hash support
#define SHA3_256_SUPPORT ENABLED
//SHA3-384 hash support
#define SHA3_384_SUPPORT ENABLED
//SHA3-512 hash support
#define SHA3_512_SUPPORT ENABLED
//SHAKE support
#define SHAKE_SUPPORT ENABLED
//cSHAKE support
#define CSHAKE_SUPPORT DISABLED
//Keccak support
#define KECCAK_SUPPORT ENABLED
//BLAKE2b support
#define BLAKE2B_SUPPORT ENABLED
//BLAKE2b-160 hash support
#define BLAKE2B160_SUPPORT DISABLED
//BLAKE2b-256 hash support
#define BLAKE2B256_SUPPORT DISABLED
//BLAKE2b-384 hash support
#define BLAKE2B384_SUPPORT DISABLED
//BLAKE2b-512 hash support
#define BLAKE2B512_SUPPORT ENABLED
//BLAKE2s support
#define BLAKE2S_SUPPORT ENABLED
//BLAKE2s-128 hash support
#define BLAKE2S128_SUPPORT DISABLED
//BLAKE2s-160 hash support
#define BLAKE2S160_SUPPORT DISABLED
//BLAKE2s-224 hash support
#define BLAKE2S224_SUPPORT DISABLED
//BLAKE2s-256 hash support
#define BLAKE2S256_SUPPORT ENABLED
//Tiger hash support
#define TIGER_SUPPORT DISABLED
//Whirlpool hash support
#define WHIRLPOOL_SUPPORT DISABLED
//SECP256K1 curve support
#define SECP256K1_SUPPORT ENABLED
// PEM support
#define PEM_SUPPORT ENABLED
// RSA support
#define RSA_SUPPORT ENABLED
#endif
