/* gcm_mode.h - TinyCrypt interface to a GCM mode implementation */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * @brief Interface to a GCM mode implementation.
 *
 *  Overview: GCM (for "Galois/Counter Mode") mode is a NIST approved mode of
 *            operation defined in SP 800-38D.
 *
 *  Security: 
 *
 *  Requires: AES-128, AES-192, AES-256
 *
 *  Usage:    1) call tc_gcm_encryption_init to initialize the GCM mode encryption.
 *
 *            2) call tc_gcm_encryption_update to updates data for GCM encryption.
 *
 *            3) call tc_gcm_encryption_final to calculates TAG for GCM mode.
 * 
 *            4) call tc_gcm_decryption_init to initialize the GCM mode decryption.
 *
 *            5) call tc_gcm_decryption_update to updates data for GCM mode decryption.
 *
 *            6) call tc_gcm_decryption_final to verifies the TAG for GCM mode decryption.
 */

#ifndef __TC_GCM_MODE_H__
#define __TC_GCM_MODE_H__

#include <tinycrypt/aes.h>
#include <stddef.h>
#include "rm_tinycrypt_port_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief initialize the GCM mode encryption procedure
 * @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if:
 *                sched == NULL or
 *                iv == NULL or
 *                aad == NULL or
 *                additional_len == 0
 * @param sched IN -- AES key schedule
 * @param iv IN - Pointer to Initial Vector
 * @param aad IN - Pointer to additional data
 * @param additional_len -- Length of additional data
 */
int tc_gcm_encryption_init(const TCAesKeySched_t sched, uint8_t * iv, uint8_t * aad, uint32_t additional_len);

/**
 * @brief updates data for GCM encryption procedure
 * @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if:
 *                sched == NULL or
 *                input == NULL or
 *                output == NULL or
 *                length == 0
 * @param sched IN -- AES key schedule
 * @param input IN - plaintext to encrypt
 * @param output OUT -- encrypted data
 * @param length IN -- intput length
 */
int tc_gcm_encryption_update(const TCAesKeySched_t sched, const uint8_t * input, uint8_t * output,
                             uint8_t length);

/**
 * @brief calculates TAG for GCM mode encryption procedure
 * @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if:
 *                sched == NULL or
 *                input == NULL or
 *                output == NULL or
 *                tag == NULL or
 *                input_len == 0
 *                aad_len == 0
 * @param sched IN -- AES key schedule
 * @param input IN - plaintext to encrypt
 * @param input_len IN -- intput length
 * @param aad_len IN -- additional data length
 * @param output OUT - encrypted data
 * @param tag OUT - encrypted tag
 */
int tc_gcm_encryption_final(const TCAesKeySched_t sched,
                            uint8_t             * input,
                            uint8_t               input_len,
                            uint8_t               aad_len,
                            uint8_t             * output,
                            uint8_t             * tag);

/**
 * @brief initialize the GCM mode decryption procedure
 * @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if:
 *                sched == NULL or
 *                iv == NULL or
 *                aad == NULL or
 *                additional_len == 0
 * @param sched IN -- AES key schedule
 * @param iv IN - Pointer to Initial Vector
 * @param aad IN - Pointer to additional data
 * @param additional_len -- Length of additional data
 */
int tc_gcm_decryption_init(const TCAesKeySched_t sched, uint8_t * iv, uint8_t * aad, uint32_t additional_len);

/**
 * @brief updates data for GCM decryption procedure
 * @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if:
 *                sched == NULL or
 *                input == NULL or
 *                output == NULL or
 *                length == 0
 * @param sched IN -- AES key schedule
 * @param input IN - ciphertext to decrypt
 * @param output OUT -- decrypted data
 * @param length IN -- intput length
 */
int tc_gcm_decryption_update(const TCAesKeySched_t sched, const uint8_t * input, uint8_t * output,
                             uint8_t length);

/**
 * @brief calculates TAG for GCM mode decryption procedure
 * @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if:
 *                sched == NULL or
 *                input == NULL or
 *                tag == NULL or
 *                aad_len == 0
 *                input_len == 0
 *                tag_len == 0
 *                output == NULL or
 * @param sched IN -- AES key schedule
 * @param input IN - ciphertext to decrypt
 * @param tag IN - pointer to TAG buffer
 * @param aad_len IN -- additional data length
 * @param input_len IN -- intput length
 * @param tag_len IN -- tag length
 * @param output OUT - decrypted data
 */
int tc_gcm_decryption_final(const TCAesKeySched_t sched,
                            uint8_t             * input,
                            uint8_t             * tag,
                            uint8_t               aad_len,
                            uint8_t               input_len,
                            uint8_t               tag_len,
                            uint8_t             * output);

#endif /* __TC_GCM_MODE_H__ */
