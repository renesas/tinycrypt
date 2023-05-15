/* gcm_mode.c - TinyCrypt implementation of GCM mode */

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

#ifndef _GCM_MODE_C_
#define _GCM_MODE_C_

#include <tinycrypt/gcm_mode.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>

#include <stdio.h>

#define TC_PARAMETER_NOT_USED(p)    (void) ((p))

int tc_gcm_encryption_init(const TCAesKeySched_t sched, uint8_t * iv, uint8_t * aad, uint32_t additional_len)
{
	TC_PARAMETER_NOT_USED(sched);
	TC_PARAMETER_NOT_USED(*iv);
	TC_PARAMETER_NOT_USED(*aad);
	TC_PARAMETER_NOT_USED(additional_len);
	return TC_CRYPTO_FAIL;
}

int tc_gcm_encryption_update(const TCAesKeySched_t sched, const uint8_t * input, uint8_t * output,
                             uint8_t length)
{
	TC_PARAMETER_NOT_USED(sched);
	TC_PARAMETER_NOT_USED(*input);
	TC_PARAMETER_NOT_USED(*output);
	TC_PARAMETER_NOT_USED(length);
	return TC_CRYPTO_FAIL;
}

int tc_gcm_encryption_final(const TCAesKeySched_t sched,
                            uint8_t             * input,
                            uint8_t               input_len,
                            uint8_t               aad_len,
                            uint8_t             * output,
                            uint8_t             * tag)
{
	TC_PARAMETER_NOT_USED(sched);
	TC_PARAMETER_NOT_USED(*input);
	TC_PARAMETER_NOT_USED(input_len);
	TC_PARAMETER_NOT_USED(aad_len);
	TC_PARAMETER_NOT_USED(*output);
	TC_PARAMETER_NOT_USED(*tag);
	return TC_CRYPTO_FAIL;
}

int tc_gcm_decryption_init(const TCAesKeySched_t sched, uint8_t * iv, uint8_t * aad, uint32_t additional_len)
{
	TC_PARAMETER_NOT_USED(sched);
	TC_PARAMETER_NOT_USED(*iv);
	TC_PARAMETER_NOT_USED(*aad);
	TC_PARAMETER_NOT_USED(additional_len);
	return TC_CRYPTO_FAIL;
}

int tc_gcm_decryption_update(const TCAesKeySched_t sched, const uint8_t * input, uint8_t * output,
                             uint8_t length)
{
	TC_PARAMETER_NOT_USED(sched);
	TC_PARAMETER_NOT_USED(*input);
	TC_PARAMETER_NOT_USED(*output);
	TC_PARAMETER_NOT_USED(length);
	return TC_CRYPTO_FAIL;
}

int tc_gcm_decryption_final(const TCAesKeySched_t sched,
                            uint8_t             * input,
                            uint8_t             * tag,
                            uint8_t               aad_len,
                            uint8_t               input_len,
                            uint8_t               tag_len,
                            uint8_t             * output)
{
	TC_PARAMETER_NOT_USED(sched);
	TC_PARAMETER_NOT_USED(*input);
	TC_PARAMETER_NOT_USED(*tag);
	TC_PARAMETER_NOT_USED(aad_len);
	TC_PARAMETER_NOT_USED(input_len);
	TC_PARAMETER_NOT_USED(tag_len);
	TC_PARAMETER_NOT_USED(*output);
	return TC_CRYPTO_FAIL;
}
#endif /* !defined _GCM_MODE_C_ */
