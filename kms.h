/******************************************************************************/
/* KMS Key Material generation code.                                          */
/*                                                                            */
/* Copyright 2015 Jim Buller                                                  */
/*                                                                            */
/* Licensed under the Apache License, Version 2.0 (the "License");            */
/* you may not use this file except in compliance with the License.           */
/* You may obtain a copy of the License at                                    */
/*                                                                            */
/*     http://www.apache.org/licenses/LICENSE-2.0                             */
/*                                                                            */
/* Unless required by applicable law or agreed to in writing, software        */
/* distributed under the License is distributed on an "AS IS" BASIS,          */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   */
/* See the License for the specific language governing permissions and        */
/* limitations under the License.                                             */
/******************************************************************************/

/***************************************************************************//**
 * @file kms.h
 * @brief KMS crypto funtions.
 ******************************************************************************/
#ifndef __ES_KMS_H__
#define __ES_KMS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <global.h>

#define KMS_V_FAILURE 20 /*!< ERROR code for 'v' calculation failures. Indicates
                          *   to the caller that they should retry with another
                          *   value for 'v'.
                          */

/*******************************************************************************
 * Create KMS keys.
 ******************************************************************************/
uint8_t kms_createKMSKeys(
    const uint8_t   ms_param_set,
    const uint8_t  *kms_id,
    const uint8_t  *version,
    const uint8_t  *owner,
    const uint8_t  *z_T,
    const size_t    z_T_len,
    const uint8_t  *KSAK,
    const size_t    KSAK_len);

/*******************************************************************************
 * Create KMS SSK (Secret Signing Key) PVT (Public Validation Token) pairing.
 ******************************************************************************/
uint8_t kms_createSSKPVTPairForUser(
    const uint8_t  *community,
    const uint8_t  *user_id,
    const size_t    user_id_len,
    uint8_t       **ssk,
    size_t         *ssk_len,
    uint8_t       **pvt,
    size_t         *pvt_len,
    uint8_t       **v, /* A random octet string */ 
    size_t         *v_len);

/*******************************************************************************
 * Create KMS RSK (Receiver Secret Key).
 ******************************************************************************/
uint8_t kms_createRSK(
    const uint8_t   msParamSet,
    const char     *kms_id,
    const char     *user_id,
    const size_t    user_id_len,
    uint8_t       **rsk,
    size_t         *rsk_len);

/*******************************************************************************
 * Add user. To add this, we need create the RSk and SSK/ PVT pairing.
 ******************************************************************************/
uint8_t kms_addUser(
    const char     *user_id_date,
    const char     *user_id_uri,
    const char     *community,
    uint8_t       **v,
    size_t         *v_len);

/*******************************************************************************
 * List the 'user' and 'community' data that meeds to be sent to the client.
 *
 * This could be done using Secure Chorus protocols, or for testing with the 
 * ECCSI-SAKKE demo code, just copy these files to the storage directory used
 * by the demo code.
 ******************************************************************************/
void kms_listDetailsToSendToClient(
    char           *user_date,
    char           *user_uri,
    char           *community);

#ifdef __cplusplus
}
#endif
#endif /* __ES_KMS_H__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
