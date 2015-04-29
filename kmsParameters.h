/******************************************************************************/
/* KMS Key Material data access functions.                                    */
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
 * @file kmsParameters.h
 * @brief KMS Key Material access functions.
 ******************************************************************************/
#ifndef KMS_PARAMETERS_STORAGE_H_
#define KMS_STORAGE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/*******************************************************************************
 * Add a new KMS details to storage.
 ******************************************************************************/
short kms_addKms(
    const uint8_t *version,
    const uint8_t *kms_uri,
    const uint8_t *owner,
    const uint8_t *z_T,
    const size_t   z_T_len,
    const uint8_t *Z_T,  
    const size_t   Z_T_len,
    const uint8_t *KSAK, 
    const size_t   KSAK_len,
    const uint8_t *KPAK, 
    const size_t   KPAK_len);

/*******************************************************************************
 * Remove the specified KMS details from storage.
 ******************************************************************************/
short kms_removeKms(
    const uint8_t *kms_uri);

/*******************************************************************************
 * Purge ALL KMS details from storage.
 ******************************************************************************/
short kms_deleteAllKms();

/*******************************************************************************
 * Check a specified KMS exists.
 ******************************************************************************/
short kms_exists(
    const uint8_t *kms_uri);

/***************************************************************************//**
 * Return the owner for a specified KMS. 
 ******************************************************************************/
char *kms_getOwner(
    const uint8_t *kms_uri);

/***************************************************************************//**
 * Return the version number for a specified KMS. 
 ******************************************************************************/
char *kms_getVersion(
    const uint8_t *kms_uri);

/*******************************************************************************
 * Return the z_T (KMS Master Secret) value for the specified KMS.
 ******************************************************************************/
char *kms_getzT(
    const uint8_t *kms_uri);

/*******************************************************************************
 * Return the Z_T (KMS Public Key) value for the specified KMS.
 ******************************************************************************/
char *kms_getZT(
    const uint8_t *kms_uri);

/*******************************************************************************
 * Return the KSAK (KMS Secret Authentication Key) value for the specified KMS.
 ******************************************************************************/
char *kms_getKSAK(
    const uint8_t *kms_uri);

/*******************************************************************************
 * Return the KPAK (KMS Public Authentication Key) value for the specified KMS.
 ******************************************************************************/
char *kms_getKPAK(
    const uint8_t *kms_uri);

/*******************************************************************************
 * Output the stored details for the specified KMS - A debug function.
 ******************************************************************************/
void  kms_output_parameters(
    const uint8_t *kms_uri); 

#ifdef __cplusplus
}
#endif
#endif /* KMS_PARAMETERS_STORAGE_H_ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
