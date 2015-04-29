/******************************************************************************/
/* KMS Parameters                                                             */
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
 * @file kmsParameters.c
 * @brief Storage of KMS data.
 *
 * <PRE>
 * Provides :
 *     File storage nad management functions for KMS data.
 * </PRE>
 *
 * Handles multiple KMSes accessed by kms-uri.
 * <BR>
 * Implements a flat file storage for KMS parameters.
 ******************************************************************************/
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "kmsParameters.h"
#include "kmsdb.h"
#include "log.h"

#define KMS_STORAGE_SECTION_NAME "(KMS-STORAGE)"/*!< DEBUG output section ID. */
#define KMS_MAX_ATTR_LEN         1024           /*!< Maximum attribute length.*/

/***************************************************************************//**
 * Stores a new KMS.
 *
 * @param[in]  version          (optional/null) May need a version id in future.
 * @param[in]  kms_uri          This KMS identifier.
 * @param[in]  owner            (optional/null) May need owner id in future.
 * @param[in]  z_T              KMS Master secret
 * @param[in]  z_T_len          KMS Master secret length
 * @param[in]  Z_T              KMS Public Key 
 * @param[in]  Z_T_len          KMS Public Key length
 * @param[in]  KSAK             KMS Secret Authrentication Key
 * @param[in]  KSAK_len         KMS Secret Authentication Key length
 * @param[in]  KPAK             KMS Public Authentication Key 
 * @param[in]  KPAK_len         KMS Public Authentication Key length
 *
 * @return ES_SUCCESS or ES_FAILURE (where MSDB_SUCCESS or MSDB_FAILURE 
 *         returned from the call to msdb_communityAdd match).
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
    const size_t   KPAK_len) {

    return kmsdb_add(kms_uri, version, owner,
                     z_T, z_T_len,
                     Z_T, Z_T_len,
                     KSAK, KSAK_len,
                     KPAK, KPAK_len);
} /* kms_addKms */

/***************************************************************************//**
 * Removes a KMS (identified by parameter 'kms_uri').
 *
 * @return ES_SUCCESS ro ES_FAILURE 
 ******************************************************************************/
short kms_removeKms(
    const uint8_t *kms_uri) {
    return kmsdb_delete(kms_uri);
} /* kms_removeKms */

/***************************************************************************//**
 * Deletes all the KMS data.
 *
 * @return A success/ failure indicator.
 ******************************************************************************/
short kms_deleteAllKms() {
    return kmsdb_purge();
} /* kms_deleteAllKms */

/***************************************************************************//**
 * Indicates whether the specified KMS is stored. For use externally as no 
 * reference to KMS is returned.
 *
 * @param[in] kms_uri The KMS name to check
 *
 * @return ES_TRUE or ES_FALSE.
 ******************************************************************************/
short kms_exists(
    const uint8_t *kms_uri) {
    return kmsdb_exists(kms_uri);
} /* kms_exists */

/***************************************************************************//**
 * Returns an unsorted CSV (Comma Separated Value) list of currently stored
 * KMS names.
 *
 * It is expected this function may be useful at the application level to
 * list supported KMS.
 *
 * Callers of this function are responsible for freeing the storage.
 *
 * @return The CSV list of stored KMS which may be NULL.
 ******************************************************************************/
uint8_t *kms_listKms() {
    return kmsdb_list();
} /* kms_listKms */

/***************************************************************************//**
 * Get the number of currently stored KMS.
 *
 * @return The number of currently stored KMS.
 ******************************************************************************/
uint8_t kms_countKms() {
    return kmsdb_count();
} /* community_count*/

/***************************************************************************//**
 * Get the Owner from  a specified KMS file. Callers are responsible for i
 * freeing the memory of the returned value.
 *
 * @param[in] kms_uri The KMS to get the owner of.
 *
 * @return A string containing the 'owner' value.
 ******************************************************************************/
char *kms_getOwner(
    const uint8_t *kms_uri) {
    char *owner = calloc(1, KMS_MAX_ATTR_LEN);
    kmsdb_getOwner(kms_uri, owner);
    return owner;
} /* kms_getOwner*/

/***************************************************************************//**
 * Get the version number from a specified KMS file. Callers are responsible 
 * for freeing the memory of the returned value.
 *
 * @param[in] kms_uri The KMS to get the version of.
 *
 * @return A string containing the 'version' value.
 ******************************************************************************/
char *kms_getVersion(
    const uint8_t *kms_uri) {
    char *ver = calloc(1, KMS_MAX_ATTR_LEN);
    kmsdb_getVersion(kms_uri, ver);
    return ver;
} /* kms_getOwner*/

/***************************************************************************//**
 * Get the KMS Master Secret for a specified KMS. Callers are responsible for 
 * freeing the memory of the returned value.
 *
 * @param[in] kms_uri The KMS to get z_T for
 *
 * @return A string containing the z_T value.
 ******************************************************************************/
char *kms_getzT(
    const uint8_t *kms_uri) { 
    char *z_T = calloc(1, KMS_MAX_ATTR_LEN);
    kmsdb_getzT(kms_uri, z_T);
    return z_T;
} /* kms_getzT */

/***************************************************************************//**
 * Get the KMS Public Key for a specified KMS. Callers are responsible for 
 * freeing the memory of the returned value.
 *
 * @param[in] kms_uri The KMS to get Z_T for
 *
 * @return A string containing the Z_T value.
 ******************************************************************************/
char *kms_getZT(const uint8_t *kms_uri) {
    char *Z_T = calloc(1, KMS_MAX_ATTR_LEN);
    kmsdb_getZT(kms_uri, Z_T);
    return Z_T;
} /* kms_getZT */

/***************************************************************************//**
 * Get the KSAK for a specified KMS. Callers are responsible for freeing the 
 * memory of the returned value.
 *
 * @param[in] kms_uri The KMS to get KSAK for
 *
 * @return A string containing the KSAK value.
 ******************************************************************************/
char *kms_getKSAK(const uint8_t *kms_uri) {
    char *KSAK = calloc(1, KMS_MAX_ATTR_LEN);
    kmsdb_getKSAK(kms_uri, KSAK);
    return KSAK;
} /* kms_getKSAK */

/***************************************************************************//**
 * Get the KPAK for a specified KMS. Callers are responsible for freeing the 
 * memory of the returned value.
 *
 * @param[in] kms_uri The KMS to get KPAK for
 *
 * @return A string containing the KPAK value.
 ******************************************************************************/
char *kms_getKPAK(const uint8_t *kms_uri) {
    char *KPAK = calloc(1, KMS_MAX_ATTR_LEN);
    kmsdb_getKPAK(kms_uri, KPAK);
    return KPAK;
} /* kms_getKPAK */

/***************************************************************************//**
 * Output the stored details for the specified KMS.
 * 
 * A debug function.
 ******************************************************************************/
void kms_output_parameters(const uint8_t *kms_id) {
#ifdef ES_OUTPUT_DEBUG
    char *z_T  = kms_getzT(kms_id);
    char *Z_T  = kms_getZT(kms_id);
    char *KSAK = kms_getKSAK(kms_id);
    char *KPAK = kms_getKPAK(kms_id);

    ES_DEBUG("%s       KMS Parameters", KMS_STORAGE_SECTION_NAME);
    ES_DEBUG("%s       ==============", KMS_STORAGE_SECTION_NAME);
    
    if (z_T  == NULL) { 
        ES_DEBUG("%s           z_T [mandatory] is missing", KMS_STORAGE_SECTION_NAME);
    }
    else { 
        ES_DEBUG("%s           z_T:  <%s>", KMS_STORAGE_SECTION_NAME, z_T);
    } 
    if (Z_T  == NULL) { 
        ES_DEBUG("%s           Z_T [optional] is missing", KMS_STORAGE_SECTION_NAME);
    }
    else { 
        ES_DEBUG("%s           Z_T:  <%s>", KMS_STORAGE_SECTION_NAME, Z_T);
    } 
    if (KSAK == NULL) { 
        ES_DEBUG("%s           KSAK [mandatory] is missing", KMS_STORAGE_SECTION_NAME);
    }
    else { 
        ES_DEBUG("%s           KSAK: <%s>", KMS_STORAGE_SECTION_NAME, KSAK);
    } 
    if (KPAK == NULL) { 
        ES_DEBUG("%s           KPAK [optional] is missing", KMS_STORAGE_SECTION_NAME);
    }
    else { 
        ES_DEBUG("%s           KPAK: <%s>", KMS_STORAGE_SECTION_NAME, KPAK);
    } 

    if (z_T != NULL) {
        memset(z_T, 0, strlen(z_T));
        free(z_T);
        z_T = NULL;
    }
    if (Z_T != NULL) {
        memset(Z_T, 0, strlen(Z_T));
        free(Z_T);
        Z_T = NULL;
    }
    if (KSAK != NULL) {
        memset(KSAK, 0, strlen(KSAK));
        free(KSAK);
        KSAK = NULL;
    }
    if (KPAK != NULL) {
        memset(KPAK, 0, strlen(KPAK));
        free(KPAK);
        KPAK = NULL;
    }
#endif /* ES_OUTPUT_DEBUG */

} /* kms_output_parameters */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
