/******************************************************************************/
/* Generic Data Handling (KMS)                                                */
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
 * @file kmsdb.h
 * @brief Generic Data Handling for KMS attributes.
 *
 * This header file describes the access functions that are required by the
 * KMS back end storage mechanism.
 * <P>
 * This <b>EXAMPLE</b> code implements this interface, storing the data in flat 
 * file format. However, it is very simple and not intended for product, just as
 * a simple exemplar. The storage implentation code itself isn't particularly
 * pretty and I haven't spent much time on it because I'd expect it to be
 * replaced by others (i.e. YOU), depending on what you want this storage to
 * be.
 * <P>
 * Implementors are free to implement the back end storage mechanism in
 * whatever way they see fit. However, it MUST comply with the interface/ API
 * defined in THIS header file for it to work.
 * <P>
 * The actual storage mechanism chosen to store this (KMS) key material will 
 * largely depend upon the implemntation architecture and target platform  and
 * may be:
 * <PRE>
 *     One of a variety of databases e.g.:
 *         MYSQL/ SQLcipher
 *         PostGres
 *         Oracle
 *         LDAP etc
 *     or, something more novel perhaps (depending on product/ platform) :
 *         RFID/ NFC card/ Yubi key/ SD card, or hardware tag
 *     or, something else entirely I haven't considered yet.
 * </PRE>
 *
 * In short these actions (i.e. what YOU must implement for your chosen
 * storage mechanism for your KMS) are:
 * <PRE>
 *     KMS:
 *         kmsdb_add
 *         kmsdb_exists
 *         kmsdb_delete
 *         kmsdb_purge
 *         kmsdb_list
 *         kmsdb_count<br>
 *       Attributes access functions...
 *         kmsdb_getVersion
 *         kmsdb_getOwner
 *         kmsdb_getzT
 *         kmsdb_getZT
 *         kmsdb_getKSAK
 *         kmsdb_getKPAK
 * </PRE>
 ******************************************************************************/
#ifndef __ES_KMS_DATA_STORAGE_H__
#define __ES_KMS_DATA_STORAGE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MSDB_MAX_LOG_LINE 1024       /*!< The maximum length for log output. */

/* Matches ES_TRUE/ ES_FALSE */
#ifndef MSDB_TRUE
#define MSDB_TRUE 1                  /*!< MSDB value for true  */
#endif
#ifndef MSDB_FALSE
#define MSDB_FALSE (!MSDB_TRUE)      /*!< MSDB value for false */
#endif

/* Matches ES_FAILURE/ ES_SUCCESS*/
#ifndef MSDB_FAILURE_
#define MSDB_FAILURE 1               /*!< MSDB value for failure */
#endif
#ifndef MSDB_SUCCESS
#define MSDB_SUCCESS (!MSDB_FAILURE) /*!< MSDB value for success */
#endif

#define STORAGE_ROOT       "." /*!< The root directory location for data 
                                *   storage.
                                */
#define STORAGE_DIRECTORY  STORAGE_ROOT"/storage"  /*!< The storage directory.*/

/***************************************************************************//**
 * MSDB Error Macro - output passed error string
 */
#define MSDB_ERROR(a_format, vargs...) { \
    char outBuff_a[MSDB_MAX_LOG_LINE]; \
    snprintf(outBuff_a, sizeof(outBuff_a), a_format, ## vargs); \
    fprintf(stdout, "KMSDB ERROR: %s\n", outBuff_a); \
    }

/******************************************************************************/
/* Community Data Accessor Functions.                                         */
/******************************************************************************/

/* Management */

/*******************************************************************************
 * Add KMS new KMS (community). If the kms_uri  name exists the storage is 
 * deleted first.
 ******************************************************************************/
short    kmsdb_add(
    const uint8_t *kms_uri, /* community */
    const uint8_t *version,
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
 * Check whether the specified KMS exists.
 ******************************************************************************/
short    kmsdb_exists(
    const uint8_t *kms_uri);

/*******************************************************************************
 * Delete specified KMS.
 ******************************************************************************/
short    kmsdb_delete(
    const uint8_t *kms_uri);

/*******************************************************************************
 * Delete all (purge) stored KMSs.
 ******************************************************************************/
short    kmsdb_purge();

/*******************************************************************************
 * Get a comma separated list of stored KMSs.
 ******************************************************************************/
uint8_t *kmsdb_list();

/*******************************************************************************
 * The number of stored KMSs.
 ******************************************************************************/
uint16_t kmsdb_count();

/* Get Attributes */

/*******************************************************************************
 * Get the stored version for the specified KMS.
 ******************************************************************************/
short kmsdb_getVersion(
    const uint8_t *kms_uri,
    uint8_t       *version);

/*******************************************************************************
 * Get the stored owner of KMS.
 ******************************************************************************/
short kmsdb_getOwner(
    const uint8_t *kms_uri,
    uint8_t       *owner);

/*******************************************************************************
 * Get a KMS's z_T (Master Secret) - SECRET!
 ******************************************************************************/
short    kmsdb_getzT(
    const uint8_t *kms_uri,
    uint8_t       *zT);

/*******************************************************************************
 * Get a KMS's Public Key - PUBLIC.
 ******************************************************************************/
short    kmsdb_getZT(
    const uint8_t *kms_uri,
    uint8_t       *ZT);

/*******************************************************************************
 * Get a specified KMS's KSAK (KMS Secret Authentication Key) - SECRET!
 ******************************************************************************/
short    kmsdb_getKSAK(
    const uint8_t *kms_uri,
    uint8_t       *KSAK);

/*******************************************************************************
 * Get a specified KMS's KPAK (KMS Public Authentication Key) - PUBLIC.
 ******************************************************************************/
short    kmsdb_getKPAK(
    const uint8_t *kms_uri,
    uint8_t       *KPAK);

#ifdef __cplusplus
}
#endif
#endif /* __ES_KMS_DATA_STORAGE_H__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
