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
 * @file kmsdb.c
 * @brief Example KMSDB API implemntation to store KMS data.
 ******************************************************************************/
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>

#include "kmsdb.h"

#define ES_MAX_LINE_LEN               1024 /*!< Maximum line len for reading 
                                            *   data from file. 
                                            */
#define ES_MAX_DIR_FILE_NAME_LEN      1024 /*!< The maximum file name length. */

#define STORAGE_DIRECTORY             STORAGE_ROOT"/storage" 
/*!< The storage directory where kms and other data is stored. */

#define STORAGE_KMS_DIRECTORY STORAGE_DIRECTORY"/kms"
/*!< The storage directory where KMS data is stored. */

/***************************************************************************//**
 * Strip the white space from the  provided string 'in'.
 *
 * @param[in]  in The input string to strip white space from.
 *
 * @return A pointer to the modified 'in' string.
 ******************************************************************************/
static uint8_t *utils_stripWS(
    uint8_t *in)
{
    int count   = 0;
    int cur_pos = 0;

    if (in != NULL) {
        for (count = 0; count < strlen((char *)in); count++) {
            if ((in[count] != ' ')  && (in[count] != '\t') &&
                (in[count] != '\n') && (in[count] != '\r')) {
                in[cur_pos] = in[count];
                cur_pos++;
            }
        }
        in[cur_pos] = 0;
    }
    return in;
} /* utils_stripWS */

/***************************************************************************//**
 * Cleanup the parsed data (stripping trailing spaces) or indicating the line
 * should be ignored if it empty or a comment (indicated by';').
 *
 * @param[in] opt The line that was parsed.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
static short cleanConfigLine(
    char* opt) 
{
    short ret_val = MSDB_FAILURE;
    int   i       = 0;

    /* Remove initial white spaces */
    while (isspace(*opt)) {
        opt++;
    }
    /* Remove trailing white spaces */
    for (i=strlen(opt)-1; i>=0 && isspace(opt[i]); --i) {
        opt[i]='\0';
    }
    /* Empty or comment */
    if(opt[0]!='\0' && opt[0]!=';') {
        ret_val = MSDB_SUCCESS;
    }

    return ret_val;
} /* cleanConfigLine */

/***************************************************************************//**
 * Parse the specified file looking for the 'key' and return the 'value'.
 *
 * Note! THIS IS INTERNAL AND NOT PART OF THE REQUIRED API.
 *
 * @param[in]  fp    A pointer to the file to be parsed.
 * @param[in]  key   The 'key' identifier we are looking for.
 * @param[out] value The return 'value' for the specified 'key'.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
static short parseDataAttribute(
    FILE    *fp, 
    char    *key,
    uint8_t *value) 
{
    short ret_val = MSDB_FAILURE; 
    char conf_line[ES_MAX_LINE_LEN];
    char conf_total[ES_MAX_LINE_LEN];

    if (NULL != fp) {
        /* Read the configuration line by line looking for key */
        short first_line=1;
        memset(conf_line, 0, sizeof(conf_line));
        while (NULL != fgets(conf_line, ES_MAX_LINE_LEN, fp)) {
            if (first_line==1) {
                if ((conf_line[0] != ';') && (conf_line[0] != '\n')) {
                    strcpy(conf_total, conf_line);
                    first_line=0;
                }
                /* else ignore comment or blank line. */
            }
            else {
                utils_stripWS((uint8_t *)&conf_line);
                /* Not comment or CRLF */
                if ((conf_line[0] != ';') && (conf_line[0] != '\n')) {
                    /* Used to allow key:([WS|CRLF])*value, but Secure Chorus 
                     * date spec has ':' so now format MUST comply with 
                     * key:CRLF[ws]value
                     */
                    if (conf_line[0] != 0) { /* Blank line - skip it. */
                        if (conf_line[strlen(conf_line)-1] != ':') {
                            conf_total[strlen(conf_total)] = 0x0;
                            strcat(conf_total, conf_line);
                        }
                        else {
                            /* Cleanup the config line */
                            if (cleanConfigLine(conf_total)) { 
                                continue;
                            }
        
                            utils_stripWS((uint8_t *)&conf_total);
                            if ((strlen(conf_total) > 0) && 
                                       (!strncmp(conf_total, key, strlen(key)))) {
                                /* Found what we were looking for. */
                                break;
                            }
                            memset(conf_total, 0, sizeof(conf_total));
                            if (conf_line[0] != ';') {
                                strcpy(conf_total, conf_line);
                            }
                        }
                    }
                }
                /* else skip comment or blank line */
            }
            memset(conf_line, 0, sizeof(conf_line));
        }

        utils_stripWS((uint8_t*)&conf_total);
        if (strlen(conf_total) > 0) {
            if (!strncmp(conf_total, key, strlen(key))) {
                strcpy((char *)value, conf_total+(strlen(key)));
                ret_val = MSDB_SUCCESS;
            }       
        } 
    }

    return ret_val;
} /* parseDataAttribute */

/***************************************************************************//**
 * Opens the specified KMS file.
 *
 * Note! THIS IS INTERNAL AND NOT PART OF THE REQUIRED API.
 *
 * @param[in]  kms_uri The URI of the KMS, the file for which will be opened.
 *
 * @return Success (a FILE pointer) or Failure (NULL).
 ******************************************************************************/
static FILE *openKMSFile(
    const uint8_t *kms_uri)
{
    char  filename[ES_MAX_DIR_FILE_NAME_LEN];
    FILE *fp = NULL;

    if (NULL == kms_uri) {
        MSDB_ERROR("%s", "KMSDB Open KMS File, no kms specified!");
    }
    else {
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s", 
                 STORAGE_KMS_DIRECTORY, kms_uri);

        if (NULL == (fp = fopen(filename, "r"))) {
            MSDB_ERROR("KMSDB Open KMS File, unable to access KMS data <%s>!",
                kms_uri);
        }
   }
   return fp;
} /* openKMSFile */

/***************************************************************************//**
 * Produces 'pretty' (for humans) 4 byte space and 16 byte line separated 
 * output. The output is used to store hex strings to file.
 *
 * @param[out] out_line The output string of the prettyfication.
 * @param[in]  str      The input octet string.
 * @param[in]  str_len  The length of the input octet string.
 * @param[in]  pad      Pad for the output line of the hash.
 ******************************************************************************/
static void utils_prettyPrintOctetString(
    uint8_t       *out_line,
    const uint8_t *str,
    const size_t   str_len,
    const uint8_t  pad)
{
    uint16_t loop = 0;
    strcpy((char *)out_line, "");
    for (loop=0; loop < str_len; loop++) {
        if ((loop%16)==0) {
            sprintf((char *)&out_line[strlen((char *)out_line)], "\n%*s", pad, " ");
        }
        else {
            if ((loop%4)==0) {
                sprintf((char *)&out_line[strlen((char *)out_line)], " ");
            }
        }
        sprintf((char *)&out_line[strlen((char *)out_line)], "%X%X",
                (((str[loop])&0xf0)>>4), (str[loop])&0x0f);
    }
    sprintf((char *)&out_line[strlen((char *)out_line)], "\n\n");
} /* utils_prettyPrintOctetString */

/*****************************************************************************/
/* KMS Data Accessor Functions.                                              */
/*****************************************************************************/
/* Management */

/**************************************************************************//**
 * Add KMS data for a new KMS. If the kms_uri exists the storage is deleted 
 * first.
 *
 * @param[in]  kms_uri  The URI of the KMS.
 * @param[in]  version  The version number of the KMS data.
 * @param[in]  owner    A designated owner of the KMS.
 * @param[in]  z_T      KMS Master Secret.
 * @param[in]  z_T_len  KMS Master Secret Length.
 * @param[in]  Z_T      KMS Public Key.
 * @param[in]  Z_T_len  KMS Public Key length.
 * @param[in]  KSAK     KMS Secret Authentiction Key.
 * @param[in]  KSAK_len KMS Secret Authentication key length.
 * @param[in]  KPAK     KMS Public Authentication Key.
 * @param[in]  KPAK_len KMS Public Authtication Key length.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE.
 ******************************************************************************/
short kmsdb_add(
    const uint8_t *kms_uri,
    const uint8_t *version,
    const uint8_t *owner,
    const uint8_t *z_T,
    const size_t   z_T_len,
    const uint8_t *Z_T,
    const size_t   Z_T_len,
    const uint8_t *KSAK,
    const size_t   KSAK_len,
    const uint8_t *KPAK,
    const size_t   KPAK_len) {
    short  ret_val = MSDB_FAILURE;
    FILE  *file_p  = NULL;

    char out_line[ES_MAX_LINE_LEN];
    char filename[ES_MAX_DIR_FILE_NAME_LEN];

    /* For some reason Secure Chorus doesn't mandate the KMS provide MS
     * parameter set.
     */
    if (NULL == kms_uri) {
        MSDB_ERROR("%s", "MSDB KMS Add, missing mandatory parameter 'KmsUri'!");
    /* Version and Owner are optional */
    } else if (NULL == z_T) {
        MSDB_ERROR("MSDB KMS Add, <%s>, missing mandatory parameter 'z_T' (KMS Master Secret)!",
            kms_uri);
    } else if (NULL == Z_T) {
        MSDB_ERROR("MSDB KMS Add, <%s>, missing mandatory parameter 'Z_T' (KMS Public Key)!",
            kms_uri);
    } else if (NULL == KSAK) {
        MSDB_ERROR("MSDB KMS Add, <%s>, missing mandatory parameter 'KSAK' (KMS Secret Authentication Key)!",
            kms_uri);
    } else if (NULL == KPAK) {
        MSDB_ERROR("MSDB KMS Add, <%s>, missing mandatory parameter 'KPAK' (KMS Public Authentication Key)!",
            kms_uri);
    }
    else {
        /* Remove existing storage */
        kmsdb_delete(kms_uri);

        /* Create the temporary file. */
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s", STORAGE_KMS_DIRECTORY, 
                 kms_uri);

        if (NULL == (file_p = fopen(filename, "w"))) {
            MSDB_ERROR("MSDB KMS Add, unable to access KmsUri storage <%s>!",
                     kms_uri);
        }
        else {
            if ((NULL != version) && (strlen(version) > 0)) {
                snprintf(out_line, sizeof(out_line), 
                         "Version:\n    %s\n\n", version);
                fwrite(out_line, strlen(out_line), 1, file_p);
            }
            if ((NULL != owner) && (strlen(owner) > 0)) {
                snprintf(out_line, sizeof(out_line), 
                         "Owner:\n    %s\n\n", owner);
                fwrite(out_line, strlen(out_line), 1, file_p);
            }
            if (NULL != z_T) {
                memset(out_line, 0, sizeof(out_line));
                snprintf(out_line, sizeof(out_line),
                    "; Master Secret - MUST be kept secret!\n");
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
                snprintf(out_line, sizeof(out_line), "z_T:");
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
                utils_prettyPrintOctetString((uint8_t *)&out_line, 
                    (uint8_t *)z_T, z_T_len, 4); 
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
            }

            if (NULL != Z_T) {
                memset(out_line, 0, sizeof(out_line));
                snprintf(out_line, sizeof(out_line),
                    "; In (client) community files this is called 'PubEncKey', as per Secure Chorus.\n");
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
                snprintf(out_line, sizeof(out_line), "Z_T:");
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
                utils_prettyPrintOctetString((uint8_t *)&out_line, 
                    (uint8_t *)Z_T, Z_T_len, 4); 
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
            }
            if (NULL != KSAK) {
                memset(out_line, 0, sizeof(out_line));
                snprintf(out_line, sizeof(out_line),
                    "; KMS Secret Authentication Key - MUST be kept secret!\n");
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
                snprintf(out_line, sizeof(out_line), "KSAK:");
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
                utils_prettyPrintOctetString((uint8_t *)&out_line, 
                    (uint8_t *)KSAK, KSAK_len, 4); 
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
            }
            if (NULL != KPAK) {
                memset(out_line, 0, sizeof(out_line));
                snprintf(out_line, sizeof(out_line),
                    "; In community files this is called 'PubEncKey', as per Secure Chorus.\n");
                fwrite(out_line, strlen(out_line), 1, file_p);
                snprintf(out_line, sizeof(out_line), "KPAK:");
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
                utils_prettyPrintOctetString((uint8_t *)&out_line, 
                    (uint8_t *)KPAK, KPAK_len, 4); 
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
            }


            /* Close the file. */
            fclose(file_p);

            ret_val = MSDB_SUCCESS;
        }
    }

    memset(out_line,  0, sizeof(out_line));
    memset(filename, 0, sizeof(filename));

    return ret_val;

} /* kmsdb_add */

/***************************************************************************//**
 * Check whether the specified KMS exists.
 *
 * @param[in]  kms_uri The KMS URI to check exists.
 *
 * @return ES_TRUE or ES_FALSE
 ******************************************************************************/
short kmsdb_exists(
    const uint8_t *kms_uri)
{
    short       ret_val = MSDB_FALSE;
    char        filename[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat file_info;

    if (NULL != kms_uri) {
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s", 
                 STORAGE_KMS_DIRECTORY, kms_uri);

        if ((!stat(filename, &file_info)) && /* Regular file? */
            (S_ISREG(file_info.st_mode))) {
                ret_val = MSDB_TRUE;
        }
    }

    return ret_val;

} /* kmsdb_exists */

/***************************************************************************//**
 * Delete specified KMS.
 *
 * @param[in]  kms_uri The name of the KMS to delete.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
short kmsdb_delete(
    const uint8_t *kms_uri)
{
    short       ret_val = MSDB_FAILURE;
    char        filename[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat file_info;

    if (NULL == kms_uri) {
        MSDB_ERROR("%s", "MSDB KMS Delete, no KMS URI specified!");
    }
    else {
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s", 
                 STORAGE_KMS_DIRECTORY, kms_uri);

        /* Regular file? */
        if ((!stat(filename, &file_info)) && 
            (S_ISREG(file_info.st_mode))) {

            if (!remove(filename)) {
                ret_val = MSDB_SUCCESS;
            }
            else {
                 MSDB_ERROR("MSDB KMS Delete, unable to delete KMS <%s>!",
                      kms_uri);
             }
        }
        else { /* Does not exist, success */
            ret_val = MSDB_SUCCESS;
        }
 
    }

    return ret_val;

} /* kmsdb_delete */

/***************************************************************************//**
 * Delete all (purge) stored KMSs.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short kmsdb_purge() 
{
    short          ret_val         = MSDB_FAILURE;
    DIR           *dir_p           = NULL;
    struct dirent *dirEntry_p      = NULL;
    char           tmpPath[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat    file_info;

    /* Initialise storage structure. */
    memset(tmpPath,  0, sizeof(tmpPath));
    snprintf(tmpPath, sizeof(tmpPath), STORAGE_KMS_DIRECTORY);

    dir_p = opendir(tmpPath);
    if (NULL != dir_p) {

        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name,  ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {

                memset(tmpPath, 0, sizeof(tmpPath));
                snprintf(tmpPath, sizeof(tmpPath), 
                         "%s/%s", STORAGE_KMS_DIRECTORY, dirEntry_p->d_name);

                /* Regular file? */
                if ((!stat(tmpPath, &file_info)) &&
                    (S_ISREG(file_info.st_mode))) {

                    if (remove(tmpPath)) {
                        MSDB_ERROR("MSDB KMS Purge, unable to delete KMS file <%s>!",
                            dirEntry_p->d_name);
                    }
                }
            }
        }
        ret_val = MSDB_SUCCESS;
    }

    return ret_val;

} /* kmsdb_purge */

/***************************************************************************//**
 * Get a comma separated list of stored KMSs.
 *
 * @return A pointer to the list of KMSs, NULL if none.
 ******************************************************************************/
uint8_t *kmsdb_list() {
    DIR            *dir_p           = NULL;
    struct  dirent *dirEntry_p      = NULL;
    char            tmpPath[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat     file_info;
    uint8_t        *kmsList   = NULL;

    /* Initialise storage structure. */
    memset(tmpPath,  0, sizeof(tmpPath));

    snprintf(tmpPath, sizeof(tmpPath), STORAGE_KMS_DIRECTORY);
    dir_p = opendir(tmpPath);
    if (NULL != dir_p) {

        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name,  ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {
                memset(tmpPath,  0, sizeof(tmpPath));
                snprintf(tmpPath, sizeof(tmpPath), "%s/%s", 
                         STORAGE_KMS_DIRECTORY, dirEntry_p->d_name);

                if ((!stat(tmpPath, &file_info)) && 
                    (S_ISREG(file_info.st_mode))) {

                    if (NULL == kmsList) {
                        kmsList = calloc(1, strlen(dirEntry_p->d_name)+1);
                        strcpy((char *)kmsList, dirEntry_p->d_name);
                    }
                    else {
                        /* comma and NULL terminator. */
                        kmsList = realloc(kmsList,
                            strlen((char *)kmsList)+strlen(dirEntry_p->d_name)+ 2); 
                        strcat((char *)kmsList, ",");
                        strcat((char *)kmsList, dirEntry_p->d_name);
                    }
                }
            }
        }
    }

    return kmsList;
} /* kmsdb_list */

/***************************************************************************//**
 * The number of stored KMSs.
 *
 * @return A count indicating the number of stored KMSs.
 ******************************************************************************/
uint16_t kmsdb_count() 
{
    DIR                 *dir_p           = NULL;
    struct  dirent      *dirEntry_p      = NULL;
    char    tmpPath[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat file_info;
    uint8_t              count           = 0;

    /* Initialise storage structure. */
    memset(tmpPath,  0, sizeof(tmpPath));

    snprintf(tmpPath, sizeof(tmpPath), STORAGE_KMS_DIRECTORY);
    dir_p = opendir(tmpPath);
    if (NULL != dir_p) {

        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name,  ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {
                memset(tmpPath,  0, sizeof(tmpPath));
                snprintf(tmpPath, sizeof(tmpPath), "%s/%s", 
                         STORAGE_KMS_DIRECTORY, dirEntry_p->d_name);

                if ((!stat(tmpPath, &file_info)) && 
                    (S_ISREG(file_info.st_mode))) {
                    count++;
                }
            }
        }
    }

    return count;
} /* kmsdb_count */

/* Get Attributes */

/***************************************************************************//**
 * Get the stored version for the specified KMS.
 *
 * @param[in]  kms_uri  The name of the KMS from which to get the 
 *                      version.
 * @param[out] version  The version, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short kmsdb_getVersion(
    const uint8_t *kms_uri,
    uint8_t       *version) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == kms_uri) {
        MSDB_ERROR("%s", "MSDB Community Get Version, no KMS URI specified!");
    } else if (NULL != (fp = openKMSFile(kms_uri))) {
        if (!parseDataAttribute(fp, "Version:", version)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB KMS Get Version, unable to get Version from KMS <%s>!",
                kms_uri);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB KMS Get Version, failed to retrieve Version!")
    }

    return ret_val;
} /* kmsdb_getVersion */

/***************************************************************************//**
 * Get the stored Owner for the specified KMS.
 *
 * @param[in]  kms_uri The name of the KMSfrom which to get the Owner.
 * @param[out] owner The Owner, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short kmsdb_getOwner(
    const uint8_t *kms_uri,
    uint8_t       *owner) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == kms_uri) {
        MSDB_ERROR("%s", "MSDB KMS Get Owner, no KMS URI specified!");
    } else if (NULL != (fp = openKMSFile(kms_uri))) {
        if (!parseDataAttribute(fp, "Owner:", owner)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB KMS Get Owner, unable to get Owner from KMS <%s>!",
                kms_uri);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB KMS Get Owner, failed to retrieve Owner!");
    }

    return ret_val;
} /* kmsdb_getOwner */

/***************************************************************************//**
 * Get the stored z_T (Master Secret) for the specified KMS.
 *
 * @param[in]  kms_uri The name of the KMS from which to get the Master Secret.
 * @param[out] zT      The Master Secret z_T, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short kmsdb_getzT(
    const uint8_t *kms_uri,
    uint8_t       *zT)
{
    short          ret_val = MSDB_FAILURE;
    FILE          *fp      = NULL;

    if (NULL == kms_uri) {
        MSDB_ERROR("%s", "MSDB KMS Get z_T (Master Secret), no KMS specified!");
    } else if (NULL != (fp = openKMSFile(kms_uri))) {
        if (!parseDataAttribute(fp, "z_T:", zT)) { 
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB KMS Get z_T (Master Secret), unable to get z_T from KMS <%s>!",
                kms_uri);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB KMS Get z_T (Master Secret), failed to retrieve z_T!");
    }

    return ret_val;
} /* kmsdb_getzT */

/***************************************************************************//**
 * Get the stored Z_T (Public Key) for the specified KMS.
 *
 * @param[in]  kms_uri The name of the KMS from which to get the Public Key.
 * @param[out] ZT      The Public Key Z_T, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short kmsdb_getZT(
    const uint8_t *kms_uri,
    uint8_t       *ZT)
{
    short          ret_val = MSDB_FAILURE;
    FILE          *fp      = NULL;

    if (NULL == kms_uri) {
        MSDB_ERROR("%s", "MSDB KMS Get Z_T (Public Key), no KMS specified!");
    } else if (NULL != (fp = openKMSFile(kms_uri))) {
        if (!parseDataAttribute(fp, "Z_T:", ZT)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB KMS Get Z_T (Public Key), unable to get Z_T from KMS <%s>!",
                kms_uri);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB KMS Get Z_T (Public Key), failed to retrieve Z_T!");
    }

    return ret_val;
} /* kmsdb_getZT */

/***************************************************************************//**
 * Get the stored KSAK (KMS Secret Authentication Key) for the specified KMS.
 *
 * @param[in]  kms_uri The name of the KMS from which to get the KSAK.
 * @param[out] KSAK    The KSAK (KMS Secret Authentication Key), on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short kmsdb_getKSAK(
    const uint8_t *kms_uri,
    uint8_t       *KSAK)
{
    short          ret_val = MSDB_FAILURE;
    FILE          *fp      = NULL;

    if (NULL == kms_uri) {
        MSDB_ERROR("%s", "MSDB KMS Get KSAK, no KMS specified!");
    } else if (NULL != (fp = openKMSFile(kms_uri))) {
        if (!parseDataAttribute(fp, "KSAK:", KSAK)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB KMS Get KSAK, unable to get KSAK from KMS <%s>!",
                kms_uri);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB KMS Get KSAK, failed to retrieve KSAK!");
    }

    return ret_val;
} /* kmsdb_getKSAK */

/***************************************************************************//**
 * Get the stored KPAK (KMS Public Authentication Key) for the specified KMS.
 *
 * @param[in]  kms_uri The name of the KMS from which to get the KPAK.
 * @param[out] KPAK    The KPAK (KMS Public Authentication Key), on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short kmsdb_getKPAK(
    const uint8_t *kms_uri,
    uint8_t       *KPAK)
{
    short          ret_val = MSDB_FAILURE;
    FILE          *fp      = NULL;

    if (NULL == kms_uri) {
        MSDB_ERROR("%s", "MSDB KMS Get KPAK, no KMS specified!");
    } else if (NULL != (fp = openKMSFile(kms_uri))) {
        if (!parseDataAttribute(fp, "KPAK:", KPAK)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB KMS Get KPAK, unable to get KPAK from KMS <%s>!",
                kms_uri);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB KMS Get KPAK, failed to retrieve KPAK!");
    }

    return ret_val;
} /* kmsdb_getKPAK */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
