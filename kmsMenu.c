/******************************************************************************/
/* KMS Menu                                                                   */
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
 * @file kmsMenu.c
 * @brief A VERY simple menu driven KMS for generating Mikey-Sakke key material.
 *
 * <PRE>
 * Provides:
 *     KMS       List, Add, Delete, List-Details
 *     Community List, Add, Delete, List-Details
 *     User      List, Add, Delete, List-Details [aka data to send to MS client]
 * </PRE>
 *
 * Note! 
 * Virtually no checking or valiation of entered values.
 ******************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>

#include <openssl/bn.h>

#include <kms.h>
#include <kmsParameters.h>
#include <communityParameters.h>

#define STORAGE_KMS_DIRECTORY         "./storage/kms"         /*!< KMS storage directory */
#ifndef STORAGE_COMMUNITIES_DIRECTORY 
#define STORAGE_COMMUNITIES_DIRECTORY "./storage/communities" /*!< Communities storage directory */
#endif 
#ifndef STORAGE_USERS_DIRECTORY 
#define STORAGE_USERS_DIRECTORY       "./storage/users"       /*!< Users storage directory */
#endif 

#define ES_MAX_DIR_FILE_NAME_LEN 1024 /*!< Directory path maximum length */

#define KMS_MAX_COMMUNITIES       100 /*!< Maximum number of communities */
#define KMS_MAX_KMS               100 /*!< Maximum number of KMSes       */
#define KMS_MAX_USERS            1000 /*!< Maximum number of Users       */
#define KMS_MAX_LINE_LEN          512 /*!< Maximum attribute line length */

/* Arrays of string for KMSes, Communities and Users used in list functions. */
char *kms[KMS_MAX_KMS];                 /*!< Array of kms names - list selection */
char *communities[KMS_MAX_COMMUNITIES]; /*!< Array of community names - list selection */
char *users[KMS_MAX_USERS];             /*!< Array of user names - list selection */

char  tmp_path[ES_MAX_DIR_FILE_NAME_LEN];/*!< Temporary file name space       */

char  user_date[KMS_MAX_LINE_LEN];       /*!< Array for storing User-Date     */
char  user_uri[KMS_MAX_LINE_LEN];        /*!< Array for storing User-Uri      */
char  community[KMS_MAX_LINE_LEN];       /*!< Array for storing Community     */
char  kms_name[KMS_MAX_LINE_LEN];        /*!< Array for storing KmsName       */
char  owner[KMS_MAX_LINE_LEN];           /*!< Array for storing Owner         */
char  version[KMS_MAX_LINE_LEN];         /*!< Array for storing Version       */
char  cert_uri[KMS_MAX_LINE_LEN];        /*!< Array for storing CertUri       */
char  kms_uri[KMS_MAX_LINE_LEN];         /*!< Array for storing KmsUri        */
char  issuer[KMS_MAX_LINE_LEN];          /*!< Array for storing Issuer        */
char  valid_from[KMS_MAX_LINE_LEN];      /*!< Array for storing ValidFrom     */
char  valid_to[KMS_MAX_LINE_LEN];        /*!< Array for storing ValidTo       */
char  user_id_format[KMS_MAX_LINE_LEN];  /*!< Array for storing UserIdFormat  */
char  kms_domain_list[KMS_MAX_LINE_LEN]; /*!< Array for storing KmsDomainList */

char  conf_line[KMS_MAX_LINE_LEN]; /*!< For reading from files/ */

#define rfc6508_z_T  "AFF429D3" "5F84B110" "D094803B" "3595A6E2" \
                     "998BC99F" /*!< RFC 6508 'z_T' value  */
#define rfc6507_KSAK "12345"    /*!< RFC 6507 'KSAK' value */
#define rfc6507_v    "23456"    /*!< RFC 'v' value         */

/***************************************************************************//**
 * Clear KMS list array.
 ******************************************************************************/
void kms_clearKmsList() {
    uint8_t c = 0;
  
    for (; c < KMS_MAX_KMS; c++) {
        if (kms[c] != NULL) {
            free(kms[c]);
            kms[c] = NULL;
        }
        else {
            break; /* End of previous data */
        }
    }
} /* kms_clearKmsList */

/***************************************************************************//**
 * Create KMS list, copying all KMS names into in the kms array.
 ******************************************************************************/
uint8_t kms_list() {
    DIR             *dir_p      = NULL;
    struct   dirent *dirEntry_p = NULL;
    struct   stat    file_info;
    uint8_t          ret_val    = 0;
    unsigned int     selection  = 0;
    uint8_t          count      = 0;

    /* Initialise storage structures. */
    memset(tmp_path,  0, sizeof(tmp_path));
    kms_clearKmsList();

    snprintf(tmp_path, sizeof(tmp_path), STORAGE_KMS_DIRECTORY);
    if (NULL != (dir_p = opendir(tmp_path))) {
        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name, ".gitignore") != 0) &&
                (strcmp(dirEntry_p->d_name, ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {
                memset(tmp_path,  0, sizeof(tmp_path));
                snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
                         STORAGE_KMS_DIRECTORY,
                         dirEntry_p->d_name);

                if ((!stat(tmp_path, &file_info)) &&
                    (S_ISREG(file_info.st_mode))) {

                    kms[ret_val] = calloc(1, strlen(dirEntry_p->d_name)+1);
                    strcpy(kms[ret_val], dirEntry_p->d_name);
                    ret_val++;
                }
            }
        }
        closedir(dir_p);
    }

    return ret_val;

} /* kms_list */

/***************************************************************************//**
 * Display the list of KMSes and allow selection of one of these, returning 
 * this selection.
 *
 * @return The selected kms.
 ******************************************************************************/
char *kms_listSelect() {
    DIR             *dir_p      = NULL;
    struct   dirent *dirEntry_p = NULL;
    struct   stat    file_info;
    char            *ret_val    = NULL;
    uint8_t          kms_count  = 0;
    unsigned int     selection  = 0;
    uint8_t          count      = 0;
    size_t           kms_len    = 0;

    kms_count = kms_list();
    for (count = 0; count < kms_count; count++) {
         printf("            %d - %s\n", count+1, kms[count]);
    }
    printf("        Selection: ");
    scanf(" %u", &selection);
    if ((selection > 0) && (selection <= kms_count)) {
        kms_len = strlen(STORAGE_KMS_DIRECTORY) + 1 +
                  strlen(kms[selection-1]) + 1;
        ret_val = calloc(1, kms_len);
        snprintf(ret_val, kms_len, "%s/%s", STORAGE_KMS_DIRECTORY,
                 kms[selection-1]);
    }
    getchar(); /* Consume EOLN */

    kms_clearKmsList();

    return ret_val;

} /* kms_listSelect */

/***************************************************************************//**
 * Handle KMS management functions.
 *
 *     0 - Return to previous menu
 *     1 - List KMS
 *     2 - Add KMS
 *     3 - Delete KMS
 *     4 - List KMS Details
 ******************************************************************************/
void kmsMenu() {
    unsigned int   selection      = 0;
    char           confirm        = 0;
    unsigned int   cont           = 1;
    unsigned int   c              = 0;
    char          *selected_kms   = NULL;
    short          use_rfc_values = ES_FALSE;
    FILE          *file_p         = NULL;
    struct   stat  file_info;
    uint8_t       *z_T            = NULL;
    size_t         z_T_len        = 0;
    uint8_t       *KSAK           = NULL;
    size_t         KSAK_len       = 0;
    BIGNUM        *z_T_bn         = NULL;
    BIGNUM        *KSAK_bn        = NULL;

    while (cont) {
        memset(kms_name, 0, sizeof(kms));
        memset(version,  0, sizeof(version));
        memset(owner,    0, sizeof(owner));

        printf("\n    KMS Menu\n");
        printf("    --------\n");
        printf("        0 - Return to previous menu\n");
        printf("        1 - List KMS\n");
        printf("        2 - Add KMS\n");
        printf("        3 - Delete KMS\n");
        printf("        4 - List KMS Details\n");
        printf("    Selection: ");
        scanf("%u", &selection);
        switch (selection) {
            case 0  : {
                cont = 0;
                break;
            }
            case 1  : {
                printf("\n    Stored KMS are:\n");
                int a = kms_list();
                for (c = 0; c < a; c++) {
                    printf("        %s\n", kms[c]);
                }
                kms_clearKmsList();
                break;
            }
            case 2  : {
                getchar(); /* Clear from menu selection */
                printf("        Enter name of new KMS: ");
                fgets(kms_name, sizeof(kms_name)-1, stdin);
                memset(&kms_name[strlen(kms_name)-1], 0, 1);

                if (strlen(kms_name) > 0) {

                    /* Check it doesn't already exist. */
                    if (!kms_exists(kms_name)) {
                        printf("        Enter a version for these KMS data (optional): ");
                        fgets(version, sizeof(version)-1, stdin);
                        memset(&version[strlen(version)-1], 0, 1);

                        printf("        Enter an owner for these KMS data (optional): ");
                        fgets(owner, sizeof(owner)-1, stdin);
                        memset(&owner[strlen(owner)-1], 0, 1);

                        do {
                            printf("        Do you want to use RFC values, rather than random? (y/n): ");
                            scanf(" %c", &confirm);
                        } while ((confirm != 'Y') && (confirm != 'y') &&
                                 (confirm != 'N') && (confirm != 'n'));

                        if ((confirm == 'Y') || (confirm == 'y')) {
                            utils_convertHexStringToOctetString(rfc6508_z_T, 
                                (strlen(rfc6508_z_T)/2) + (strlen(rfc6508_z_T)%2),
                                &z_T, &z_T_len);
                            utils_convertHexStringToOctetString(rfc6507_KSAK, 
                                (strlen(rfc6507_KSAK)/2) + (strlen(rfc6507_KSAK)%2),
                                &KSAK, &KSAK_len);
                        }
                        else {
                            /* z_T - must be in the range 2..q-1 */
                            z_T_len = 32;
                            do {
                                ES_PRNG(&z_T,  z_T_len);
                                z_T_bn = BN_bin2bn((unsigned char *)z_T, z_T_len, NULL);
                                if ((BN_cmp(z_T_bn, BN_value_one()) == 1) &&
                                    (BN_cmp(z_T_bn, community_getq_bn()) == -1)) {
                                    break;
                                }
                                else { /* Get another number. */
                                    BN_clear_free(z_T_bn);
                                    z_T_bn = NULL;
                                }
                                BN_clear_free(z_T_bn);
                                z_T_bn = NULL;
                            } while(1);

                            /* KSAK - A random non 0 int modulo q */
                            KSAK_len = 32;
                            do {
                                ES_PRNG(&KSAK, KSAK_len);
                                KSAK_bn = BN_bin2bn((unsigned char *)KSAK, KSAK_len, NULL);
                                BN_nnmod(KSAK_bn, KSAK_bn, community_getq_bn(), NULL); /* mod q */
                                if (BN_cmp(KSAK_bn, BN_value_one()) >= 0) {
                                    break;
                                }
                                else {
                                    BN_clear_free(KSAK_bn);
                                    KSAK_bn = NULL;
                                }
                            } while(1);
                            BN_clear_free(KSAK_bn);
                            KSAK_bn = NULL;
                        }

                        if (!kms_createKMSKeys(1, /* MSParamSet, currently only one*/
                            kms_name, version, owner, 
                            z_T,     z_T_len, 
                            KSAK,    KSAK_len)) {
                            printf("    KMS save successful\n");
                        }
                        else {
                            printf("\n    ERROR: KMS save failed\n");
                        }
                        /* Tidy up as we might be looping adding again. */
                        if (z_T != NULL) {
                            memset(z_T, 0, z_T_len);
                            free(z_T);
                            z_T = NULL;
                        }
                        if (KSAK != NULL) {
                            memset(KSAK, 0, KSAK_len);
                            free(KSAK);
                            KSAK = NULL;
                        }
                    }
                    else {
                        printf("\n    ERROR: Cannot proceed, kms <%s> exists, delete it first!\n",
                               kms_name);
                    }
                }
                else {
                    printf("\n    ERROR: Cannot proceed, no KMS name specified!\n");
                }

                break;
            }
            case 3  : {
                printf("\n    Delete KMS:\n");
                printf("    -----------------\n");
                selected_kms = kms_listSelect();
                if (selected_kms) {
                    do {
                        printf("\n    Are you absolutely sure? (y/n): ");
                        scanf(" %c", &confirm);
                    } while ((confirm != 'Y') && (confirm != 'y') &&
                             (confirm != 'N') && (confirm != 'n'));
                    if ((confirm == 'Y') || (confirm == 'y')) {

                        /* Strip path */
                        strcpy(kms_name, selected_kms +
                            strlen(STORAGE_KMS_DIRECTORY)+1);

                        if (kms_removeKms(kms_name)) {
                            printf("\n    ERROR: Failed to remove KMS <%s>!\n", selected_kms);
                        }
                    }
                    free(selected_kms);
                    selected_kms = NULL;
                }
                break;
            }
            case 4  : {
                printf("\n    KMS to list details for:\n");
                printf("    -----------------------\n");
                selected_kms = kms_listSelect();
                if (selected_kms != NULL) {
                    printf("\n");
                    printf("    ++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                    printf("    Contents of KMS file:\n        %s\n\n",  selected_kms);
                    if (NULL != (file_p = fopen(selected_kms, "r"))) {
                        memset(conf_line, 0, sizeof(conf_line));
                        while (NULL != fgets(conf_line, KMS_MAX_LINE_LEN, file_p)) {
                            printf("%s", conf_line);
                        }
                    }
                    else {
                        printf("\n    ERROR: Could not open <%s>!\n", selected_kms);
                    }
                    printf("    ++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                    free(selected_kms);
                    selected_kms = NULL;
                }
                break;
            }
            default : {
                break;
            }
        }
    }

} /* kmsMenu */

/***************************************************************************//**
 * Clear Communities list array.
 ******************************************************************************/
void kms_clearCommunitiesList() {
    uint8_t c = 0;

    for (; c < KMS_MAX_COMMUNITIES; c++) {
        if (communities[c] != NULL) {
            free(communities[c]);
            communities[c] = NULL;
        }
        else {
            break; /* End of previous data */
        }
    }
} /* kms_clearCommunitiesList */

/***************************************************************************//**
 * Create Community list, copying all Community names into in the Community 
 * array.
 ******************************************************************************/
uint8_t kms_communityList() {
    DIR            *dir_p           = NULL;
    struct  dirent *dirEntry_p      = NULL;
    struct stat     file_info;

    uint8_t      ret_val   = 0;
    unsigned int selection = 0;
    uint8_t      count     = 0;

    /* Initialise storage structures. */
    memset(tmp_path,  0, sizeof(tmp_path));
    kms_clearCommunitiesList();

    /* Could have used community_list() here */

    snprintf(tmp_path, sizeof(tmp_path), STORAGE_COMMUNITIES_DIRECTORY);
    if (NULL != (dir_p = opendir(tmp_path))) {
        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name, ".gitignore") != 0) &&
                (strcmp(dirEntry_p->d_name, ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {
                memset(tmp_path,  0, sizeof(tmp_path));
                snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
                         STORAGE_COMMUNITIES_DIRECTORY,
                         dirEntry_p->d_name);

                if ((!stat(tmp_path, &file_info)) &&
                    (S_ISREG(file_info.st_mode))) {

                    communities[ret_val] = calloc(1, strlen(dirEntry_p->d_name)+1);
                    strcpy(communities[ret_val], dirEntry_p->d_name);
                    ret_val++;
                }
            }
        }
        closedir(dir_p);
    }

    return ret_val;

} /* kms_communityList */

/***************************************************************************//**
 * Display the list of communities and allow selection of one of these,
 * returning this selection.
 *
 * @return The selected community.
 ******************************************************************************/
char *kms_communityListSelect() {
    DIR            *dir_p           = NULL;
    struct  dirent *dirEntry_p      = NULL;
    struct stat     file_info;
    char           *ret_val         = NULL;
    uint8_t         community_count = 0;
    unsigned int    selection       = 0;
    uint8_t         count           = 0;
    size_t          community_len   = 0;

    community_count = kms_communityList();
    for (count = 0; count < community_count; count++) {
         printf("            %d - %s\n", count+1, communities[count]);
    }
    printf("        Selection: ");
    scanf(" %u", &selection);
    if ((selection > 0) && (selection <= community_count)) {
        community_len = strlen(STORAGE_COMMUNITIES_DIRECTORY) + 1 +
                        strlen(communities[selection-1]) + 1;
        ret_val       = calloc(1, community_len);
        snprintf(ret_val, community_len, "%s/%s", 
                 STORAGE_COMMUNITIES_DIRECTORY, 
                 communities[selection-1]);
    }
    getchar();

    kms_clearCommunitiesList();

    return ret_val;
} /* kms_communityListSelect */

/***************************************************************************//**
 * Handle Community management functions.
 *
 *     0 - Return to previous menu
 *     1 - List Communities
 *     2 - Add Community
 *     3 - Delete Community
 *     4 - List Community Details
 ******************************************************************************/
void communityMenu() {
    unsigned int  selection          = 0;
    char          confirm            = 0;
    unsigned int  cont               = 1;
    unsigned int  c                  = 0;
    char         *selected_community = NULL;
    char         *selected_kms       = NULL;
    FILE         *file_p             = NULL;
    int           num_communities    = 0;
    char         *ZT                 = NULL;
    uint8_t      *ZT_ostr            = NULL;
    size_t        ZT_len             = 0;
    char         *KPAK               = NULL;
    uint8_t      *KPAK_ostr          = NULL;
    size_t        KPAK_len           = 0;

    char  version[KMS_MAX_LINE_LEN];
    char  cert_uri[KMS_MAX_LINE_LEN];
    char  kms_uri[KMS_MAX_LINE_LEN];
    char  issuer[KMS_MAX_LINE_LEN];
    char  valid_from[KMS_MAX_LINE_LEN];
    char  valid_to[KMS_MAX_LINE_LEN];
    short revoked;
    char  user_id_format[KMS_MAX_LINE_LEN];

    while (cont) {
        memset(community,       0, sizeof(community));
        memset(version,         0, sizeof(version));
        memset(cert_uri,        0, sizeof(cert_uri));
        memset(kms_uri,         0, sizeof(kms_uri));
        memset(issuer,          0, sizeof(issuer));
        memset(valid_from,      0, sizeof(valid_from));
        memset(valid_to,        0, sizeof(valid_to));
        memset(user_id_format,  0, sizeof(user_id_format));
        memset(kms_domain_list, 0, sizeof(kms_domain_list));
        revoked = ES_FALSE;

        printf("\n    Community Menu\n");
        printf("    --------------\n");
        printf("        0 - Return to previous menu\n");
        printf("        1 - List Communities\n");
        printf("        2 - Add Community\n");
        printf("        3 - Delete Community\n");
        printf("        4 - List Community Details\n");
        printf("    Selection: ");
        scanf("%u", &selection);
        switch (selection) {
            case 0  : {
                cont = 0; 
                break; 
            }
            case 1  : { 
                printf("\n    Stored communities are:\n");
                num_communities = kms_communityList();
                for (c = 0; c < num_communities; c++) {
                    printf("        %s\n", communities[c]);
                }
                kms_clearCommunitiesList();
                break; 
            }
            case 2  : {
                getchar();
                printf("        Name of new community     : ");
                /* AKA Cert-URI */
                fgets(community, sizeof(community)-1, stdin);
                memset(&community[strlen(community)-1], 0, 1);
                if (strlen(community) > 0) {
                    if (!community_exists(community)) {
                        printf("        Version (optional)        : ");
                        fgets(version, sizeof(version)-1, stdin);
                        memset(&version[strlen(version)-1], 0, 1);
                        printf("        Select KmsUri             : \n");
                        selected_kms = kms_listSelect();
                        /* strip the path from the selected kms file */
                        strcpy(kms_uri, selected_kms+strlen(STORAGE_KMS_DIRECTORY)+1);
                        printf("        Issuer (optional)         : ");
                        fgets(issuer, sizeof(issuer)-1, stdin);
                        memset(&issuer[strlen(issuer)-1], 0, 1);
                        printf("        Valid From (optional)     : ");
                        fgets(valid_from, sizeof(valid_from)-1, stdin);
                        memset(&valid_from[strlen(valid_from)-1], 0, 1);
                        printf("        Valid To (optional)       : ");
                        fgets(valid_to, sizeof(valid_to)-1, stdin);
                        memset(&valid_to[strlen(valid_to)-1], 0, 1);
                        do {
                            printf("        Revoked (y|n default 'N') :");
                            scanf("%c", &confirm);
                        } while ((confirm != 'Y') && (confirm != 'y') &&
                                 (confirm != 'N') && (confirm != 'n') &&
                                 (confirm != '\n'));
                        if ((confirm == 'Y') || (confirm == 'y')) {
                            revoked = ES_TRUE;
                        }
                        if (confirm != '\n') { getchar(); } 
                        printf("        User ID Format (optional) : ");
                        fgets(user_id_format, sizeof(user_id_format)-1, stdin);
                        memset(&user_id_format[strlen(user_id_format)-1], 0, 1);
                        printf("        KMS domain list (optional): ");
                        fgets(kms_domain_list, sizeof(kms_domain_list)-1, stdin);
                        memset(&kms_domain_list[strlen(kms_domain_list)-1], 0, 1);

                        /* Get Z_T and KPAK for KMS. */    
                        ZT        = kms_getZT(kms_uri);
                        KPAK      = kms_getKPAK(kms_uri);

                        /* Convert to Octet Strings. */
                        utils_convertHexStringToOctetString(
                            ZT,         (strlen(ZT)/2)+(strlen(ZT)%2), 
                            &ZT_ostr,   &ZT_len);
                        utils_convertHexStringToOctetString(
                            KPAK,       (strlen(KPAK)/2)+(strlen(KPAK)%2), 
                            &KPAK_ostr, &KPAK_len);

                        if (NULL != ZT)   { free(ZT);   ZT   = NULL; }
                        if (NULL != KPAK) { free(KPAK); KPAK = NULL; }

                        if (!community_store(
                            version,
                            community, /* CertUri */
                            kms_uri,   /* KmsUri  */
                            issuer,
                            valid_from,
                            valid_to,
                            revoked,
                            user_id_format,
                            ZT_ostr,        /* Mandatory pub_enc_key - AKA 'Z' */
                            ZT_len,         /* Mandatory pub_enc_key len.      */
                            KPAK_ostr,      /* Mandatory pub_auth_key - 'KPAK' */
                            KPAK_len,       /* Mandatory pub_auth_key len.     */
                            kms_domain_list /* Optional kms_domain_list        */
                            )) {
                            printf("    Community save successful\n");
                        }
                        else {
                            printf("\n    ERROR: Community save failed\n");
                        }
                        if (NULL != ZT_ostr)   { 
                            free(ZT_ostr);
                            ZT_ostr   = NULL;
                            ZT_len    = 0;
                        }
                        if (NULL != KPAK_ostr) { 
                            free(KPAK_ostr); 
                            KPAK_ostr = NULL; 
                            KPAK_len  = 0;
                        }
                    }
                    else {
                        printf("\n    ERROR: Cannot proceed, community <%s> exists, delete it first!\n", 
                               community);
                    }
                }
                else {
                    printf("\n    ERROR: Cannot proceed, no community name specified!\n");
                }

                break; 
            }
            case 3  : {
                printf("\n    Delete Community:\n");
                printf("    -----------------\n");
                printf("        Select Community:\n");
                selected_community = kms_communityListSelect();
                if (selected_community) {
                    do {
                        printf("\n    Are you absolutely sure? (y/n): ");
                        scanf(" %c", &confirm);
                    } while ((confirm != 'Y') && (confirm != 'y') &&
                             (confirm != 'N') && (confirm != 'n'));

                    if ((confirm == 'Y') || (confirm == 'y')) {
                        strcpy(community, selected_community +
                               strlen(STORAGE_COMMUNITIES_DIRECTORY)+1);
                        if (community_remove(community)) {
                            printf("\n    ERROR: Failed to remove community <%s>!\n", 
                                   selected_community);
                        }
                    }
                    free(selected_community);
                    
                    selected_community = NULL;
                }
                break; 
            }
            case 4  : {
                printf("\n    Community to list details for:\n");
                printf("    ------------------------------\n");
                selected_community = kms_communityListSelect();
                if (selected_community) {
                    printf("\n");
                    printf("    ++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                    printf("    Contents of Community file:\n        %s\n\n",  
                           selected_community);
                    if (NULL != (file_p = fopen(selected_community, "r"))) {
                        memset(conf_line, 0, sizeof(conf_line));
                        while (NULL != fgets(conf_line, KMS_MAX_LINE_LEN, file_p)) {
                            printf("%s", conf_line);
                        }
                    }
                    else {
                        printf("\n    ERROR: Could not open <%s>!\n", selected_community);
                    }
                    printf("    ++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                    free(selected_community);
                    selected_community = NULL;
                }
                break; 
            }
            default : {
                break; 
            }
        }
    }

} /* communityMenu */

/******************************************************************************/
/* User menu functions                                                        */
/******************************************************************************/

/***************************************************************************//**
 * Clear User list array.
 ******************************************************************************/
void kms_clearUsersList() {
    uint8_t c = 0;

    for (; c < KMS_MAX_USERS; c++) {
        if (users[c] != NULL) {
            free(users[c]);
            users[c] = NULL;
        }
        else {
            break; /* End of previous data */
        }
    }
} /* kms_clearUsersList */

/***************************************************************************//**
 * Create User list, copying all User names into in the User array.
 ******************************************************************************/
uint8_t kms_userList() {
    DIR            *dir_p           = NULL;
    struct  dirent *dirEntry_p      = NULL;
    struct stat     file_info;

    uint8_t      ret_val   = 0;
    unsigned int selection = 0;
    uint8_t      count     = 0;

    /* Initialise storage structure. */
    memset(tmp_path,  0, sizeof(tmp_path));
    kms_clearUsersList();

    /* Could have used user_list() here. */

    snprintf(tmp_path, sizeof(tmp_path), STORAGE_USERS_DIRECTORY);
    if (NULL != (dir_p =  opendir(tmp_path))) {
        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name, ".gitignore") != 0) &&
                (strcmp(dirEntry_p->d_name, ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {
                memset(tmp_path,  0, sizeof(tmp_path));
                snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
                         STORAGE_USERS_DIRECTORY,
                         dirEntry_p->d_name);

                if ((!stat(tmp_path, &file_info)) &&
                    (S_ISREG(file_info.st_mode))) {

                    users[ret_val] = calloc(1, strlen(dirEntry_p->d_name)+1);
                    strcpy(users[ret_val], dirEntry_p->d_name);
                    ret_val++;
                }
            }
        }
        closedir(dir_p);
    }

    return ret_val;

} /* kms_userList */

/***************************************************************************//**
 * Display the list of users and allow selection of one of these, returning 
 * this selection.
 *
 * @return The selected user.
 ******************************************************************************/
char *kms_userListSelect() {
    DIR            *dir_p           = NULL;
    struct  dirent *dirEntry_p      = NULL;
    struct stat     file_info;
    char           *ret_val         = NULL;
    uint8_t         user_count      = 0;
    unsigned int    selection       = 0;
    uint8_t         count           = 0;
    size_t          user_len        = 0;

    user_count = kms_userList();
    for (count = 0; count < user_count; count++) {
         printf("            %d - %s\n", count+1, users[count]);
    }
    printf("        Selection: ");
    scanf(" %u", &selection);
    if ((selection > 0) && (selection <= user_count)) {
        user_len = strlen(STORAGE_USERS_DIRECTORY) + 1 +
                   strlen(users[selection-1]) + 1;
        ret_val  = calloc(1, user_len);
        snprintf(ret_val, user_len, "%s/%s", STORAGE_USERS_DIRECTORY, 
                 users[selection-1]);
    }
    getchar();

    return ret_val;

} /* kms_userListSelect */

/***************************************************************************//**
 * Handle User management functions.
 *
 *     0 - Return to previous menu
 *     1 - List Users
 *     2 - Add User
 *     3 - Delete User
 *     4 - List User Details (to send)
 ******************************************************************************/
void userMenu() {
    unsigned int  selection          = 0;
    char          confirm            = 0;
    unsigned int  cont               = 1;
    unsigned int  c                  = 0;
    unsigned int  res                = 0;
    char         *selected_user      = NULL;
    char         *selected_community = NULL;
    FILE         *file_p             = NULL;
    struct stat   file_info;
    int           num_users          = 0;
    uint8_t      *rnd_str            = NULL;
    size_t        rnd_str_len        = 32;

    while (cont) {
        memset(user_date, 0, sizeof(user_date));
        memset(user_uri,  0, sizeof(user_uri));
        memset(community, 0, sizeof(community));
        memset(tmp_path,  0, sizeof(tmp_path));

        printf("\n    UserMenu\n");
        printf("    --------\n");
        printf("        0 - Return to previous menu\n");
        printf("        1 - List Users\n");
        printf("        2 - Add User\n");
        printf("        3 - Delete User\n");
        printf("        4 - List User Details (to send)\n");
        printf("    Selection: ");
        scanf("%u", &selection);
        switch (selection) {
            case 0  : {
                cont = 0;
                break;
            }
            case 1  : {
                printf("\n    Stored Users are:\n");
                num_users = kms_userList();
                for (c = 0; c < num_users; c++) {
                    printf("        %s\n", users[c]);
                }
                kms_clearUsersList();
                break;
            }
            case 2  : {
                printf("        Note! entries are not validated.\n");
                printf("        Enter date validity for new User (YYYY-MM): ");
                scanf(" %s", &user_date);
                printf("        Enter identify of new User (e.g. tel:+number): ");
                scanf(" %s", &user_uri);
                printf("        Which community is the new user part of:\n");
                selected_community = kms_communityListSelect();
                if (selected_community) {
                    do {
                        printf("        Do you want to use RFC values, rather than random? (y/n): ");
                        scanf(" %c", &confirm);
                    } while ((confirm != 'Y') && (confirm != 'y') &&
                             (confirm != 'N') && (confirm != 'n'));
                    do {
                        if ((confirm == 'Y') || (confirm == 'y')) {
                            utils_convertHexStringToOctetString(
                                rfc6507_v, 
                                (strlen(rfc6507_v)/2) + (strlen(rfc6507_v)%2),
                                &rnd_str, &rnd_str_len);
                        }
                        else {
                            rnd_str_len = 32;
                            ES_PRNG(&rnd_str, rnd_str_len);
                        }
                        if ((res = kms_addUser((char *)&user_date, (char *)&user_uri, 
                                (char *)selected_community+
                                strlen(STORAGE_COMMUNITIES_DIRECTORY)+1,
                                &rnd_str, &rnd_str_len)) != KMS_V_FAILURE) {
                                /* ES_SUCCESS or ES_FAILURE */
                                if (res == ES_SUCCESS) {
                                    printf("    User save successful\n");
                                }
                                else {
                                    printf("\n    ERROR: User save failed\n");
                                }
                                break;
                        }
                        else { /* The value for 'v' we created failed in 
                                * calculations, so pick another one.
                                * Clear out 'v' first and loop.
                                */
                            if (rnd_str != NULL) {
                                memset(rnd_str, 0, rnd_str_len);
                                free(rnd_str);
                                rnd_str     = NULL;
                                rnd_str_len = 32;
                            }
                        }
                    } while (1);
                    /* Clear random in case we loop and add again. */
                    if (rnd_str != NULL) {
                        memset(rnd_str, 0, rnd_str_len);
                        free(rnd_str);
                        rnd_str     = NULL;
                        rnd_str_len = 32;
                    }
                    free(selected_community);
                    selected_community = NULL;
                }

                /* TBD - Check it doesn't already exist. */
                break;
            }
            case 3  : {
                printf("\n    Delete User :\n");
                printf("    -----------------\n");
                printf("        Select User:\n");
                selected_user = kms_userListSelect();
                if (selected_user) {
                    do {
                        printf("\n    Are you absolutely sure? (y/n): ");
                        scanf(" %c", &confirm);
                    } while ((confirm != 'Y') && (confirm != 'y') &&
                             (confirm != 'N') && (confirm != 'n'));

                    if ((confirm == 'Y') || (confirm == 'y')) {
                        /* Strip path */
                        strcpy(tmp_path, selected_user +
                            strlen(STORAGE_USERS_DIRECTORY)+1);
                        /* Get elements */
                        sscanf(tmp_path, "%s %s %s", user_date, user_uri, community); 
                        /* We'll use user_date as full user_id store is:
                         *   id = date|NULL|id.
                         */
                        strcpy((char *)user_date+strlen((char *)user_date)+1, 
                               user_uri);
                        if (user_remove(user_date, /* user-id we just did. */
                                strlen(user_date) + strlen(user_uri) + 2, 
                                community)) {
                            printf("\n    ERROR: Failed to remove community <%s>!\n", 
                                   selected_user);
                        }
                    }
                    free(selected_user);
                    selected_user = NULL;
                }
                break;
            }
            case 4  : {
                printf("\n    User to list details for:\n");
                printf("    -------------------------\n");
                selected_user = kms_userListSelect();
                if (selected_user != NULL) {

                    /* We know the User exists, what about the community? */

                    /* Community is after the last ' ' in the filename. */
                    char *tmp = strrchr(selected_user, ' ');
                    memset(tmp_path,  0, sizeof(tmp_path));
                    snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
                        STORAGE_COMMUNITIES_DIRECTORY, tmp+1);

                    if ((!stat(tmp_path, &file_info)) &&
                        (S_ISREG(file_info.st_mode))) {

                        /* The filename has everything we need to identify the 
                         * data, user-date, user-uri and user-community.
                         */
                        printf("\n");
                        printf("    ++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                        printf("    The following data needs to be relayed (SECURELY!)\n");
                        printf("    to the client (perhaps using Secure Chorus message\n");
                        printf("    structures), but it's up to you to pick your\n");
                        printf("    preferred protocol.\n\n");

                        printf("    If you are just using this, and the ECCSI-SAKKE\n");
                        printf("    code, you can either modify the USER and COMMUNITY\n");
                        printf("    data creation examples provided in the ECCSI-SAKKE\n");
                        printf("    project 'es-demo-nnn.c' file, or, just create the\n");
                        printf("    file and add the content as indicated below.\n\n");

                        printf("    NOTE! If you following the 'modify es-demo-nnn.c'\n");
                        printf("    route, for adding this data to the client(s) demo,\n");
                        printf("    you will NOT need to include HASH (i.e. only add\n");
                        printf("    SSK, RSK and PVT) for the user data. This is\n");
                        printf("    because the HASH will calculated and added to the\n");
                        printf("    file when it is created.\n\n");

                        printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
                        printf("Create User filename:\n    <your-storage-dir>%s\n",  selected_user+1);
                        printf("With the following content:\n\n");
                        if (NULL != (file_p = fopen(selected_user, "r"))) {
                            memset(conf_line, 0, sizeof(conf_line));
                            while (NULL != fgets(conf_line, KMS_MAX_LINE_LEN, file_p)) {
                                printf("%s", conf_line);
                            }
                            fclose(file_p);
                            printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
                            printf("Create Community filename:\n    <your-storage-dir>%s\n",  tmp_path+1);
                            printf("With the following content:\n\n");
                            if (NULL != (file_p = fopen(tmp_path, "r"))) {
                                memset(conf_line, 0, sizeof(conf_line));
                                while (NULL != fgets(conf_line, KMS_MAX_LINE_LEN, file_p)) {
                                    printf("%s", conf_line);
                                }
                                fclose(file_p);
                            }
                            else {
                                printf("\n    ERROR: Cannot proceed, could not open 'community' file <%s>!\n", 
                                       tmp_path);
                            }
                            printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                        }
                        else {
                            printf("\n    ERROR: Cannot proceed, could not open 'user' file <%s>!\n", 
                                   selected_user);
                        }
                    }
                    else {
                        printf("%s    ERROR: Cannot proceed community <%s> for user <%s> does not exist!\n", 
                               tmp+1, selected_user);
                    }
                    free(selected_user);
                    selected_user = NULL;
                }
                break;
                default : {
                    break;
                }
            }
        }
    }

} /* userMenu */

/***************************************************************************//**
 * Top level menu
 *
 *     0 Exit
 *     1 KMS Management
 *     2 Community Management
 *     3 User Management
 ******************************************************************************/
int main(int argc, char *argv[]) {
    unsigned int selection = 0;
    unsigned int cont      = 1;

    memset(kms,         0, KMS_MAX_KMS);
    memset(communities, 0, KMS_MAX_COMMUNITIES);
    memset(users,       0, KMS_MAX_USERS);

    /* Initialisation - MUST be done!!!  */
    ms_initParameterSets();
    community_initStorage();

    while (cont) {
        printf("\n    Main Menu\n");
        printf("    =========\n");
        printf("        0 Exit\n");
        printf("        1 KMS Management\n");
        printf("        2 Community Management\n");
        printf("        3 User Management\n");
        printf("    Selection: ");
        scanf("%u", &selection);
        switch (selection) {
            case 0  : { cont = 0;        break; }
            case 1  : { kmsMenu();       break; }
            case 2  : { communityMenu(); break; }
            case 3  : { userMenu();      break; }
            default : { break;                  }
        }
        getchar();
    }

    ms_deleteParameterSets();
    community_deleteStorage();

    kms_clearKmsList();
    kms_clearCommunitiesList();
    kms_clearUsersList();
} /* main */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
