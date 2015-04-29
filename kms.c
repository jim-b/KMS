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
 * @file kms.c
 * @brief KMS crypto funtions.
 ******************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <utils.h>
#include <log.h>
#include <openssl/bn.h>
#include <openssl/sha.h> /* For SHA256_DIGEST_LENGTH */
#include <openssl/ec.h>

#include <kms.h>
#include <mikeySakkeParameters.h>
#include <communityParameters.h>
#include <userParameters.h>
#include <kmsParameters.h>
#include <eccsi.h> /* For computeHS */
#include <log.h>

#define KES_SECTION_NAME   "(KMS) " /*!< DEBUG output section ID.     */

#define MAX_RSK_COORD_SIZE 256      /*!< Maximum RSK coordinate size. */
#define ECCSI_ERR_HS    "ECCSI Compute HS, " /*!< ERROR start for compute HS. */

/***************************************************************************//**
 * Creates and stores the KMS keys :
 *     z_T   KMS Master Secret (SECRET! must NEVER leave the KMS)
 *     Z_T   KMS Public Key
 *     KSAK  KMS Secret Authentication Key (SECRET! must NEVER leave the KMS)
 *     KPAK  KMS Public Authentication Key (SECRET! must NEVER leave the KMS)
 *
 * It also returns pointers to this Key Material for callers to use.
 *
 * Z_T (Public Key) and KPAK are provided to clients as 'community' data.
 * z_T (Master Secret) and KSAK are kept secret from clients.
 *
 * @param[in]  ms_param_set  Mikey-Sakke Paraneter Set (currently only one).
 * @param[in]  kms_id        The KMS id/uri - forms part of the filename in
 *                           which the KMS Key Material is stored.
 * @param[in]  version       A version for the key material (might be needed
 *                           in future).
 * @param[in]  owner         An owner id. for the key material (might be 
 *                           needed in future).
 * @param[in]  z_T           A Random Number for 'z_T' (Master Secret).
 * @param[in]  z_T_len       Length of 'z_T' octet string.
 * @param[in]  KSAK          A Random Number for 'KSAK' (KMS Secret 
 *                           Authenticationi Key).
 * @param[in]  KSAK_len      Length of 'KSAK' octet string.
 *
 * @return ES_SUCCESS, ES_FAILURE 
 *****************************************************************************/
uint8_t kms_createKMSKeys(
    const uint8_t   ms_param_set,
    const uint8_t  *kms_id,
    const uint8_t  *version,
    const uint8_t  *owner,
    const uint8_t  *z_T,
    const size_t    z_T_len,
    const uint8_t  *KSAK,
    const size_t    KSAK_len) {

    uint8_t   ret_val           = ES_FAILURE;
    short     error_encountered = ES_FALSE;

    EC_GROUP *ms_curve   = NULL;
    EC_GROUP *nist_curve = NULL;
    int       res        = 0;
    BN_CTX   *bn_ctx     = BN_CTX_new();

    EC_POINT *P_point    = NULL;
    BIGNUM   *z_T_bn     = NULL;

    uint8_t  *Z_T        = NULL;
    size_t    Z_T_len    = 0;
    BIGNUM   *Z_Tx_bn    = NULL;
    BIGNUM   *Z_Ty_bn    = NULL;

    BIGNUM   *KSAK_bn    = NULL;

    EC_POINT *KPAK_point = NULL;
    uint8_t  *KPAK       = NULL;
    size_t    KPAK_len   = 0;
    BIGNUM   *KPAK_x_bn  = NULL;
    BIGNUM   *KPAK_y_bn  = NULL;

    /* printf("    ***%s:%s:%d \n", __FILE__, __FUNCTION__, __LINE__); */

    ES_DEBUG("%s  Create KMS Keys", KES_SECTION_NAME);
    ES_DEBUG("%s  ===============", KES_SECTION_NAME);

    /**************************************************************************/
    /* Check passed parameters                                                */
    /**************************************************************************/
    if (kms_id == NULL) {
        ES_ERROR("KMS Create keys 'kms_id' reference is NULL!");
        error_encountered = ES_TRUE;
    }

    /**************************************************************************/
    /* Init                                                                   */
    /**************************************************************************/
    if (!error_encountered) {
        nist_curve = community_get_NIST_P256_Curve();
        ms_curve   = ms_getParameter_E(ms_param_set);
    }

    /**************************************************************************/
    /* Create KMS Master Secret (z_T).                                        */
    /**************************************************************************/
    if (!error_encountered) {
        /* KMS Master Secret - a random number between 2 and q-1. */
        ES_DEBUG("%s    Create z_T Master Secret", KES_SECTION_NAME);
        ES_DEBUG("%s    ------------------------", KES_SECTION_NAME);
        ES_DEBUG("%s      (RFC 6508, Section 2.2): z_T a random num between 2 and q-1",
                 KES_SECTION_NAME);

        if (!(z_T_bn = BN_bin2bn((unsigned char *)z_T, z_T_len, z_T_bn))) {
            ES_ERROR("%s:%s:%d - 'z_T' BN creation failed!",
                      __FILE__, __FUNCTION__, __LINE__);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME,
                "      z_T:", 8, z_T, z_T_len);
        }
    }

    /**************************************************************************/
    /* Create Z_T - KMS Public Key (PubEncKey in Secure Chorus).              */
    /**************************************************************************/
    if (!error_encountered) {

        /**********************************************************************/
        /* Create Zx/Zy Public Keys [z_T]P.                                   */
        /**********************************************************************/
        ES_DEBUG("%s    Calculate Z_T", KES_SECTION_NAME);
        ES_DEBUG("%s    -------------", KES_SECTION_NAME);
        ES_DEBUG("%s      (RFC 6508, Section 2.2 and 6.1): Z_T = [z_T]P", 
                 KES_SECTION_NAME);

        if (NULL == (P_point = EC_POINT_dup(ms_getParameter_P(ms_param_set), 
                                            ms_curve))) {
            ES_ERROR("%s:%s:%d - Failed to dup. point 'P' for param-set <%d>!",
                __FILE__, __FUNCTION__, __LINE__, ms_param_set);
            error_encountered = ES_TRUE;
        } 
        else {
            res = EC_POINT_mul(ms_curve, P_point, 0, 
                      P_point, 
                      z_T_bn, bn_ctx);

            /*ES_DEBUG_DISPLAY_AFFINE_COORDS(KES_SECTION_NAME,
             *   "      Z_T (PublicKey 'x' and 'y' co-ordinates)", 10, 
             *   ms_curve, P_point);
             */

            /* Get the Z_T points. */
            Z_Tx_bn = BN_new();
            Z_Ty_bn = BN_new();
            EC_POINT_get_affine_coordinates_GFp(
                ms_curve,
                P_point, Z_Tx_bn, Z_Ty_bn, bn_ctx);

            Z_T_len = (128*2)+1;
            Z_T     = calloc(1, Z_T_len);
            Z_T[0]  = 0x04;
            if (!BN_bn2bin(Z_Tx_bn, /* Pad */
                           (unsigned char *)Z_T+1+(128-BN_num_bytes(Z_Tx_bn)))) {
                ES_ERROR("%s:%s:%d - Failed to create Z_T_x!",
                    __FILE__, __FUNCTION__, __LINE__);
                error_encountered = ES_TRUE;
            } else if (!BN_bn2bin(Z_Ty_bn, /* Pad */
                       (unsigned char *)Z_T+1+128-(128-BN_num_bytes(Z_Ty_bn)))) {
                ES_ERROR("%s:%s:%d - Failed to create Z_T_y!",
                    __FILE__, __FUNCTION__, __LINE__);
                error_encountered = ES_TRUE;
            } else {
                ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME, 
                    "      Z_T:", 8, Z_T, Z_T_len);
            }
        }
    }

    /**************************************************************************/
    /* Create KSAK                                                            */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s    Create KSAK", KES_SECTION_NAME);
        ES_DEBUG("%s    -----------", KES_SECTION_NAME);
        ES_DEBUG("%s      (RFC 6508, Section 4.2): A random non 0 int modulo q",
                 KES_SECTION_NAME);
        /* RFC 6507 Section 4.2. KSAK MUST be chosen to be a random secret 
         * non-zero integer modulo q. The value of the KSAK must be kept 
         * secret to the KMS.
         */
        if (!(KSAK_bn = BN_bin2bn((unsigned char *)KSAK, KSAK_len, KSAK_bn))) {
            ES_ERROR("%s:%s:%d - 'KSAK' BN creation failed!",
                      __FILE__, __FUNCTION__, __LINE__);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME,
                "      KSAK:", 8, KSAK, KSAK_len);
        }
    }

    /**************************************************************************/
    /* KPAK calculation (RFC 6507, Section 4.2): KPAK = [KSAK]G               */
    /**************************************************************************/
    if (!error_encountered) {
	ES_DEBUG("%s    Calculate KPAK", KES_SECTION_NAME);
        ES_DEBUG("%s    --------------", KES_SECTION_NAME);
        ES_DEBUG("%s      (RFC 6507, Section 4.2): KPAK = [KSAK]G", 
                 KES_SECTION_NAME);

        if (NULL == (KPAK_point = 
                     EC_POINT_dup(community_getG_point(), ms_curve))) {
            ES_ERROR("%s:%s:%d - Failed to dup. point 'G'!",
                __FILE__, __FUNCTION__, __LINE__, ms_param_set);
            error_encountered = ES_TRUE;
        }
        else {
            res = EC_POINT_mul(
                      nist_curve,
                      KPAK_point, 0, KPAK_point, KSAK_bn, bn_ctx);

            /* Get the KPAK points. */
            KPAK_x_bn = BN_new();
            KPAK_y_bn = BN_new();
            EC_POINT_get_affine_coordinates_GFp(
                nist_curve, KPAK_point, KPAK_x_bn, KPAK_y_bn, bn_ctx); 
            KPAK_len = (32*2)+1;
            KPAK     = calloc(1, KPAK_len);
            KPAK[0]  = 0x04;
            if (!BN_bn2bin(KPAK_x_bn, /* Pad */
                           (unsigned char *)KPAK+1+(32-BN_num_bytes(KPAK_x_bn)))) {
                ES_ERROR("%s:%s:%d - Failed to create KPAK (x-coord) octet-string!",
                         __FILE__, __FUNCTION__, __LINE__);
                error_encountered = ES_TRUE;
            } else if (!BN_bn2bin(KPAK_y_bn, /* Pad */
                       (unsigned char *)KPAK+1+32-(32-BN_num_bytes(KPAK_y_bn)))) {
                ES_ERROR("%s:%s:%d - Failed to create KPAK (y-coord) octet-string!",
                         __FILE__, __FUNCTION__, __LINE__);
                error_encountered = ES_TRUE;
            }
            else {
                ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME, 
                    "      KPAK:", 8, KPAK, KPAK_len);
            }
        }
    }

    /* Save to file. */
    if (!error_encountered) {
        ret_val = kms_addKms(version, kms_id, owner, 
                              z_T,    BN_num_bytes(z_T_bn),
                              Z_T,    Z_T_len,
                              KSAK,   BN_num_bytes(KSAK_bn),
                              KPAK,   KPAK_len);
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    /* BIGNUMs */
    BN_clear_free(KPAK_x_bn);
    BN_clear_free(KPAK_y_bn);
    BN_clear_free(z_T_bn);
    BN_clear_free(Z_Tx_bn);
    BN_clear_free(Z_Ty_bn);
    BN_clear_free(KSAK_bn);

    /* Strings */
    if (KPAK != NULL) {
        memset(KPAK, 0, KPAK_len);
        free(KPAK);
        KPAK     = NULL;
        KPAK_len = 0;
    }
    if (Z_T != NULL) {
        memset(Z_T, 0, Z_T_len);
        free(Z_T);
        Z_T     = NULL;
        Z_T_len = 0;
    }

    /* Curves - temporary pointers */
    ms_curve   = NULL;
    nist_curve = NULL;

    /* Points */
    EC_POINT_clear_free(P_point);
    EC_POINT_clear_free(KPAK_point);

    /* BN Context */
    if (NULL != bn_ctx) {
       BN_CTX_free(bn_ctx);
    }

    return ret_val;
} /* kms_createKMSKeys */

/***************************************************************************//**
 * Creates SSK (Secret Signing Key)/ PVT (Public Validation Token) Pair for 
 * a client (user).
 *
 * RFC 6507 Section 5.1.1.
 *
 * @param[in]  community     The 'community' the 'user' is part of.
 * @param[in]  user_id       Octet string pointer of the 'user-id'. user-id is
 *                           comprised date|null|uri|null.
 * @param[in]  user_id_len   Length of 'user-id' octet stringi (as the id
 *                           contains a NULL).
 * @param[out] ssk           Octet string pointer of the 'ssk', Secret Signing
 *                           Key.
 * @param[out] ssk_len       Length of 'ssk' octet string.
 * @param[out] pvt           Octet string pointe of the 'pvt', Public 
 *                           Validation Token.
 * @param[out] pvt_len       Length of 'pvt' octet string.
 * @param[in]  v             A random number for 'v' (used in calculations.
 *                           Note! This value will be cleared by this function
 *                           on exit as per RFC dewscription.
 * @param[in]  v_len         Length of 'v' octet string.
 *
 * @return ES_SUCCESS, ES_FAILURE or ES_V_FAILURE Note! The latter informs the 
 * caller to try another value for 'v' as there was some problem with 
 * calculation, see  RFC 6507 Section 5.1.1. point 5.
 *****************************************************************************/
uint8_t kms_createSSKPVTPairForUser(
    const uint8_t   *community,
    const uint8_t   *user_id,
    const size_t     user_id_len,
    uint8_t        **ssk,
    size_t          *ssk_len,
    uint8_t        **pvt,
    size_t          *pvt_len,
    uint8_t        **v, /* A random octet string */ 
    size_t          *v_len) {

    /* printf("        ***%s:%s:%d \n", 
     *        __FUNCTION__, __FILE__, __LINE__); 
     */

    short ret_val           = ES_FAILURE;
    short error_encountered = ES_FALSE;

    BN_CTX   *bn_ctx        = BN_CTX_new();
    BIGNUM   *v_bn          = NULL;
    BIGNUM   *KSAK_bn       = NULL;
    BIGNUM   *SSK_bn        = NULL;
    BIGNUM   *SSK_check_bn  = NULL;
    BIGNUM   *hash_check_bn = NULL;
    BIGNUM   *KPAKx_bn      = NULL;
    BIGNUM   *KPAKy_bn      = NULL;
    BIGNUM   *PVTx_bn       = NULL;
    BIGNUM   *PVTy_bn       = NULL;
    BIGNUM   *Gx_bn         = NULL;
    BIGNUM   *Gy_bn         = NULL;
    uint8_t  *G             = NULL;
    size_t    G_len         = 0;
    uint8_t  *kpak          = NULL;
    size_t    kpak_len      = 0;
    EC_POINT *PVT_point     = NULL;
    EC_POINT *KPAK_point    = NULL;
    int       count         = 0;
    uint8_t  *hash_result   = NULL;
    uint8_t   kms_uri[1024];
    int       res           = 0;

    ES_DEBUG(KES_SECTION_NAME "    Creating SSK/PVT pair for User");
    ES_DEBUG(KES_SECTION_NAME "    ==============================");
    ES_DEBUG_PRINT_ID(KES_SECTION_NAME, "  user:", 12, user_id, user_id_len);

    if (!(hash_result = calloc(1, (community_get_N()*2)+1))) { 
        /* hash_result is a string so *2 +1 */
        ES_ERROR("%scould not allocate space for HS hash!", KES_SECTION_NAME);
        error_encountered = ES_TRUE;
    }
    else {
        /* G */
        Gx_bn  = BN_new();
        Gy_bn  = BN_new();
        EC_POINT_get_affine_coordinates_GFp(
            community_get_NIST_P256_Curve(), community_getG_point(), Gx_bn, Gy_bn, bn_ctx);
        G_len  = 65;
        G      = calloc(1, G_len);
        G[0]   = 0x04;

        BN_bn2bin(Gx_bn, G + 1  + (32 - BN_num_bytes(Gx_bn)));
        BN_bn2bin(Gy_bn, G + 33 + (32 - BN_num_bytes(Gy_bn)));

        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME,
            "        G:", 12, G, G_len);
    }

    /*************************************************************************/
    /* RFC 6507 Section 5.1.1.                                               */
    /* 2) Compute PVT = [v]G                                                 */
    /*************************************************************************/
    if (!error_encountered) {
        /* Choose a random ephemeral number of F_q - but value passed in. */
        v_bn = BN_new();
        ES_DEBUG(KES_SECTION_NAME 
            "        1) Choose a random (ephemeral) non zero element of F_q!!");

        if (!(v_bn = BN_bin2bn((unsigned char *)*v, *v_len, v_bn))) {
            ES_ERROR("%s:%s:%d - 'v' BN creation failed!",
                      __FILE__, __FUNCTION__, __LINE__); 
            error_encountered = ES_TRUE;
        }

        /* Set PVT to G initially before multiplying by 'v'. */
        ES_DEBUG("%s        2) Compute PVT (Public Validation Token) PVT = v[G]",
                 KES_SECTION_NAME);
        PVT_point = EC_POINT_new(community_get_NIST_P256_Curve());
        EC_POINT_set_affine_coordinates_GFp(community_get_NIST_P256_Curve(), 
            PVT_point, Gx_bn, Gy_bn, bn_ctx);
        res = EC_POINT_mul(community_get_NIST_P256_Curve(), 
                       PVT_point, 0, PVT_point, v_bn, bn_ctx);
        ES_DEBUG_DISPLAY_AFFINE_COORDS(KES_SECTION_NAME,
            "        PVT (Public Validation Token, one per subscriber) :"
           , 12, community_get_NIST_P256_Curve(), PVT_point);
    }

    /*************************************************************************/
    /* RFC 6507 Section 5.1.1.                                               */
    /* 3) Compute the hash HS = hash(G || KPAK || ID || PVT).                */
    /*************************************************************************/

    /* -A- Firstly we need to calculate the KPAK - (RFC 6507, Section 4.2):
     *     KPAK = [KSAK]G
     */
    if (!error_encountered) {
        /* Not pretty as we're bypassing communityParameters and going 
         * straight to DB as the access function isn't in communityParameters 
         * yet.
         */
        memset(kms_uri, 0, sizeof(kms_uri));
        if (!msdb_communityGetKmsUri(community, &kms_uri)) {
            KSAK_bn = BN_new();
            BN_hex2bn(&KSAK_bn, kms_getKSAK(kms_uri));

            ES_DEBUG_DISPLAY_BN(KES_SECTION_NAME,
               "        KSAK (KMS Secret Authentication Key NEVER leaves KMS): ",
               12, KSAK_bn);

            /* Set KPAK to G initially before multiplying by 'KSAK'. */
            KPAK_point = EC_POINT_new(community_get_NIST_P256_Curve());
            EC_POINT_set_affine_coordinates_GFp(community_get_NIST_P256_Curve(), 
                KPAK_point, Gx_bn, Gy_bn, bn_ctx);
            res  = EC_POINT_mul(community_get_NIST_P256_Curve(), 
                                KPAK_point, 0, KPAK_point, KSAK_bn, bn_ctx);
            ES_DEBUG_DISPLAY_AFFINE_COORDS(KES_SECTION_NAME,
                "        KPAK ('x' and 'y' coords):", 12, 
                community_get_NIST_P256_Curve(), KPAK_point);
        }
        else {
            ES_ERROR("%s:%s:%d - Unable to get KMS details from community <%s>",
                      __FILE__, __FUNCTION__, __LINE__, community); 
            error_encountered = ES_TRUE;
        }
    }

    /* -B- Now, we can Compute the hash HS = hash(G || KPAK || ID || PVT). */
    if (!error_encountered) {
        ES_DEBUG(KES_SECTION_NAME 
            "        3) Compute the hash HS = hash(G || KPAK || ID || PVT)");

        /* KPAK */
        KPAKx_bn = BN_new();
        KPAKy_bn = BN_new();
        EC_POINT_get_affine_coordinates_GFp(community_get_NIST_P256_Curve(), 
                                            KPAK_point, KPAKx_bn, KPAKy_bn, bn_ctx);
        count    = 0;
        kpak_len = 65;
        kpak     = calloc(1, kpak_len);
        kpak[0]  = 0x04;
        BN_bn2bin(KPAKx_bn, kpak + 1  + (32 - BN_num_bytes(KPAKx_bn)));
        BN_bn2bin(KPAKy_bn, kpak + 33 + (32 - BN_num_bytes(KPAKy_bn)));
        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME,
            "         KPAK (KMS Public Authentication Key for all users in community):",
            12, kpak, kpak_len);

        /* ID */
        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME,
            "        ID (Subscriber Identity):", 12, user_id, user_id_len);

        /* PVT */
        PVTx_bn = BN_new();
        PVTy_bn = BN_new();
        EC_POINT_get_affine_coordinates_GFp(community_get_NIST_P256_Curve(), 
                                            PVT_point, PVTx_bn, PVTy_bn, bn_ctx);
        *pvt_len = 65;   
        *pvt     = calloc(1, *pvt_len);
        *pvt[0]  = 0x04;
        BN_bn2bin(PVTx_bn, *pvt + 1  + (32 - BN_num_bytes(PVTx_bn)));
        BN_bn2bin(PVTy_bn, *pvt + 33 + (32 - BN_num_bytes(PVTy_bn)));
        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME, 
            "        PVT (Public Validation Token for subscriber):",
            12, *pvt, *pvt_len);

        /* For the following calculation PVT needs to be in hex form. */
        if (computeHS(G,        G_len, 
                      kpak,     kpak_len, 
                      user_id,  user_id_len, 
                      *pvt,    *pvt_len, &hash_result)) {
            ES_ERROR("%s:%s:%d - Call to computeHS failed!",
                   __FILE__, __FUNCTION__, __LINE__);
            error_encountered = ES_TRUE;
        }
    }

    /*************************************************************************/
    /* RFC 6507 Section 5.1.1.                                               */
    /* 4) Compute SSK = (KSAK + HS * v) modulo q.                            */
    /*************************************************************************/
    if (!error_encountered) {
         ES_DEBUG(KES_SECTION_NAME 
             "        4) Compute SSK = (KSAK + HS * v) modulo q");
         /* Initially make SSK (result) = HS */
         SSK_bn = BN_bin2bn(hash_result, 32, NULL);
         ES_DEBUG_DISPLAY_BN(KES_SECTION_NAME,
             "        HS - hash (RFC 6507 Appendix A, page 14):",
             12, SSK_bn);

         /* SSK = (KSAK + HS * v) modulo q */
         BN_mul(SSK_bn, SSK_bn, v_bn, bn_ctx);
         BN_add(SSK_bn, SSK_bn, KSAK_bn);
         ES_DEBUG_DISPLAY_BN(KES_SECTION_NAME,
             "q: ", 12, community_getq_bn());

         BN_nnmod(SSK_bn, SSK_bn, community_getq_bn(), bn_ctx); /* mod q */ 
         ES_DEBUG_DISPLAY_BN(KES_SECTION_NAME,
             "        SSK (Secret Signing Key for subscriber):", 12, SSK_bn);
    }

    /*************************************************************************/
    /* RFC 6507 Section 5.1.1.                                               */
    /* 5) If SSK or HS is zero modulo q, the KMS MUST erase the SSK and      */
    /*    abort and restart with a fresh value of v.                         */
    /*                                                                       */
    /* In our case we indicate the error to the caller and let them pass     */
    /* 'v' to try again.                                                     */
    /*************************************************************************/
    if (!error_encountered) {
         ES_DEBUG("%s        5) If SSK or HS is zero modulo q, the KMS MUST erase", 
                  KES_SECTION_NAME);
         ES_DEBUG("%s           the SSK and abort and restart with a fresh value of v", 
                  KES_SECTION_NAME);
         SSK_check_bn = BN_dup(SSK_bn);
         BN_nnmod(SSK_check_bn, SSK_check_bn, community_getq_bn(), bn_ctx);
         if (!BN_is_zero(SSK_check_bn)) {
             ES_DEBUG("%s            SSK check (mod q)  != 0 - succeeded",
                      KES_SECTION_NAME);

             hash_check_bn = BN_bin2bn(hash_result, 32, NULL);
             BN_nnmod(hash_check_bn, hash_check_bn, community_getq_bn(), bn_ctx);
             if (!BN_is_zero(hash_check_bn)) {
                 ES_DEBUG("%s            hash check (mod q) != 0 - succeeded",
                          KES_SECTION_NAME);
             
                 /* Prepare SSK return for saving. */
                 *ssk_len = 32;
                 *ssk     = calloc(1, *ssk_len+1);
                 BN_bn2bin(SSK_bn, *ssk + (*ssk_len - BN_num_bytes(SSK_bn)));
             }
             else {
                 ES_ERROR("%s:%s:%d - hash check (mod q) == 0 - FAILED!", 
                          __FILE__, __FUNCTION__, __LINE__);
                 ret_val = KMS_V_FAILURE;
                 error_encountered = ES_FALSE;
             }
         }
         else {
             ES_ERROR("%s:%s:%d - SSK check (mod q) == 0 - FAILED!", 
                      __FILE__, __FUNCTION__, __LINE__);
             ret_val = KMS_V_FAILURE;
             error_encountered = ES_FALSE;
         }
    }

    /*************************************************************************/
    /* RFC 6507 Section 5.1.1.                                               */
    /* 6) Output the (SSK,PVT) pair. The KMS MUST then erase the value 'v'.  */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG(KES_SECTION_NAME
                 "        6) Output (SSK, PVT) pair and erase value of 'v'");
        /* Done directly below in Cleanup section */

        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME,
            "        PVT (Public Validation Token for subscriber):",
            12, *pvt, *pvt_len);
        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME,
            "        SSK (Secret Signing Key for subscriber):",
            12, *ssk, *ssk_len);

        ret_val = ES_SUCCESS;
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    BN_clear_free(v_bn);
    BN_clear_free(KSAK_bn);
    BN_clear_free(SSK_bn);
    BN_clear_free(SSK_check_bn);
    BN_clear_free(KPAKx_bn);
    BN_clear_free(KPAKy_bn);
    BN_clear_free(PVTx_bn);
    BN_clear_free(PVTy_bn);
    BN_clear_free(Gx_bn);
    BN_clear_free(Gy_bn);

    /* Points */
    EC_POINT_clear_free(PVT_point);
    EC_POINT_clear_free(KPAK_point);

    /* Strings */
    if (*v != NULL) {
        memset(*v, 0, *v_len);
        free(*v);
        *v = NULL;
    }
    if (hash_result != NULL) {
        memset(hash_result, 0, strlen(hash_result));
        free(hash_result);
        hash_result = NULL;
    }
    if (G != NULL) {
        memset(G, 0, G_len);
        free(G);
        G = NULL;
    }
    if (kpak != NULL) {
        memset(kpak, 0, kpak_len);
        free(kpak);
        kpak = NULL;
    }

    /* Context */
    if (bn_ctx != NULL) {
        BN_CTX_free(bn_ctx);
    }

    return ret_val;
} /* kms_createSSKPVTPairForUser */

/***************************************************************************//**
 * Creates RSK (Receiver Secret Key) for user. This is provided to clients but 
 * they MUST keep it secret.
 *
 * @param[in]  ms_param_set  Mikey-Sakke Paraneter Set (currently only one).
 * @param[in]  kms_id        String of the 'kms-id' used to create the 
 *                           'community' the 'user' is part of.
 * @param[in]  user_id       Octet string pointer of the 'user-id'. user-id is
 *                           comprised date|null|uri|null.
 * @param[in]  user_id_len   Length of 'user-id' octet stringi (as the id
 *                           contains a NULL).
 * @param[out] rsk           Octet string pointer of the 'rsk' (Receiver Secret
 *                           Key) result.
 *                           Key.
 * @param[out] rsk_len       Length of 'rsk' octet string.
 *
 * @return ES_SUCCESS, ES_FAILURE 
 *****************************************************************************/
uint8_t kms_createRSK(
    const uint8_t  ms_param_set,
    const char    *kms_id,
    const char    *user_id,
    const size_t   user_id_len,
    uint8_t      **rsk,
    size_t        *rsk_len) {

    short ret_val           = ES_FAILURE;
    short error_encountered = ES_FALSE;

    BIGNUM   *a_bn          = NULL;
    BIGNUM   *q_bn          = NULL;
    BIGNUM   *z_T_bn        = NULL;
    char     *z_T           = NULL;
    EC_GROUP *ms_curve      = NULL;
    EC_POINT *RSK           = NULL;
    BIGNUM   *RSK_x_bn      = NULL;
    BIGNUM   *RSK_y_bn      = NULL;

    /* printf("        ***%s:%s:%d \n", __FUNCTION__, 
     *        __FILE__, __LINE__);
     */

    BN_CTX *bn_ctx = BN_CTX_new();

    ES_DEBUG(KES_SECTION_NAME "    Create RSK");
    ES_DEBUG(KES_SECTION_NAME "    ==========");

    ES_DEBUG_PRINT_ID(KES_SECTION_NAME, "  user:", 12, user_id, user_id_len);

    /* Get KMS Master Secret z_T */
    z_T = kms_getzT(kms_id);
    if (!BN_hex2bn(&z_T_bn, z_T)) {
        ES_ERROR("%s:%s:%d - Creating RSK, could not retrieve 'z_T' value",
            __FILE__, __FUNCTION__, __LINE__);
        error_encountered = ES_TRUE;
    }
    else {
        ES_DEBUG_DISPLAY_BN(KES_SECTION_NAME, "z_T:", 12, z_T_bn);

        /* Create user 'a' (ID) as an integer. */
        a_bn = BN_bin2bn(user_id, user_id_len, NULL);
        q_bn = ms_getParameter_q(ms_param_set);

        if (q_bn == NULL) {
            ES_ERROR("%s:%s:%d - Creating RSK, could not retrieve 'q' value",
                __FILE__, __FUNCTION__, __LINE__);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG_DISPLAY_BN(KES_SECTION_NAME, "q: ", 12, q_bn);

            /*********************************************************************/
            /* Create RSK (Receiver Secret Key                                   */
            /*********************************************************************/
            /*!< RSK (K_(a,T) = [(a + z_T)^-1]P, where 'a' is interpreted as an 
             *   integer, and the inversion is performed modulo q.
             */
            BN_mod_add(a_bn /* user-id */, a_bn, 
                       z_T_bn/* Master Secret */, q_bn /* mod q */, bn_ctx);
            BN_mod_inverse(a_bn, a_bn, q_bn, bn_ctx);

            /*!< Copy P for RSK result, then multiply by result of [(a + z_T)^-1] 
             * above.
             */
            ms_curve = ms_getParameter_E(ms_param_set);
            RSK      = EC_POINT_dup(ms_getParameter_P(ms_param_set), ms_curve);

            int res = EC_POINT_mul(ms_curve, RSK, 0, RSK, a_bn, bn_ctx);

            /*ES_DEBUG_DISPLAY_AFFINE_COORDS(KES_SECTION_NAME,
             *   "        RSK (Receiver Secret Key for subscriber)", 
             *   12, ms_curve, RSK);
             */
            RSK_x_bn = BN_new();
            RSK_y_bn = BN_new();
            EC_POINT_get_affine_coordinates_GFp(ms_curve, 
                RSK, RSK_x_bn, RSK_y_bn, bn_ctx);
    
            *rsk_len = 257;
            *rsk     = calloc(1, *rsk_len);
            *rsk[0]  = 0x04;
            if (!BN_bn2bin(RSK_x_bn, *rsk + 1 + (128 - BN_num_bytes(RSK_x_bn)))) {
                ES_ERROR("%s'RSKx' length incorrect!", KES_SECTION_NAME);
            }
            else if (!BN_bn2bin(RSK_y_bn, *rsk + 129 + (128 - BN_num_bytes(RSK_y_bn)))) {
                ES_ERROR("%s'RSKy' length incorrect!", KES_SECTION_NAME);
            }
            else {
                ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(KES_SECTION_NAME, 
                    "RSK:", 12, *rsk, *rsk_len);
                ret_val = ES_SUCCESS;
            }
        }
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    /* BIGNUMs */
    BN_clear_free(a_bn);
    q_bn = NULL;
    BN_clear_free(z_T_bn);
    BN_clear_free(RSK_x_bn);
    BN_clear_free(RSK_y_bn);

    if (z_T != NULL) {
        memset(z_T, 0, strlen(z_T));
        free(z_T);
        z_T = NULL;
    }

    /* Curves */
    ms_curve = NULL;
    EC_POINT_free(RSK);

    /* Context */
    if (bn_ctx != NULL) {
        BN_CTX_free(bn_ctx);
    }

    return ret_val;
} /* kms_createRSK */

/***************************************************************************//**
 * Adds a 'user' to storage, firstly calculating the RSK and SSK/PVT pairing/
 * Key Material.
 *
 * @param[in]  user_id_date  String of the 'date' part of the 'user-id'.
 * @param[in]  user_id_uri   String of the 'uri' part of the 'user-id'.
 * @param[out] community     String pointer of the 'community' the 'user' will
 *                           be part of.
 * @param[in]  v             A random number for 'v' (used in calculations.
 *                           Note! This value will be cleared by this function
 *                           on exit as per RFC dewscription.
 * @param[in]  v_len         Length of 'v' octet string.
 *
 * @return ES_SUCCESS, ES_FAILURE or ES_V_FAILURE Note! The latter is returned
 * from the call to 'kms_createSSKPVTPairForUser, and informs the caller to 
 * try another value for 'v' as there was some problem with calculation, see  
 * RFC 6507 Section 5.1.1. point 5.
 *****************************************************************************/
uint8_t kms_addUser(
    const char  *user_id_date,
    const char  *user_id_uri,
    const char  *community,
    uint8_t    **v,
    size_t      *v_len) {

    short    ret_val      = ES_FAILURE;
    uint8_t  tmp_res      = ES_FAILURE;
    uint8_t *user_id      = NULL; /* date|null|id-uri */
    size_t   user_id_len  = 0;
    uint8_t *rsk          = NULL;
    size_t   rsk_len      = 0;
    uint8_t *ssk          = NULL;
    size_t   ssk_len      = 0;
    uint8_t *pvt          = NULL;
    size_t   pvt_len      = 0;
    uint8_t  kms_id[512];

    memset(kms_id, 0, sizeof(kms_id));

    /* Firstly, create the user_id (date|null|uri) in correct format. */
    user_id_len  = strlen(user_id_date) + strlen(user_id_uri) + 2;
    user_id      = calloc(1, user_id_len);
    strcpy((char *)user_id, user_id_date);
    strcpy((char *)user_id+strlen((char *)user_id)+1, user_id_uri);
    ES_DEBUG_PRINT_ID(KES_SECTION_NAME, "  user:", 12, user_id, user_id_len);

    /* Next, in order to create the RSK (Receiver Secret Key) we need to
     * know the KMS details. we can get these from the selected community
     * for the user. Note! You may chose to bind 'KMS' and 'Community' data,
     * but, in my example, they are separate so that one KMS could 'manage'
     * several 'Communities'.
     *
     * The way I have implemented this is as follows:
     *
     * Each 'community' file has a name and (rather unsurpringly) the name
     * of the community represented. Inside the 'community' file there 
     * is an attribute 'KmsUri', which is the URI of the KMS used in the
     * creation of the community date. The data related to this KMS can be
     * found under storage/kms, but note! 'z_T' and 'KSAK MUST be kept 
     * secret/ NEVER passed to the client.
     *
     * Now, you may chose to make the 'community' and 'kms' the same name,
     * iif you want to manage one community, but you don't have to if you 
     * want to manage more than one, but retain the same (core) key (KMS)
     * material for all of these communitites.
     */

    /* Look up KMS id from community data. */
    msdb_communityGetKmsUri(community, &kms_id);

    /* Create RSK */
    if (kms_createRSK(1,          /* Mikey-Sakke parameter set to use.      */
            (char *)&kms_id,      /* The KMS we're going to use values from.*/
            user_id, user_id_len, /* User-ID.    */
            &rsk, &rsk_len)) {    /* RSK result. */
         ES_ERROR("%s  Failed to create RSK for <%s.%s> using KMS details <%s>!",
                  KES_SECTION_NAME, user_id_date, user_id_uri, kms_id);
    }
    else { /* Calculate SSK/ PVT pairing */
        tmp_res = kms_createSSKPVTPairForUser(
                     community,
                     user_id, user_id_len,
                     &ssk,    &ssk_len,
                     &pvt,    &pvt_len,
                     v,       v_len);
        if (tmp_res == ES_FAILURE) {
             ES_ERROR("%s  Failed to create SSK/ PVT pair for <%s.%s> using KMS details <%s>!",
                      KES_SECTION_NAME, user_id_date, user_id_uri, kms_id);
        }
        else {
            if (tmp_res == KMS_V_FAILURE) {
                 ES_ERROR("%s  Failed to create SSK/ PVT pair 'v' failed. Try another!",
                          KES_SECTION_NAME);
                 ret_val = tmp_res;
            }
            else {
                if (user_store( /* Add User */
                    user_id_date, user_id_uri,
                    community,
                    ssk,          ssk_len,
                    rsk,          rsk_len,
                    pvt,          pvt_len)) {
                    ES_ERROR("%s  Failed to create User <%s.%s>!",
                             KES_SECTION_NAME, user_id_date, user_id_uri);
                }
                else {
                    ret_val = ES_SUCCESS;
                }
            }
        }
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    if (user_id != NULL) {
        memset(user_id, 0, user_id_len);
        free(user_id);
        user_id_len = 0;
    }
    if (rsk     != NULL) {
        memset(rsk, 0, rsk_len);
        free(rsk);
        rsk_len     = 0;
    }
    if (ssk     != NULL) {;
        memset(ssk, 0, ssk_len);
        free(ssk);
        ssk_len     = 0;
    }
    if (pvt     != NULL) {
        memset(pvt, 0, pvt_len);
        free(pvt);
        pvt_len     = 0;
    }
    memset(kms_id, 0, sizeof(kms_id));

    return ret_val;
} /* kms_addUser */

/***************************************************************************//**
 * Lists the contents of the 'community' and 'user' files that need to be sent
 * to the client device in order that it can use Mikey-Sakke.
 * 
 * These data could be sent using Secure Chorus defined protocols, or something
 * else entirely, it's up to you (as long as it's secure!). For testing, you
 * may even decide to copy the 'community' and 'user' files to the client/ demo
 * code for it to use.
 *
 * @param[in]  user_date  String of the 'date' part of the 'user-id'.
 * @param[in]  user_uri   String of the 'uri' part of the 'user-id'.
 * @param[in]  community  String pointer of the 'community' the 'user' is
 *                        part of.
 *****************************************************************************/
void kms_listDetailsToSendToClient(
    char   *user_date,
    char   *user_uri,
    char   *community) {

    char   *user_id     = NULL;
    size_t  user_id_len = 0;

    /* Create the user_id (date|null|uri) in correct format. */
    user_id_len  = strlen(user_date) + strlen(user_uri) + 2;
    user_id      = calloc(1, user_id_len);
    strcpy((char *)user_id, user_date);
    strcpy((char *)user_id+strlen((char *)user_id)+1, user_uri);
    /* ES_DEBUG_PRINT_ID(KES_SECTION_NAME, "  user:", 12, 
     * user_id, user_id_len);
     */

    community_outputKMSCertificate(community);
    user_outputParameterSet(user_id, user_id_len, community);

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    if (user_id != NULL) {
        memset(user_id, 0, user_id_len);
        free(user_id);
        user_id_len = 0;
    }

} /* kms_listDetailsToSendToClient */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
