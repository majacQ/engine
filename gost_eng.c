/**********************************************************************
 *                          gost_eng.c                                *
 *              Main file of GOST engine                              *
 *                                                                    *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *             Copyright (c) 2020 Chikunov Vitaly <vt@altlinux.org>   *
 *                                                                    *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 **********************************************************************/
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include "e_gost_err.h"
#include "gost_lcl.h"
#include "gost-engine.h"

#include "gost_grasshopper_cipher.h"

static const char* engine_gost_id = "gost";

static const char* engine_gost_name =
        "Reference implementation of GOST engine";

const ENGINE_CMD_DEFN gost_cmds[] = {
    {GOST_CTRL_CRYPT_PARAMS,
     "CRYPT_PARAMS",
     "OID of default GOST 28147-89 parameters",
     ENGINE_CMD_FLAG_STRING},
    {GOST_CTRL_PBE_PARAMS,
     "PBE_PARAMS",
     "Shortname of default digest alg for PBE",
     ENGINE_CMD_FLAG_STRING},
    {GOST_CTRL_PK_FORMAT,
     "GOST_PK_FORMAT",
     "Private key format params",
     ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

/* Symmetric cipher and digest function registrar */

static int gost_ciphers(ENGINE* e, const EVP_CIPHER** cipher,
                        const int** nids, int nid);

static int gost_digests(ENGINE* e, const EVP_MD** digest,
                        const int** nids, int nid);

static int gost_pkey_meths(ENGINE* e, EVP_PKEY_METHOD** pmeth,
                           const int** nids, int nid);

static int gost_pkey_asn1_meths(ENGINE* e, EVP_PKEY_ASN1_METHOD** ameth,
                                const int** nids, int nid);

  <<<<<<< magma_impl
static int gost_cipher_nids[] = {
        NID_id_Gost28147_89,
        NID_gost89_cnt,
        NID_gost89_cnt_12,
        NID_gost89_cbc,
        NID_grasshopper_ecb,
        NID_grasshopper_cbc,
        NID_grasshopper_cfb,
        NID_grasshopper_ofb,
        NID_grasshopper_ctr,
        NID_magma_cbc,
        NID_magma_ctr,
        NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm,
        0
  =======
static EVP_PKEY_METHOD* pmeth_GostR3410_2001 = NULL,
        * pmeth_GostR3410_2001DH = NULL,
        * pmeth_GostR3410_2012_256 = NULL,
        * pmeth_GostR3410_2012_512 = NULL,
        * pmeth_Gost28147_MAC = NULL, * pmeth_Gost28147_MAC_12 = NULL,
        * pmeth_magma_mac = NULL,  * pmeth_grasshopper_mac = NULL,
        * pmeth_magma_mac_acpkm = NULL,  * pmeth_grasshopper_mac_acpkm = NULL;

static EVP_PKEY_ASN1_METHOD* ameth_GostR3410_2001 = NULL,
        * ameth_GostR3410_2001DH = NULL,
        * ameth_GostR3410_2012_256 = NULL,
        * ameth_GostR3410_2012_512 = NULL,
        * ameth_Gost28147_MAC = NULL, * ameth_Gost28147_MAC_12 = NULL,
        * ameth_magma_mac = NULL,  * ameth_grasshopper_mac = NULL,
        * ameth_magma_mac_acpkm = NULL,  * ameth_grasshopper_mac_acpkm = NULL;

GOST_digest *gost_digest_array[] = {
    &GostR3411_94_digest,
    &Gost28147_89_MAC_digest,
    &GostR3411_2012_256_digest,
    &GostR3411_2012_512_digest,
    &Gost28147_89_mac_12_digest,
    &magma_mac_digest,
    &grasshopper_mac_digest,
    &kuznyechik_ctracpkm_omac_digest,
  >>>>>>> master
};

GOST_cipher *gost_cipher_array[] = {
    &Gost28147_89_cipher,
    &Gost28147_89_cnt_cipher,
    &Gost28147_89_cnt_12_cipher,
    &Gost28147_89_cbc_cipher,
    &grasshopper_ecb_cipher,
    &grasshopper_cbc_cipher,
    &grasshopper_cfb_cipher,
    &grasshopper_ofb_cipher,
    &grasshopper_ctr_cipher,
    &magma_cbc_cipher,
    &magma_ctr_cipher,
    &magma_ctr_acpkm_cipher,
    &magma_ctr_acpkm_omac_cipher,
    &grasshopper_ctr_acpkm_cipher,
    &grasshopper_ctr_acpkm_omac_cipher,
    &magma_kexp15_cipher,
    &kuznyechik_kexp15_cipher,
};

static struct gost_meth_minfo {
    int nid;
    EVP_PKEY_METHOD **pmeth;
    EVP_PKEY_ASN1_METHOD **ameth;
    const char *pemstr;
    const char *info;
} gost_meth_array[] = {
    {
        NID_id_GostR3410_2001,
        &pmeth_GostR3410_2001,
        &ameth_GostR3410_2001,
        "GOST2001",
        "GOST R 34.10-2001",
    },
    {
        NID_id_GostR3410_2001DH,
        &pmeth_GostR3410_2001DH,
        &ameth_GostR3410_2001DH,
        "GOST2001 DH",
        "GOST R 34.10-2001 DH",
    },
    {
        NID_id_Gost28147_89_MAC,
        &pmeth_Gost28147_MAC,
        &ameth_Gost28147_MAC,
        "GOST-MAC",
        "GOST 28147-89 MAC",
    },
    {
        NID_id_GostR3410_2012_256,
        &pmeth_GostR3410_2012_256,
        &ameth_GostR3410_2012_256,
        "GOST2012_256",
        "GOST R 34.10-2012 with 256 bit key",
    },
    {
        NID_id_GostR3410_2012_512,
        &pmeth_GostR3410_2012_512,
        &ameth_GostR3410_2012_512,
        "GOST2012_512",
        "GOST R 34.10-2012 with 512 bit key",
    },
    {
        NID_gost_mac_12,
        &pmeth_Gost28147_MAC_12,
        &ameth_Gost28147_MAC_12,
        "GOST-MAC-12",
        "GOST 28147-89 MAC with 2012 params",
    },
    {
        NID_magma_mac,
        &pmeth_magma_mac,
        &ameth_magma_mac,
        "MAGMA-MAC",
        "GOST R 34.13-2015 Magma MAC",
    },
    {
        NID_grasshopper_mac,
        &pmeth_grasshopper_mac,
        &ameth_grasshopper_mac,
        "KUZNYECHIK-MAC",
        "GOST R 34.13-2015 Grasshopper MAC",
    },
    {
        NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac,
        &pmeth_magma_mac_acpkm,
        &ameth_magma_mac_acpkm,
        "ID-TC26-CIPHER-GOSTR3412-2015-MAGMA-CTRACPKM-OMAC",
        "GOST R 34.13-2015 Magma MAC ACPKM",
    },
    {
        NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac,
        &pmeth_grasshopper_mac_acpkm,
        &ameth_grasshopper_mac_acpkm,
        "ID-TC26-CIPHER-GOSTR3412-2015-KUZNYECHIK-CTRACPKM-OMAC",
        "GOST R 34.13-2015 Grasshopper MAC ACPKM",
    },
    { 0 },
};

#ifndef OSSL_NELEM
# define OSSL_NELEM(x) (sizeof(x)/sizeof((x)[0]))
#endif

static int known_digest_nids[OSSL_NELEM(gost_digest_array)];
static int known_cipher_nids[OSSL_NELEM(gost_cipher_array)];
/* `- 1' because of terminating zero element */
static int known_meths_nids[OSSL_NELEM(gost_meth_array) - 1];

/* ENGINE_DIGESTS_PTR callback installed by ENGINE_set_digests */
static int gost_digests(ENGINE *e, const EVP_MD **digest,
                        const int **nids, int nid)
{
    int i;

    if (!digest) {
        int *n = known_digest_nids;

        *nids = n;
        for (i = 0; i < OSSL_NELEM(gost_digest_array); i++)
            *n++ = gost_digest_array[i]->nid;
        return i;
    }

    for (i = 0; i < OSSL_NELEM(gost_digest_array); i++)
        if (nid == gost_digest_array[i]->nid) {
            *digest = GOST_init_digest(gost_digest_array[i]);
            return 1;
        }
    *digest = NULL;
    return 0;
}

/* ENGINE_CIPHERS_PTR callback installed by ENGINE_set_ciphers */
static int gost_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                        const int **nids, int nid)
{
    int i;

    if (!cipher) {
        int *n = known_cipher_nids;

        *nids = n;
        for (i = 0; i < OSSL_NELEM(gost_cipher_array); i++)
            *n++ = gost_cipher_array[i]->nid;
        return i;
    }

    for (i = 0; i < OSSL_NELEM(gost_cipher_array); i++)
        if (nid == gost_cipher_array[i]->nid) {
            *cipher = GOST_init_cipher(gost_cipher_array[i]);
            return 1;
        }
    *cipher = NULL;
    return 0;
}

static int gost_meth_nids(const int **nids)
{
    struct gost_meth_minfo *info = gost_meth_array;
    int *n = known_meths_nids;

    *nids = n;
    for (; info->nid; info++)
        *n++ = info->nid;
    return OSSL_NELEM(known_meths_nids);
}

/* ENGINE_PKEY_METHS_PTR installed by ENGINE_set_pkey_meths */
static int gost_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid)
{
    struct gost_meth_minfo *info;

    if (!pmeth)
        return gost_meth_nids(nids);

    for (info = gost_meth_array; info->nid; info++)
        if (nid == info->nid) {
            *pmeth = *info->pmeth;
            return 1;
        }
    *pmeth = NULL;
    return 0;
}

/* ENGINE_PKEY_ASN1_METHS_PTR installed by ENGINE_set_pkey_asn1_meths */
static int gost_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
                                const int **nids, int nid)
{
    struct gost_meth_minfo *info;

    if (!ameth)
        return gost_meth_nids(nids);

    for (info = gost_meth_array; info->nid; info++)
        if (nid == info->nid) {
            *ameth = *info->ameth;
            return 1;
        }
    *ameth = NULL;
    return 0;
}

static int gost_engine_init(ENGINE* e) {
    return 1;
}

static int gost_engine_finish(ENGINE* e) {
    return 1;
}

static int gost_engine_destroy(ENGINE* e) {
  <<<<<<< magma_impl
  =======
  <<<<<<< openssl_1_1_0_release1
    EVP_delete_digest_alias("streebog256");
    EVP_delete_digest_alias("streebog512");
  >>>>>>> master
    digest_gost_destroy();
    digest_gost2012_256_destroy();
    digest_gost2012_512_destroy();

    imit_gost_cpa_destroy();
    imit_gost_cp_12_destroy();
  <<<<<<< magma_impl
    magma_omac_destroy();
    grasshopper_omac_destroy();
    grasshopper_omac_acpkm_destroy();

    cipher_gost_destroy();
    cipher_gost_grasshopper_destroy();

    gost_param_free();

    pmeth_GostR3410_2001 = NULL;
    pmeth_Gost28147_MAC = NULL;
    pmeth_GostR3410_2012_256 = NULL;
    pmeth_GostR3410_2012_512 = NULL;
    pmeth_Gost28147_MAC_12 = NULL;
    pmeth_magma_mac = NULL;
    pmeth_grasshopper_mac = NULL;

    ameth_GostR3410_2001 = NULL;
    ameth_Gost28147_MAC = NULL;
    ameth_GostR3410_2012_256 = NULL;
    ameth_GostR3410_2012_512 = NULL;
    ameth_Gost28147_MAC_12 = NULL;
    ameth_magma_mac = NULL;
    ameth_grasshopper_mac = NULL;

	ERR_unload_GOST_strings();
	
  =======

    cipher_gost_destroy();
    cipher_gost_grasshopper_destroy();
  =======
    int i;

    for (i = 0; i < OSSL_NELEM(gost_digest_array); i++)
        GOST_deinit_digest(gost_digest_array[i]);
    for (i = 0; i < OSSL_NELEM(gost_cipher_array); i++)
        GOST_deinit_cipher(gost_cipher_array[i]);
  >>>>>>> master

    gost_param_free();

    struct gost_meth_minfo *minfo = gost_meth_array;
    for (; minfo->nid; minfo++) {
        *minfo->pmeth = NULL;
        *minfo->ameth = NULL;
    }

    ERR_unload_GOST_strings();

  >>>>>>> master
    return 1;
}

/*
 * Following is the glue that populates the ENGINE structure and that
 * binds it to OpenSSL libraries
 */

static int populate_gost_engine(ENGINE* e) {
    int ret = 0;

    if (e == NULL)
        goto end;
    if (!ENGINE_set_id(e, engine_gost_id)) {
        printf("ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_gost_name)) {
        printf("ENGINE_set_name failed\n");
        goto end;
    }
    if (!ENGINE_set_digests(e, gost_digests)) {
        printf("ENGINE_set_digests failed\n");
        goto end;
    }
    if (!ENGINE_set_ciphers(e, gost_ciphers)) {
        printf("ENGINE_set_ciphers failed\n");
        goto end;
    }
    if (!ENGINE_set_pkey_meths(e, gost_pkey_meths)) {
        printf("ENGINE_set_pkey_meths failed\n");
        goto end;
    }
    if (!ENGINE_set_pkey_asn1_meths(e, gost_pkey_asn1_meths)) {
        printf("ENGINE_set_pkey_asn1_meths failed\n");
        goto end;
    }
    /* Control function and commands */
    if (!ENGINE_set_cmd_defns(e, gost_cmds)) {
        fprintf(stderr, "ENGINE_set_cmd_defns failed\n");
        goto end;
    }
    if (!ENGINE_set_ctrl_function(e, gost_control_func)) {
        fprintf(stderr, "ENGINE_set_ctrl_func failed\n");
        goto end;
    }
    if (!ENGINE_set_destroy_function(e, gost_engine_destroy)
        || !ENGINE_set_init_function(e, gost_engine_init)
        || !ENGINE_set_finish_function(e, gost_engine_finish)) {
        goto end;
    }

  <<<<<<< magma_impl
    if (!register_ameth_gost
            (NID_id_GostR3410_2001, &ameth_GostR3410_2001, "GOST2001",
             "GOST R 34.10-2001"))
        goto end;
    if (!register_ameth_gost
            (NID_id_GostR3410_2012_256, &ameth_GostR3410_2012_256, "GOST2012_256",
             "GOST R 34.10-2012 with 256 bit key"))
        goto end;
    if (!register_ameth_gost
            (NID_id_GostR3410_2012_512, &ameth_GostR3410_2012_512, "GOST2012_512",
             "GOST R 34.10-2012 with 512 bit key"))
        goto end;
    if (!register_ameth_gost(NID_id_Gost28147_89_MAC, &ameth_Gost28147_MAC,
                             "GOST-MAC", "GOST 28147-89 MAC"))
        goto end;
    if (!register_ameth_gost(NID_gost_mac_12, &ameth_Gost28147_MAC_12,
                             "GOST-MAC-12",
                             "GOST 28147-89 MAC with 2012 params"))
        goto end;
    if (!register_ameth_gost(NID_magma_mac, &ameth_magma_mac,
                             "MAGMA-MAC", "GOST R 34.13-2015 Magma MAC"))
        goto end;
    if (!register_ameth_gost(NID_grasshopper_mac, &ameth_grasshopper_mac,
                             "GRASSHOPPER-MAC", "GOST R 34.13-2015 Grasshopper MAC"))
        goto end;

    if (!register_pmeth_gost(NID_id_GostR3410_2001, &pmeth_GostR3410_2001, 0))
        goto end;

    if (!register_pmeth_gost
            (NID_id_GostR3410_2012_256, &pmeth_GostR3410_2012_256, 0))
        goto end;
    if (!register_pmeth_gost
            (NID_id_GostR3410_2012_512, &pmeth_GostR3410_2012_512, 0))
        goto end;
    if (!register_pmeth_gost
            (NID_id_Gost28147_89_MAC, &pmeth_Gost28147_MAC, 0))
        goto end;
    if (!register_pmeth_gost(NID_gost_mac_12, &pmeth_Gost28147_MAC_12, 0))
        goto end;
    if (!register_pmeth_gost(NID_magma_mac, &pmeth_magma_mac, 0))
        goto end;
    if (!register_pmeth_gost(NID_grasshopper_mac, &pmeth_grasshopper_mac, 0))
        goto end;
    if (!ENGINE_register_ciphers(e)
        || !ENGINE_register_digests(e)
        || !ENGINE_register_pkey_meths(e)
        /* These two actually should go in LIST_ADD command */
        || !EVP_add_cipher(cipher_gost())
        || !EVP_add_cipher(cipher_gost_cbc())
        || !EVP_add_cipher(cipher_gost_cpacnt())
        || !EVP_add_cipher(cipher_gost_cpcnt_12())
        || !EVP_add_cipher(cipher_gost_grasshopper_ecb())
        || !EVP_add_cipher(cipher_gost_grasshopper_cbc())
        || !EVP_add_cipher(cipher_gost_grasshopper_cfb())
        || !EVP_add_cipher(cipher_gost_grasshopper_ofb())
        || !EVP_add_cipher(cipher_gost_grasshopper_ctr())
        || !EVP_add_cipher(cipher_gost_grasshopper_ctracpkm())
        || !EVP_add_cipher(cipher_magma_cbc())
        || !EVP_add_cipher(cipher_magma_ctr())
        || !EVP_add_digest(digest_gost())
        || !EVP_add_digest(digest_gost2012_512())
        || !EVP_add_digest(digest_gost2012_256())
        || !EVP_add_digest(imit_gost_cpa())
        || !EVP_add_digest(imit_gost_cp_12())
        || !EVP_add_digest(magma_omac())
        || !EVP_add_digest(grasshopper_omac())
            ) {
        goto end;
  =======
    /*
     * "register" in "register_ameth_gost" and "register_pmeth_gost" is
     * not registering in an ENGINE sense, where things are hooked into
     * OpenSSL's library.  "register_ameth_gost" and "register_pmeth_gost"
     * merely allocate and populate the method structures of this engine.
     */
    struct gost_meth_minfo *minfo = gost_meth_array;
    for (; minfo->nid; minfo++) {

        /* This skip looks temporary. */
        if (minfo->nid == NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac)
            continue;

        if (!register_ameth_gost(minfo->nid, minfo->ameth, minfo->pemstr,
                minfo->info))
            goto end;
        if (!register_pmeth_gost(minfo->nid, minfo->pmeth, 0))
            goto end;
  >>>>>>> master
    }

    ret = 1;
  end:
    return ret;
}

static int bind_gost_engine(ENGINE* e) {
    int ret = 0;

  <<<<<<< magma_impl
static int gost_digests(ENGINE* e, const EVP_MD** digest,
                        const int** nids, int nid) {
    int ok = 1;
    if (digest == NULL) {
        return gost_digest_nids(nids);
    }
    if (nid == NID_id_GostR3411_94) {
        *digest = digest_gost();
    } else if (nid == NID_id_Gost28147_89_MAC) {
        *digest = imit_gost_cpa();
    } else if (nid == NID_id_GostR3411_2012_256) {
        *digest = digest_gost2012_256();
    } else if (nid == NID_id_GostR3411_2012_512) {
        *digest = digest_gost2012_512();
    } else if (nid == NID_gost_mac_12) {
        *digest = imit_gost_cp_12();
    } else if (nid == NID_magma_mac) {
        *digest = magma_omac();
    } else if (nid == NID_grasshopper_mac) {
        *digest = grasshopper_omac();
    } else if (nid == NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac) {
        *digest = grasshopper_omac_acpkm();
    } else {
        ok = 0;
        *digest = NULL;
    }
    return ok;
}
  =======
    if (!ENGINE_register_ciphers(e)
        || !ENGINE_register_digests(e)
        || !ENGINE_register_pkey_meths(e))
        goto end;
  >>>>>>> master

    int i;
    for (i = 0; i < OSSL_NELEM(gost_cipher_array); i++) {
        if (!EVP_add_cipher(GOST_init_cipher(gost_cipher_array[i])))
            goto end;
    }

  <<<<<<< magma_impl
    if (nid == NID_id_Gost28147_89) {
        *cipher = cipher_gost();
    } else if (nid == NID_gost89_cnt) {
        *cipher = cipher_gost_cpacnt();
    } else if (nid == NID_gost89_cnt_12) {
        *cipher = cipher_gost_cpcnt_12();
    } else if (nid == NID_gost89_cbc) {
        *cipher = cipher_gost_cbc();
    } else if (nid == NID_grasshopper_ecb) {
        *cipher = cipher_gost_grasshopper_ecb();
    } else if (nid == NID_grasshopper_cbc) {
        *cipher = cipher_gost_grasshopper_cbc();
    } else if (nid == NID_grasshopper_cfb) {
        *cipher = cipher_gost_grasshopper_cfb();
    } else if (nid == NID_grasshopper_ofb) {
        *cipher = cipher_gost_grasshopper_ofb();
    } else if (nid == NID_grasshopper_ctr) {
        *cipher = cipher_gost_grasshopper_ctr();
    } else if (nid == NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm) {
        *cipher = cipher_gost_grasshopper_ctracpkm();
    } else if (nid == NID_magma_cbc) {
        *cipher = cipher_magma_cbc();
    } else if (nid == NID_magma_ctr) {
        *cipher = cipher_magma_ctr();
    } else {
        ok = 0;
        *cipher = NULL;
  =======
    for (i = 0; i < OSSL_NELEM(gost_digest_array); i++) {
        if (!EVP_add_digest(GOST_init_digest(gost_digest_array[i])))
            goto end;
  >>>>>>> master
    }

    if(!EVP_add_digest_alias(SN_id_GostR3411_2012_256, "streebog256")
       ||	!EVP_add_digest_alias(SN_id_GostR3411_2012_512, "streebog512")) {
        goto end;
    }

    ENGINE_register_all_complete();

    ERR_load_GOST_strings();
    ret = 1;
  end:
    return ret;
}

static int check_gost_engine(ENGINE* e, const char* id)
{
    if (id != NULL && strcmp(id, engine_gost_id) != 0)
        return 0;
    if (ameth_GostR3410_2001) {
        printf("GOST engine already loaded\n");
        return 0;
    }
    return 1;
}

static int make_gost_engine(ENGINE* e, const char* id)
{
    return check_gost_engine(e, id)
        && populate_gost_engine(e)
        && bind_gost_engine(e);
}

#ifndef BUILDING_ENGINE_AS_LIBRARY

/*
 * When building gost-engine as a dynamically loadable module, these two
 * lines do everything that's needed, and OpenSSL's libcrypto will be able
 * to call its entry points, v_check and bind_engine.
 */

IMPLEMENT_DYNAMIC_BIND_FN(make_gost_engine)
IMPLEMENT_DYNAMIC_CHECK_FN()

#else

/*
 * When building gost-engine as a shared library, the application that uses
 * it must manually call ENGINE_load_gost() for it to bind itself into the
 * libcrypto libraries.
 */

void ENGINE_load_gost(void) {
    ENGINE* toadd;
    int ret = 0;

    if ((toadd = ENGINE_new()) != NULL
        && (ret = make_gost_engine(toadd, engine_gost_id)) > 0)
        ENGINE_add(toadd);
    ENGINE_free(toadd);
    if (ret > 0)
        ERR_clear_error();
}

#endif
/* vim: set expandtab cinoptions=\:0,l1,t0,g0,(0 sw=4 : */
