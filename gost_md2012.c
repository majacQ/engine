  <<<<<<< gost_provider
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/params.h>
  =======
/**********************************************************************
 *                          gost_md2012.c                             *
 *             Copyright (c) 2013 Cryptocom LTD.                      *
 *             Copyright (c) 2020 Vitaly Chikunov <vt@altlinux.org>   *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *          GOST R 34.11-2012 interface to OpenSSL engine.            *
 *                                                                    *
 * Author: Alexey Degtyarev <alexey@renatasystems.org>                *
 *                                                                    *
 **********************************************************************/

#include "compat.h"
#include <openssl/evp.h>
#include "gosthash2012.h"
#include "gost_lcl.h"
  >>>>>>> master

#include "gost_prov.h"
#include "gosthash2012.h"

const char micalg_256[] = "gostr3411-2012-256";
const char micalg_512[] = "gostr3411-2012-512";

  <<<<<<< gost_provider
/* Context management */
static void *STREEBOG256_newctx(void *provctx);
static void STREEBOG_freectx(void *dctx);
static void *STREEBOG_dupctx(void *dctx);

/* Digest generation */
static int STREEBOG256_digest_init(void *dctx);
static int STREEBOG_digest_update(void *dctx, const unsigned char *in, size_t inl);
static int STREEBOG_digest_final(void *dctx, unsigned char *out, size_t *outl,
                    size_t outsz);
  =======
  <<<<<<< magma_impl
static EVP_MD *_hidden_GostR3411_2012_256_md = NULL;
static EVP_MD *_hidden_GostR3411_2012_512_md = NULL;

EVP_MD *digest_gost2012_256(void)
{
    if (_hidden_GostR3411_2012_256_md == NULL) {
        EVP_MD *md;

        if ((md =
             EVP_MD_meth_new(NID_id_GostR3411_2012_256, NID_undef)) == NULL
#if (OPENSSL_VERSION_NUMBER <= 0x10002100L)
	    || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_PKEY_METHOD_SIGNATURE)
#endif
            || !EVP_MD_meth_set_result_size(md, 32)
            || !EVP_MD_meth_set_input_blocksize(md, 64)
            || !EVP_MD_meth_set_app_datasize(md, sizeof(gost2012_hash_ctx))
            || !EVP_MD_meth_set_init(md, gost_digest_init256)
            || !EVP_MD_meth_set_update(md, gost_digest_update)
            || !EVP_MD_meth_set_final(md, gost_digest_final)
            || !EVP_MD_meth_set_copy(md, gost_digest_copy)
            || !EVP_MD_meth_set_ctrl(md, gost_digest_ctrl_256)
            || !EVP_MD_meth_set_cleanup(md, gost_digest_cleanup)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_GostR3411_2012_256_md = md;
    }
    return _hidden_GostR3411_2012_256_md;
}
  >>>>>>> master

/* Digest parameter descriptors */
static const OSSL_PARAM *STREEBOG_gettable_params(void);
static int STREEBOG256_digest_get_params(OSSL_PARAM params[]);

  <<<<<<< gost_provider
OSSL_DISPATCH streebog256_funcs[] = {
	{ OSSL_FUNC_DIGEST_NEWCTX, (funcptr_t)STREEBOG256_newctx },
	{ OSSL_FUNC_DIGEST_FREECTX, (funcptr_t)STREEBOG_freectx },
	{ OSSL_FUNC_DIGEST_DUPCTX, (funcptr_t)STREEBOG_dupctx },

	{ OSSL_FUNC_DIGEST_INIT, (funcptr_t)STREEBOG256_digest_init },
	{ OSSL_FUNC_DIGEST_UPDATE, (funcptr_t)STREEBOG_digest_update },
	{ OSSL_FUNC_DIGEST_FINAL, (funcptr_t)STREEBOG_digest_final },

	{ OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)STREEBOG_gettable_params },
	{ OSSL_FUNC_DIGEST_GET_PARAMS, (funcptr_t)STREEBOG256_digest_get_params },

	{ 0, NULL },
};
=======
EVP_MD *digest_gost2012_512(void)
{
    if (_hidden_GostR3411_2012_512_md == NULL) {
        EVP_MD *md;

        if ((md =
             EVP_MD_meth_new(NID_id_GostR3411_2012_512, NID_undef)) == NULL
#if (OPENSSL_VERSION_NUMBER <= 0x10002100L)
	    || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_PKEY_METHOD_SIGNATURE)
#endif
            || !EVP_MD_meth_set_result_size(md, 64)
            || !EVP_MD_meth_set_input_blocksize(md, 64)
            || !EVP_MD_meth_set_app_datasize(md, sizeof(gost2012_hash_ctx))
            || !EVP_MD_meth_set_init(md, gost_digest_init512)
            || !EVP_MD_meth_set_update(md, gost_digest_update)
            || !EVP_MD_meth_set_final(md, gost_digest_final)
            || !EVP_MD_meth_set_copy(md, gost_digest_copy)
            || !EVP_MD_meth_set_ctrl(md, gost_digest_ctrl_512)
            || !EVP_MD_meth_set_cleanup(md, gost_digest_cleanup)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_GostR3411_2012_512_md = md;
    }
    return _hidden_GostR3411_2012_512_md;
}

void digest_gost2012_512_destroy(void)
{
    EVP_MD_meth_free(_hidden_GostR3411_2012_512_md);
    _hidden_GostR3411_2012_512_md = NULL;
}
  =======
GOST_digest GostR3411_2012_template_digest = {
    .input_blocksize = 64,
    .app_datasize = sizeof(gost2012_hash_ctx),
    .update = gost_digest_update,
    .final = gost_digest_final,
    .copy = gost_digest_copy,
    .cleanup = gost_digest_cleanup,
};

GOST_digest GostR3411_2012_256_digest = {
    .nid = NID_id_GostR3411_2012_256,
    .alias = "streebog256",
    .template = &GostR3411_2012_template_digest,
    .result_size = 32,
    .init = gost_digest_init256,
    .ctrl = gost_digest_ctrl_256,
};

GOST_digest GostR3411_2012_512_digest = {
    .nid = NID_id_GostR3411_2012_512,
    .alias = "streebog512",
    .template = &GostR3411_2012_template_digest,
    .result_size = 64,
    .init = gost_digest_init512,
    .ctrl = gost_digest_ctrl_512,
};
  >>>>>>> master
  >>>>>>> master

static void *STREEBOG256_newctx(void *provctx)
{
	gost2012_hash_ctx *pctx = OPENSSL_zalloc(sizeof(gost2012_hash_ctx));
	return pctx;
}

static void STREEBOG_freectx(void *dctx)
{
	OPENSSL_free(dctx);
}

static void *STREEBOG_dupctx(void *dctx) 
{
	gost2012_hash_ctx *pctx = OPENSSL_zalloc(sizeof(gost2012_hash_ctx));
	if (pctx == NULL)
		return NULL;
	
	if (pctx)
		memcpy(pctx, dctx, sizeof(gost2012_hash_ctx));
	
	return pctx;
}

static int STREEBOG256_digest_init(void *dctx)
{
	init_gost2012_hash_ctx((gost2012_hash_ctx *)dctx, 256);
	return 1;
}

static int STREEBOG_digest_update(void *dctx, const unsigned char *in, size_t inl)
{
    gost2012_hash_block((gost2012_hash_ctx *)dctx, in, inl);
    return 1;
}

static int STREEBOG_digest_final(void *dctx, unsigned char *out, size_t *outl,
                    size_t outsz)
{
	gost2012_hash_ctx *pctx = (gost2012_hash_ctx *)dctx;

	if (pctx->digest_size/8 > outsz)
		return 0;

	gost2012_finish_hash(pctx, out);
	*outl = pctx->digest_size/8;
	return 1;
}

static const OSSL_PARAM *STREEBOG_gettable_params(void)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t("blocksize", NULL),
        OSSL_PARAM_size_t("size", NULL),
  /*      OSSL_PARAM_utf8_ptr("micalg", NULL, strlen(micalg_256)+1), */
        OSSL_PARAM_END
    };

    return table;
}

static int STREEBOG256_digest_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, "blocksize")) != NULL)
        if (!OSSL_PARAM_set_size_t(p, 64))
            return 0;
    if ((p = OSSL_PARAM_locate(params, "size")) != NULL)
        if (!OSSL_PARAM_set_size_t(p, 32))
            return 0;
/*    if ((p = OSSL_PARAM_locate(params, "micalg")) != NULL)
        if (!OSSL_PARAM_set_utf8_ptr(p, micalg_256))
            return 0; */
    return 1;
}
