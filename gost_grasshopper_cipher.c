/*
 * Maxim Tishkov 2016
 * Copyright (c) 2020 Vitaly Chikunov <vt@altlinux.org>
 * This file is distributed under the same license as OpenSSL
 */

#include "gost_grasshopper_cipher.h"
#include "gost_grasshopper_defines.h"
#include "gost_grasshopper_math.h"
#include "gost_grasshopper_core.h"
#include "gost_gost2015.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

#include "gost_lcl.h"
#include "e_gost_err.h"

enum GRASSHOPPER_CIPHER_TYPE {
    GRASSHOPPER_CIPHER_ECB = 0,
    GRASSHOPPER_CIPHER_CBC,
    GRASSHOPPER_CIPHER_OFB,
    GRASSHOPPER_CIPHER_CFB,
    GRASSHOPPER_CIPHER_CTR,
    GRASSHOPPER_CIPHER_CTRACPKM,
  <<<<<<< magma_impl
};

static EVP_CIPHER* gost_grasshopper_ciphers[6] = {
        [GRASSHOPPER_CIPHER_ECB] = NULL,
        [GRASSHOPPER_CIPHER_CBC] = NULL,
        [GRASSHOPPER_CIPHER_OFB] = NULL,
        [GRASSHOPPER_CIPHER_CFB] = NULL,
        [GRASSHOPPER_CIPHER_CTR] = NULL,
        [GRASSHOPPER_CIPHER_CTRACPKM] = NULL,
  =======
    GRASSHOPPER_CIPHER_CTRACPKMOMAC,
};

static GOST_cipher grasshopper_template_cipher = {
    .block_size = GRASSHOPPER_BLOCK_SIZE,
    .key_len = GRASSHOPPER_KEY_SIZE,
    .flags = EVP_CIPH_RAND_KEY |
        EVP_CIPH_ALWAYS_CALL_INIT,
    .cleanup = gost_grasshopper_cipher_cleanup,
    .ctx_size = sizeof(gost_grasshopper_cipher_ctx),
    .set_asn1_parameters = gost_grasshopper_set_asn1_parameters,
    .get_asn1_parameters = gost_grasshopper_get_asn1_parameters,
    .ctrl = gost_grasshopper_cipher_ctl,
};

GOST_cipher grasshopper_ecb_cipher = {
    .nid = NID_grasshopper_ecb,
    .template = &grasshopper_template_cipher,
    .flags = EVP_CIPH_ECB_MODE,
    .init = gost_grasshopper_cipher_init_ecb,
    .do_cipher = gost_grasshopper_cipher_do_ecb,
};

GOST_cipher grasshopper_cbc_cipher = {
    .nid = NID_grasshopper_cbc,
    .template = &grasshopper_template_cipher,
    .iv_len = 16,
    .flags = EVP_CIPH_CBC_MODE |
        EVP_CIPH_CUSTOM_IV,
    .init = gost_grasshopper_cipher_init_cbc,
    .do_cipher = gost_grasshopper_cipher_do_cbc,
  >>>>>>> master
};

GOST_cipher grasshopper_ofb_cipher = {
    .nid = NID_grasshopper_ofb,
    .template = &grasshopper_template_cipher,
    .block_size = 1,
    .iv_len = 16,
    .flags = EVP_CIPH_OFB_MODE |
        EVP_CIPH_NO_PADDING |
        EVP_CIPH_CUSTOM_IV,
    .init = gost_grasshopper_cipher_init_ofb,
    .do_cipher = gost_grasshopper_cipher_do_ofb,
};

  <<<<<<< magma_impl
static struct GRASSHOPPER_CIPHER_PARAMS gost_cipher_params[6] = {
  =======
GOST_cipher grasshopper_cfb_cipher = {
    .nid = NID_grasshopper_cfb,
    .template = &grasshopper_template_cipher,
    .block_size = 1,
    .iv_len = 16,
    .flags = EVP_CIPH_CFB_MODE |
        EVP_CIPH_NO_PADDING |
        EVP_CIPH_CUSTOM_IV,
    .init = gost_grasshopper_cipher_init_cfb,
    .do_cipher = gost_grasshopper_cipher_do_cfb,
};

  <<<<<<< openssl_1_1_0_release1
static struct GRASSHOPPER_CIPHER_PARAMS gost_cipher_params[5] = {
  >>>>>>> master
        [GRASSHOPPER_CIPHER_ECB] = {
                NID_grasshopper_ecb,
                gost_grasshopper_cipher_init_ecb,
                gost_grasshopper_cipher_do_ecb,
                NULL,
                16,
                sizeof(gost_grasshopper_cipher_ctx),
                0,
                true
        },
        [GRASSHOPPER_CIPHER_CBC] = {
                NID_grasshopper_cbc,
                gost_grasshopper_cipher_init_cbc,
                gost_grasshopper_cipher_do_cbc,
                NULL,
                16,
                sizeof(gost_grasshopper_cipher_ctx),
                16,
                true
        },
        [GRASSHOPPER_CIPHER_OFB] = {
                NID_grasshopper_ofb,
                gost_grasshopper_cipher_init_ofb,
                gost_grasshopper_cipher_do_ofb,
                gost_grasshopper_cipher_destroy_ofb,
                1,
                sizeof(gost_grasshopper_cipher_ctx_ofb),
                16,
                false
        },
        [GRASSHOPPER_CIPHER_CFB] = {
                NID_grasshopper_cfb,
                gost_grasshopper_cipher_init_cfb,
                gost_grasshopper_cipher_do_cfb,
                NULL,
                1,
                sizeof(gost_grasshopper_cipher_ctx),
                16,
                false
        },
        [GRASSHOPPER_CIPHER_CTR] = {
                NID_grasshopper_ctr,
                gost_grasshopper_cipher_init_ctr,
                gost_grasshopper_cipher_do_ctr,
                gost_grasshopper_cipher_destroy_ctr,
                1,
                sizeof(gost_grasshopper_cipher_ctx_ctr),
		/* IV size is set to match full block, to make it responsibility of
		 * user to assign correct values (IV || 0), and to make naive context
		 * copy possible (for software such as openssh) */
                16,
  <<<<<<< magma_impl
                false
        },
        [GRASSHOPPER_CIPHER_CTRACPKM] = {
                NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm,
                gost_grasshopper_cipher_init_ctracpkm,
                gost_grasshopper_cipher_do_ctracpkm,
                gost_grasshopper_cipher_destroy_ctr,
                1,
                sizeof(gost_grasshopper_cipher_ctx_ctr),
                16,
  =======
  >>>>>>> master
                false
        },
  =======
GOST_cipher grasshopper_ctr_cipher = {
    .nid = NID_grasshopper_ctr,
    .template = &grasshopper_template_cipher,
    .block_size = 1,
    .iv_len = 8,
    .flags = EVP_CIPH_CTR_MODE |
        EVP_CIPH_NO_PADDING |
        EVP_CIPH_CUSTOM_IV,
    .init = gost_grasshopper_cipher_init_ctr,
    .do_cipher = gost_grasshopper_cipher_do_ctr,
    .ctx_size = sizeof(gost_grasshopper_cipher_ctx_ctr),
  >>>>>>> master
};

  <<<<<<< magma_impl
  =======
GOST_cipher grasshopper_ctr_acpkm_cipher = {
    .nid = NID_kuznyechik_ctr_acpkm,
    .template = &grasshopper_template_cipher,
    .block_size = 1,
    .iv_len = 8,
    .flags = EVP_CIPH_CTR_MODE |
        EVP_CIPH_NO_PADDING |
        EVP_CIPH_CUSTOM_IV,
    .init = gost_grasshopper_cipher_init_ctracpkm,
    .do_cipher = gost_grasshopper_cipher_do_ctracpkm,
    .ctx_size = sizeof(gost_grasshopper_cipher_ctx_ctr),
};

GOST_cipher grasshopper_ctr_acpkm_omac_cipher = {
    .nid = NID_kuznyechik_ctr_acpkm_omac,
    .template = &grasshopper_template_cipher,
    .block_size = 1,
    .iv_len = 8,
    .flags = EVP_CIPH_CTR_MODE |
        EVP_CIPH_NO_PADDING |
        EVP_CIPH_CUSTOM_IV |
        EVP_CIPH_FLAG_CUSTOM_CIPHER |
        EVP_CIPH_FLAG_CIPHER_WITH_MAC |
        EVP_CIPH_CUSTOM_COPY,
    .init = gost_grasshopper_cipher_init_ctracpkm_omac,
    .do_cipher = gost_grasshopper_cipher_do_ctracpkm_omac,
    .ctx_size = sizeof(gost_grasshopper_cipher_ctx_ctr),
};

  >>>>>>> master
/* first 256 bit of D from draft-irtf-cfrg-re-keying-12 */
static const unsigned char ACPKM_D_2018[] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, /*  64 bit */
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, /* 128 bit */
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, /* 256 bit */
};

  <<<<<<< magma_impl
static void acpkm_next(gost_grasshopper_cipher_ctx *c)
  =======
static void acpkm_next(gost_grasshopper_cipher_ctx * c)
  >>>>>>> master
{
    unsigned char newkey[GRASSHOPPER_KEY_SIZE];
    const int J = GRASSHOPPER_KEY_SIZE / GRASSHOPPER_BLOCK_SIZE;
    int n;

    for (n = 0; n < J; n++) {
        const unsigned char *D_n = &ACPKM_D_2018[n * GRASSHOPPER_BLOCK_SIZE];

        grasshopper_encrypt_block(&c->encrypt_round_keys,
  <<<<<<< magma_impl
            (grasshopper_w128_t *)D_n,
            (grasshopper_w128_t *)&newkey[n * GRASSHOPPER_BLOCK_SIZE],
            &c->buffer);
  =======
                                  (grasshopper_w128_t *) D_n,
                                  (grasshopper_w128_t *) & newkey[n *
                                                                  GRASSHOPPER_BLOCK_SIZE],
                                  &c->buffer);
  >>>>>>> master
    }
    gost_grasshopper_cipher_key(c, newkey);
}

/* Set 256 bit  key into context */
static GRASSHOPPER_INLINE void
gost_grasshopper_cipher_key(gost_grasshopper_cipher_ctx * c, const uint8_t *k)
{
    int i;
    for (i = 0; i < 2; i++) {
        grasshopper_copy128(&c->key.k.k[i],
                            (const grasshopper_w128_t *)(k + i * 16));
    }

    grasshopper_set_encrypt_key(&c->encrypt_round_keys, &c->key);
    grasshopper_set_decrypt_key(&c->decrypt_round_keys, &c->key);
}

/* Set master 256-bit key to be used in TLSTREE calculation into context */
static GRASSHOPPER_INLINE void
gost_grasshopper_master_key(gost_grasshopper_cipher_ctx * c, const uint8_t *k)
{
    int i;
    for (i = 0; i < 2; i++) {
        grasshopper_copy128(&c->master_key.k.k[i],
                            (const grasshopper_w128_t *)(k + i * 16));
    }
}

/* Cleans up key from context */
static GRASSHOPPER_INLINE void
gost_grasshopper_cipher_destroy(gost_grasshopper_cipher_ctx * c)
{
    int i;
    for (i = 0; i < 2; i++) {
        grasshopper_zero128(&c->key.k.k[i]);
        grasshopper_zero128(&c->master_key.k.k[i]);
    }
    for (i = 0; i < GRASSHOPPER_ROUND_KEYS_COUNT; i++) {
        grasshopper_zero128(&c->encrypt_round_keys.k[i]);
    }
    for (i = 0; i < GRASSHOPPER_ROUND_KEYS_COUNT; i++) {
        grasshopper_zero128(&c->decrypt_round_keys.k[i]);
    }
    grasshopper_zero128(&c->buffer);
}

static GRASSHOPPER_INLINE void
gost_grasshopper_cipher_destroy_ctr(gost_grasshopper_cipher_ctx * c)
{
    gost_grasshopper_cipher_ctx_ctr *ctx =
        (gost_grasshopper_cipher_ctx_ctr *) c;

    if (ctx->omac_ctx)
        EVP_MD_CTX_free(ctx->omac_ctx);

    grasshopper_zero128(&ctx->partial_buffer);
}

static int gost_grasshopper_cipher_init(EVP_CIPHER_CTX *ctx,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc)
{
    gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (EVP_CIPHER_CTX_get_app_data(ctx) == NULL) {
        EVP_CIPHER_CTX_set_app_data(ctx, EVP_CIPHER_CTX_get_cipher_data(ctx));
        if (enc && c->type == GRASSHOPPER_CIPHER_CTRACPKM) {
            gost_grasshopper_cipher_ctx_ctr *ctr = EVP_CIPHER_CTX_get_cipher_data(ctx);
            if (init_zero_kdf_seed(ctr->kdf_seed) == 0)
                return -1;
        }
    }

    if (key != NULL) {
        gost_grasshopper_cipher_key(c, key);
        gost_grasshopper_master_key(c, key);
    }

    if (iv != NULL) {
        memcpy((unsigned char *)EVP_CIPHER_CTX_original_iv(ctx), iv,
               EVP_CIPHER_CTX_iv_length(ctx));
    }

    memcpy(EVP_CIPHER_CTX_iv_noconst(ctx),
           EVP_CIPHER_CTX_original_iv(ctx), EVP_CIPHER_CTX_iv_length(ctx));

    grasshopper_zero128(&c->buffer);

    return 1;
}

static GRASSHOPPER_INLINE int
gost_grasshopper_cipher_init_ecb(EVP_CIPHER_CTX *ctx, const unsigned char
                                 *key, const unsigned char
                                 *iv, int enc)
{
    gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    c->type = GRASSHOPPER_CIPHER_ECB;
    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

static GRASSHOPPER_INLINE int
gost_grasshopper_cipher_init_cbc(EVP_CIPHER_CTX *ctx, const unsigned char
                                 *key, const unsigned char
                                 *iv, int enc)
{
    gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    c->type = GRASSHOPPER_CIPHER_CBC;
    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

static GRASSHOPPER_INLINE
int gost_grasshopper_cipher_init_ofb(EVP_CIPHER_CTX *ctx, const unsigned char
                                     *key, const unsigned char
                                     *iv, int enc)
{
    gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    c->type = GRASSHOPPER_CIPHER_OFB;
    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

static GRASSHOPPER_INLINE int
gost_grasshopper_cipher_init_cfb(EVP_CIPHER_CTX *ctx, const unsigned char
                                 *key, const unsigned char
                                 *iv, int enc)
{
    gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    c->type = GRASSHOPPER_CIPHER_CFB;
    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

static GRASSHOPPER_INLINE int
gost_grasshopper_cipher_init_ctr(EVP_CIPHER_CTX *ctx, const unsigned char
                                 *key, const unsigned char
                                 *iv, int enc)
{
    gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);

    c->c.type = GRASSHOPPER_CIPHER_CTR;
    EVP_CIPHER_CTX_set_num(ctx, 0);

    grasshopper_zero128(&c->partial_buffer);

  <<<<<<< openssl_1_1_0_release1
  =======
    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

  <<<<<<< magma_impl
GRASSHOPPER_INLINE int gost_grasshopper_cipher_init_ctracpkm(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                                               const unsigned char *iv,
                                                               int enc) {
  =======
static GRASSHOPPER_INLINE int
gost_grasshopper_cipher_init_ctracpkm(EVP_CIPHER_CTX
                                      *ctx, const unsigned
                                      char *key, const unsigned
                                      char *iv, int enc)
{
  >>>>>>> master
    gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);

    /* NB: setting type makes EVP do_cipher callback useless */
    c->c.type = GRASSHOPPER_CIPHER_CTRACPKM;
    EVP_CIPHER_CTX_set_num(ctx, 0);
  <<<<<<< magma_impl
    c->section_size  = 4096;

    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

GRASSHOPPER_INLINE int gost_grasshopper_cipher_do(EVP_CIPHER_CTX* ctx, unsigned char* out,
                                                         const unsigned char* in, size_t inl) {
    gost_grasshopper_cipher_ctx* c = (gost_grasshopper_cipher_ctx*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct GRASSHOPPER_CIPHER_PARAMS* params = &gost_cipher_params[c->type];
  =======
    c->section_size = 4096;
  >>>>>>> master

  >>>>>>> master
    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

static GRASSHOPPER_INLINE int
gost_grasshopper_cipher_init_ctracpkm_omac(EVP_CIPHER_CTX
                                           *ctx, const unsigned
                                           char *key, const unsigned
                                           char *iv, int enc)
{
    gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);

    /* NB: setting type makes EVP do_cipher callback useless */
    c->c.type = GRASSHOPPER_CIPHER_CTRACPKMOMAC;
    EVP_CIPHER_CTX_set_num(ctx, 0);
    c->section_size = 4096;

    if (key) {
        unsigned char cipher_key[32];
        c->omac_ctx = EVP_MD_CTX_new();

        if (c->omac_ctx == NULL) {
            GOSTerr(GOST_F_GOST_GRASSHOPPER_CIPHER_INIT_CTRACPKM_OMAC, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        if (gost2015_acpkm_omac_init(NID_kuznyechik_mac, enc, key,
           c->omac_ctx, cipher_key, c->kdf_seed) != 1) {
            EVP_MD_CTX_free(c->omac_ctx);
            c->omac_ctx = NULL;
            return 0;
        }

        return gost_grasshopper_cipher_init(ctx, cipher_key, iv, enc);
    }

    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

static int gost_grasshopper_cipher_do_ecb(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                          const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx *c =
        (gost_grasshopper_cipher_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    bool encrypting = (bool) EVP_CIPHER_CTX_encrypting(ctx);
    const unsigned char *current_in = in;
    unsigned char *current_out = out;
    size_t blocks = inl / GRASSHOPPER_BLOCK_SIZE;
    size_t i;

    for (i = 0; i < blocks;
         i++, current_in += GRASSHOPPER_BLOCK_SIZE, current_out +=
         GRASSHOPPER_BLOCK_SIZE) {
        if (encrypting) {
            grasshopper_encrypt_block(&c->encrypt_round_keys,
                                      (grasshopper_w128_t *) current_in,
                                      (grasshopper_w128_t *) current_out,
                                      &c->buffer);
        } else {
            grasshopper_decrypt_block(&c->decrypt_round_keys,
                                      (grasshopper_w128_t *) current_in,
                                      (grasshopper_w128_t *) current_out,
                                      &c->buffer);
        }
    }

    return 1;
}

static int gost_grasshopper_cipher_do_cbc(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                          const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx *c =
        (gost_grasshopper_cipher_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    bool encrypting = (bool) EVP_CIPHER_CTX_encrypting(ctx);
    const unsigned char *current_in = in;
    unsigned char *current_out = out;
    size_t blocks = inl / GRASSHOPPER_BLOCK_SIZE;
    size_t i;
    grasshopper_w128_t *currentBlock;

    currentBlock = (grasshopper_w128_t *) iv;

    for (i = 0; i < blocks;
         i++, current_in += GRASSHOPPER_BLOCK_SIZE, current_out +=
         GRASSHOPPER_BLOCK_SIZE) {
        grasshopper_w128_t *currentInputBlock = (grasshopper_w128_t *) current_in;
        grasshopper_w128_t *currentOutputBlock = (grasshopper_w128_t *) current_out;
        if (encrypting) {
            grasshopper_append128(currentBlock, currentInputBlock);
            grasshopper_encrypt_block(&c->encrypt_round_keys, currentBlock,
                                      currentOutputBlock, &c->buffer);
            grasshopper_copy128(currentBlock, currentOutputBlock);
        } else {
            grasshopper_w128_t tmp;

            grasshopper_copy128(&tmp, currentInputBlock);
            grasshopper_decrypt_block(&c->decrypt_round_keys,
                                      currentInputBlock, currentOutputBlock,
                                      &c->buffer);
            grasshopper_append128(currentOutputBlock, currentBlock);
            grasshopper_copy128(currentBlock, &tmp);
        }
    }

    return 1;
}

  <<<<<<< openssl_1_1_0_release1
/* increment counter (128-bit int) by 1 */
static void ctr128_inc(unsigned char *counter)
{
    unsigned int n = 16;
    unsigned char c;

    do {
  =======
void inc_counter(unsigned char *counter, size_t counter_bytes)
{
    unsigned int n = counter_bytes;

    do {
        unsigned char c;
  >>>>>>> master
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
  <<<<<<< openssl_1_1_0_release1
        if (c) return;
    } while (n);
}

int gost_grasshopper_cipher_do_ctr(EVP_CIPHER_CTX* ctx, unsigned char* out,
                                          const unsigned char* in, size_t inl) {
    gost_grasshopper_cipher_ctx_ctr* c = (gost_grasshopper_cipher_ctx_ctr*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char* iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    const unsigned char* current_in = in;
    unsigned char* current_out = out;
    grasshopper_w128_t* currentInputBlock;
    grasshopper_w128_t* currentOutputBlock;
    unsigned int n = EVP_CIPHER_CTX_num(ctx);
    size_t lasted;
  =======
        if (c)
            return;
    } while (n);
}

/* increment counter (128-bit int) by 1 */
static void ctr128_inc(unsigned char *counter)
{
    inc_counter(counter, 16);
}

static int gost_grasshopper_cipher_do_ctr(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                          const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx_ctr *c = (gost_grasshopper_cipher_ctx_ctr *)
        EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    const unsigned char *current_in = in;
    unsigned char *current_out = out;
    grasshopper_w128_t *currentInputBlock;
    grasshopper_w128_t *currentOutputBlock;
    unsigned int n = EVP_CIPHER_CTX_num(ctx);
    size_t lasted = inl;
  >>>>>>> master
    size_t i;
    size_t blocks;
    grasshopper_w128_t *iv_buffer;
    grasshopper_w128_t tmp;

    while (n && lasted) {
        *(current_out++) = *(current_in++) ^ c->partial_buffer.b[n];
        --lasted;
        n = (n + 1) % GRASSHOPPER_BLOCK_SIZE;
    }
    EVP_CIPHER_CTX_set_num(ctx, n);
    blocks = lasted / GRASSHOPPER_BLOCK_SIZE;

  <<<<<<< openssl_1_1_0_release1
    while (n && inl) {
	*(current_out++) = *(current_in++) ^ c->partial_buffer.b[n];
	--inl;
	n = (n + 1) % GRASSHOPPER_BLOCK_SIZE;
    }
    EVP_CIPHER_CTX_set_num(ctx, n);
    size_t blocks = inl / GRASSHOPPER_BLOCK_SIZE;

  <<<<<<< magma_impl
    while (n && inl) {
	*(current_out++) = *(current_in++) ^ c->partial_buffer.b[n];
	--inl;
	n = (n + 1) % GRASSHOPPER_BLOCK_SIZE;
    }
    EVP_CIPHER_CTX_set_num(ctx, n);
    size_t blocks = inl / GRASSHOPPER_BLOCK_SIZE;

  =======
  >>>>>>> master
    grasshopper_w128_t* iv_buffer = (grasshopper_w128_t*) iv;

    // full parts
    for (i = 0; i < blocks; i++) {
        currentInputBlock = (grasshopper_w128_t*) current_in;
        currentOutputBlock = (grasshopper_w128_t*) current_out;
        grasshopper_encrypt_block(&c->c.encrypt_round_keys, iv_buffer, currentOutputBlock, &c->c.buffer);
        grasshopper_append128(currentOutputBlock, currentInputBlock);
  <<<<<<< magma_impl
  =======
  =======
    iv_buffer = (grasshopper_w128_t *) iv;

    // full parts
    for (i = 0; i < blocks; i++) {
        currentInputBlock = (grasshopper_w128_t *) current_in;
        currentOutputBlock = (grasshopper_w128_t *) current_out;
        grasshopper_encrypt_block(&c->c.encrypt_round_keys, iv_buffer,
                                  &c->partial_buffer, &c->c.buffer);
        grasshopper_plus128(&tmp, &c->partial_buffer, currentInputBlock);
        grasshopper_copy128(currentOutputBlock, &tmp);
  >>>>>>> master
  >>>>>>> master
        ctr128_inc(iv_buffer->b);
        current_in += GRASSHOPPER_BLOCK_SIZE;
        current_out += GRASSHOPPER_BLOCK_SIZE;
        lasted -= GRASSHOPPER_BLOCK_SIZE;
    }

    if (lasted > 0) {
  <<<<<<< openssl_1_1_0_release1
        currentInputBlock = (grasshopper_w128_t*) current_in;
        currentOutputBlock = (grasshopper_w128_t*) current_out;
        grasshopper_encrypt_block(&c->c.encrypt_round_keys, iv_buffer, &c->partial_buffer, &c->c.buffer);
  <<<<<<< magma_impl
  =======
  =======
        currentInputBlock = (grasshopper_w128_t *) current_in;
        currentOutputBlock = (grasshopper_w128_t *) current_out;
        grasshopper_encrypt_block(&c->c.encrypt_round_keys, iv_buffer,
                                  &c->partial_buffer, &c->c.buffer);
  >>>>>>> master
  >>>>>>> master
        for (i = 0; i < lasted; i++) {
            currentOutputBlock->b[i] =
                c->partial_buffer.b[i] ^ currentInputBlock->b[i];
        }
  <<<<<<< magma_impl
	EVP_CIPHER_CTX_set_num(ctx, i);
  =======
  <<<<<<< openssl_1_1_0_release1
	EVP_CIPHER_CTX_set_num(ctx, i);
  =======
        EVP_CIPHER_CTX_set_num(ctx, i);
  >>>>>>> master
  >>>>>>> master
        ctr128_inc(iv_buffer->b);
    }

    return inl;
}

#define GRASSHOPPER_BLOCK_MASK (GRASSHOPPER_BLOCK_SIZE - 1)
  <<<<<<< magma_impl
static inline void apply_acpkm_grasshopper(gost_grasshopper_cipher_ctx_ctr *ctx, unsigned int *num)
{
    if (!ctx->section_size ||
        (*num < ctx->section_size))
  =======
static inline void apply_acpkm_grasshopper(gost_grasshopper_cipher_ctx_ctr *
                                           ctx, unsigned int *num)
{
    if (!ctx->section_size || (*num < ctx->section_size))
  >>>>>>> master
        return;
    acpkm_next(&ctx->c);
    *num &= GRASSHOPPER_BLOCK_MASK;
}

  <<<<<<< magma_impl
/* If meshing is not configured via ctrl (setting section_size)
 * this function works exactly like plain ctr */
int gost_grasshopper_cipher_do_ctracpkm(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t inl) {
    gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    unsigned int num = EVP_CIPHER_CTX_num(ctx);

    while ((num & GRASSHOPPER_BLOCK_MASK) && inl) {
        *out++ = *in++ ^ c->partial_buffer.b[num & GRASSHOPPER_BLOCK_MASK];
        --inl;
        num++;
    }
    size_t blocks = inl / GRASSHOPPER_BLOCK_SIZE;
    size_t i;

    // full parts
    for (i = 0; i < blocks; i++) {
        apply_acpkm_grasshopper(c, &num);
        grasshopper_encrypt_block(&c->c.encrypt_round_keys,
            (grasshopper_w128_t *)iv, (grasshopper_w128_t *)out, &c->c.buffer);
        grasshopper_append128((grasshopper_w128_t *)out, (grasshopper_w128_t *)in);
        ctr128_inc(iv);
        in  += GRASSHOPPER_BLOCK_SIZE;
        out += GRASSHOPPER_BLOCK_SIZE;
        num += GRASSHOPPER_BLOCK_SIZE;
    }

    // last part
    size_t lasted = inl - blocks * GRASSHOPPER_BLOCK_SIZE;
    if (lasted > 0) {
        apply_acpkm_grasshopper(c, &num);
        grasshopper_encrypt_block(&c->c.encrypt_round_keys,
            (grasshopper_w128_t *)iv, &c->partial_buffer, &c->c.buffer);
        for (i = 0; i < lasted; i++)
            out[i] = c->partial_buffer.b[i] ^ in[i];
        ctr128_inc(iv);
        num += lasted;
    }
    EVP_CIPHER_CTX_set_num(ctx, num);

    return 1;
}

  =======
  <<<<<<< openssl_1_1_0_release1
  >>>>>>> master
/*
 * Fixed 128-bit IV implementation make shift regiser redundant.
 */
static void gost_grasshopper_cnt_next(gost_grasshopper_cipher_ctx_ofb* ctx, grasshopper_w128_t* iv,
                                      grasshopper_w128_t* buf) {
    memcpy(&ctx->buffer1, iv, 16);
    grasshopper_encrypt_block(&ctx->c.encrypt_round_keys, &ctx->buffer1, buf, &ctx->c.buffer);
    memcpy(iv, buf, 16);
  <<<<<<< magma_impl
  =======
  =======
/* If meshing is not configured via ctrl (setting section_size)
 * this function works exactly like plain ctr */
static int gost_grasshopper_cipher_do_ctracpkm(EVP_CIPHER_CTX *ctx,
                                               unsigned char *out,
                                               const unsigned char *in,
                                               size_t inl)
{
    gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    unsigned int num = EVP_CIPHER_CTX_num(ctx);
    size_t blocks, i, lasted = inl;
    grasshopper_w128_t tmp;

    while ((num & GRASSHOPPER_BLOCK_MASK) && lasted) {
        *out++ = *in++ ^ c->partial_buffer.b[num & GRASSHOPPER_BLOCK_MASK];
        --lasted;
        num++;
    }
    blocks = lasted / GRASSHOPPER_BLOCK_SIZE;

    // full parts
    for (i = 0; i < blocks; i++) {
        apply_acpkm_grasshopper(c, &num);
        grasshopper_encrypt_block(&c->c.encrypt_round_keys,
                                  (grasshopper_w128_t *) iv,
                                  (grasshopper_w128_t *) & c->partial_buffer,
                                  &c->c.buffer);
        grasshopper_plus128(&tmp, &c->partial_buffer,
                            (grasshopper_w128_t *) in);
        grasshopper_copy128((grasshopper_w128_t *) out, &tmp);
        ctr128_inc(iv);
        in += GRASSHOPPER_BLOCK_SIZE;
        out += GRASSHOPPER_BLOCK_SIZE;
        num += GRASSHOPPER_BLOCK_SIZE;
        lasted -= GRASSHOPPER_BLOCK_SIZE;
    }

    // last part
    if (lasted > 0) {
        apply_acpkm_grasshopper(c, &num);
        grasshopper_encrypt_block(&c->c.encrypt_round_keys,
                                  (grasshopper_w128_t *) iv,
                                  &c->partial_buffer, &c->c.buffer);
        for (i = 0; i < lasted; i++)
            out[i] = c->partial_buffer.b[i] ^ in[i];
        ctr128_inc(iv);
        num += lasted;
    }
    EVP_CIPHER_CTX_set_num(ctx, num);

    return inl;
  >>>>>>> master
  >>>>>>> master
}

static int gost_grasshopper_cipher_do_ctracpkm_omac(EVP_CIPHER_CTX *ctx,
                                                    unsigned char *out,
                                                    const unsigned char *in,
                                                    size_t inl)
{
    int result;
    gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    /* As in and out can be the same pointer, process unencrypted here */
    if (EVP_CIPHER_CTX_encrypting(ctx))
        EVP_DigestSignUpdate(c->omac_ctx, in, inl);

    if (in == NULL && inl == 0) { /* Final call */
        return gost2015_final_call(ctx, c->omac_ctx, KUZNYECHIK_MAC_MAX_SIZE, c->tag, gost_grasshopper_cipher_do_ctracpkm);
    }

    if (in == NULL) {
        GOSTerr(GOST_F_GOST_GRASSHOPPER_CIPHER_DO_CTRACPKM_OMAC, ERR_R_EVP_LIB);
        return -1;
    }
    result = gost_grasshopper_cipher_do_ctracpkm(ctx, out, in, inl);

    /* As in and out can be the same pointer, process decrypted here */
    if (!EVP_CIPHER_CTX_encrypting(ctx))
        EVP_DigestSignUpdate(c->omac_ctx, out, inl);

    return result;
}
/*
 * Fixed 128-bit IV implementation make shift regiser redundant.
 */
static void gost_grasshopper_cnt_next(gost_grasshopper_cipher_ctx * ctx,
                                      grasshopper_w128_t * iv,
                                      grasshopper_w128_t * buf)
{
    grasshopper_w128_t tmp;
    memcpy(&tmp, iv, 16);
    grasshopper_encrypt_block(&ctx->encrypt_round_keys, &tmp,
                              buf, &ctx->buffer);
    memcpy(iv, buf, 16);
}

static int gost_grasshopper_cipher_do_ofb(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                          const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx *c = (gost_grasshopper_cipher_ctx *)
        EVP_CIPHER_CTX_get_cipher_data(ctx);
    const unsigned char *in_ptr = in;
    unsigned char *out_ptr = out;
    unsigned char *buf = EVP_CIPHER_CTX_buf_noconst(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    int num = EVP_CIPHER_CTX_num(ctx);
    size_t i = 0;
    size_t j;

    /* process partial block if any */
    if (num > 0) {
        for (j = (size_t)num, i = 0; j < GRASSHOPPER_BLOCK_SIZE && i < inl;
             j++, i++, in_ptr++, out_ptr++) {
            *out_ptr = buf[j] ^ (*in_ptr);
        }
        if (j == GRASSHOPPER_BLOCK_SIZE) {
            EVP_CIPHER_CTX_set_num(ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_num(ctx, (int)j);
            return 1;
        }
    }

    for (; i + GRASSHOPPER_BLOCK_SIZE <
         inl;
         i += GRASSHOPPER_BLOCK_SIZE, in_ptr +=
         GRASSHOPPER_BLOCK_SIZE, out_ptr += GRASSHOPPER_BLOCK_SIZE) {
        /*
         * block cipher current iv
         */
        /* Encrypt */
        gost_grasshopper_cnt_next(c, (grasshopper_w128_t *) iv,
                                  (grasshopper_w128_t *) buf);

        /*
         * xor next block of input text with it and output it
         */
        /*
         * output this block
         */
        for (j = 0; j < GRASSHOPPER_BLOCK_SIZE; j++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
    }

    /* Process rest of buffer */
    if (i < inl) {
        gost_grasshopper_cnt_next(c, (grasshopper_w128_t *) iv,
                                  (grasshopper_w128_t *) buf);
        for (j = 0; i < inl; j++, i++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        EVP_CIPHER_CTX_set_num(ctx, (int)j);
    } else {
        EVP_CIPHER_CTX_set_num(ctx, 0);
    }

    return 1;
}

static int gost_grasshopper_cipher_do_cfb(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                          const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx *c =
        (gost_grasshopper_cipher_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    const unsigned char *in_ptr = in;
    unsigned char *out_ptr = out;
    unsigned char *buf = EVP_CIPHER_CTX_buf_noconst(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    bool encrypting = (bool) EVP_CIPHER_CTX_encrypting(ctx);
    int num = EVP_CIPHER_CTX_num(ctx);
    size_t i = 0;
    size_t j = 0;

    /* process partial block if any */
    if (num > 0) {
        for (j = (size_t)num, i = 0; j < GRASSHOPPER_BLOCK_SIZE && i < inl;
             j++, i++, in_ptr++, out_ptr++) {
            if (!encrypting) {
                buf[j + GRASSHOPPER_BLOCK_SIZE] = *in_ptr;
            }
            *out_ptr = buf[j] ^ (*in_ptr);
            if (encrypting) {
                buf[j + GRASSHOPPER_BLOCK_SIZE] = *out_ptr;
            }
        }
        if (j == GRASSHOPPER_BLOCK_SIZE) {
            memcpy(iv, buf + GRASSHOPPER_BLOCK_SIZE, GRASSHOPPER_BLOCK_SIZE);
            EVP_CIPHER_CTX_set_num(ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_num(ctx, (int)j);
            return 1;
        }
    }

    for (; i + GRASSHOPPER_BLOCK_SIZE <
         inl;
         i += GRASSHOPPER_BLOCK_SIZE, in_ptr +=
         GRASSHOPPER_BLOCK_SIZE, out_ptr += GRASSHOPPER_BLOCK_SIZE) {
        /*
         * block cipher current iv
         */
        grasshopper_encrypt_block(&c->encrypt_round_keys,
                                  (grasshopper_w128_t *) iv,
                                  (grasshopper_w128_t *) buf, &c->buffer);
        /*
         * xor next block of input text with it and output it
         */
        /*
         * output this block
         */
        if (!encrypting) {
            memcpy(iv, in_ptr, GRASSHOPPER_BLOCK_SIZE);
        }
        for (j = 0; j < GRASSHOPPER_BLOCK_SIZE; j++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        /* Encrypt */
        /* Next iv is next block of cipher text */
        if (encrypting) {
            memcpy(iv, out_ptr, GRASSHOPPER_BLOCK_SIZE);
        }
    }

    /* Process rest of buffer */
    if (i < inl) {
        grasshopper_encrypt_block(&c->encrypt_round_keys,
                                  (grasshopper_w128_t *) iv,
                                  (grasshopper_w128_t *) buf, &c->buffer);
        if (!encrypting) {
            memcpy(buf + GRASSHOPPER_BLOCK_SIZE, in_ptr, inl - i);
        }
        for (j = 0; i < inl; j++, i++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        EVP_CIPHER_CTX_set_num(ctx, (int)j);
        if (encrypting) {
            memcpy(buf + GRASSHOPPER_BLOCK_SIZE, out_ptr, j);
        }
    } else {
        EVP_CIPHER_CTX_set_num(ctx, 0);
    }

    return 1;
}

static int gost_grasshopper_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    gost_grasshopper_cipher_ctx *c =
        (gost_grasshopper_cipher_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (!c)
        return 1;

    if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CTR_MODE)
        gost_grasshopper_cipher_destroy_ctr(c);

    EVP_CIPHER_CTX_set_app_data(ctx, NULL);

    return 1;
}

static int gost_grasshopper_set_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CTR_MODE) {
        gost_grasshopper_cipher_ctx_ctr *ctr = EVP_CIPHER_CTX_get_cipher_data(ctx);

        /* CMS implies 256kb section_size */
        ctr->section_size = 256*1024;

        return gost2015_set_asn1_params(params,
               EVP_CIPHER_CTX_original_iv(ctx), 8, ctr->kdf_seed);
    }
    return 0;
}

static GRASSHOPPER_INLINE int
gost_grasshopper_get_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CTR_MODE) {
        gost_grasshopper_cipher_ctx_ctr *ctr = EVP_CIPHER_CTX_get_cipher_data(ctx);

        int iv_len = 16;
        unsigned char iv[16];

        if (gost2015_get_asn1_params(params, 16, iv, 8, ctr->kdf_seed) == 0) {
            return 0;
        }

        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, iv_len);
        memcpy((unsigned char *)EVP_CIPHER_CTX_original_iv(ctx), iv, iv_len);

        /* CMS implies 256kb section_size */
        ctr->section_size = 256*1024;
        return 1;
    }
    return 0;
}

static int gost_grasshopper_cipher_ctl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_CTRL_RAND_KEY:{
            if (RAND_priv_bytes
                ((unsigned char *)ptr, EVP_CIPHER_CTX_key_length(ctx)) <= 0) {
                GOSTerr(GOST_F_GOST_GRASSHOPPER_CIPHER_CTL, GOST_R_RNG_ERROR);
                return -1;
            }
            break;
        }
  <<<<<<< magma_impl
        case EVP_CTRL_KEY_MESH: {
            gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
            if (c->c.type != GRASSHOPPER_CIPHER_CTRACPKM ||
                !arg || (arg % GRASSHOPPER_BLOCK_SIZE))
  =======
    case EVP_CTRL_KEY_MESH:{
            gost_grasshopper_cipher_ctx_ctr *c =
                EVP_CIPHER_CTX_get_cipher_data(ctx);
            if ((c->c.type != GRASSHOPPER_CIPHER_CTRACPKM &&
                c->c.type != GRASSHOPPER_CIPHER_CTRACPKMOMAC)
                || (arg == 0)
               || (arg % GRASSHOPPER_BLOCK_SIZE))
  >>>>>>> master
                return -1;
            c->section_size = arg;
            break;
        }
  <<<<<<< magma_impl
        default:
            GOSTerr(GOST_F_GOST_GRASSHOPPER_CIPHER_CTL, GOST_R_UNSUPPORTED_CIPHER_CTL_COMMAND);
            return -1;
    }
    return 1;
}

GRASSHOPPER_INLINE EVP_CIPHER* cipher_gost_grasshopper_create(int cipher_type, int block_size) {
    return EVP_CIPHER_meth_new(cipher_type,
                               block_size  /* block_size */,
                               GRASSHOPPER_KEY_SIZE /* key_size */);
}

const int cipher_gost_grasshopper_setup(EVP_CIPHER* cipher, uint8_t mode, int iv_size, bool padding) {
    return EVP_CIPHER_meth_set_iv_length(cipher, iv_size) &&
           EVP_CIPHER_meth_set_flags(cipher, (unsigned long) (
                   mode |
                   ((!padding) ? EVP_CIPH_NO_PADDING : 0) |
                   ((iv_size > 0) ? EVP_CIPH_CUSTOM_IV : 0) |
                   EVP_CIPH_RAND_KEY |
                   EVP_CIPH_ALWAYS_CALL_INIT)
           ) &&
           EVP_CIPHER_meth_set_cleanup(cipher, gost_grasshopper_cipher_cleanup) &&
           EVP_CIPHER_meth_set_set_asn1_params(cipher, gost_grasshopper_set_asn1_parameters) &&
           EVP_CIPHER_meth_set_get_asn1_params(cipher, gost_grasshopper_get_asn1_parameters) &&
           EVP_CIPHER_meth_set_ctrl(cipher, gost_grasshopper_cipher_ctl) &&
           EVP_CIPHER_meth_set_do_cipher(cipher, gost_grasshopper_cipher_do);
}

const GRASSHOPPER_INLINE EVP_CIPHER* cipher_gost_grasshopper(uint8_t mode, uint8_t num) {
    EVP_CIPHER** cipher;
    struct GRASSHOPPER_CIPHER_PARAMS* params;

    cipher = &gost_grasshopper_ciphers[num];
  =======
    case EVP_CTRL_TLSTREE:
        {
          unsigned char newkey[32];
          int mode = EVP_CIPHER_CTX_mode(ctx);
          gost_grasshopper_cipher_ctx_ctr *ctr_ctx = NULL;
          gost_grasshopper_cipher_ctx *c = NULL;

          unsigned char adjusted_iv[16];
          unsigned char seq[8];
          int j, carry, decrement_arg;
          if (mode != EVP_CIPH_CTR_MODE)
              return -1;

          ctr_ctx = (gost_grasshopper_cipher_ctx_ctr *)
              EVP_CIPHER_CTX_get_cipher_data(ctx);
          c = &(ctr_ctx->c);

          /*
           * 'arg' parameter indicates what we should do with sequence value.
           * 
           * When function called, seq is incremented after MAC calculation.
           * In ETM mode, we use seq 'as is' in the ctrl-function (arg = 0)
           * Otherwise we have to decrease it in the implementation (arg = 1).
           */
          memcpy(seq, ptr, 8);
          decrement_arg = arg;
          if (!decrement_sequence(seq, decrement_arg))
          {
              GOSTerr(GOST_F_GOST_GRASSHOPPER_CIPHER_CTL, GOST_R_CTRL_CALL_FAILED);
              return -1;
          }

          if (gost_tlstree(NID_grasshopper_cbc, c->master_key.k.b, newkey,
                (const unsigned char *)seq) > 0) {
            memset(adjusted_iv, 0, 16);
            memcpy(adjusted_iv, EVP_CIPHER_CTX_original_iv(ctx), 8);
            for(j=7,carry=0; j>=0; j--)
            {
              int adj_byte = adjusted_iv[j]+seq[j]+carry;
              carry = (adj_byte > 255) ? 1 : 0;
              adjusted_iv[j] = adj_byte & 0xFF;
            }
            EVP_CIPHER_CTX_set_num(ctx, 0);
            memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), adjusted_iv, 16);
  >>>>>>> master

            gost_grasshopper_cipher_key(c, newkey);
            return 1;
          }
        }
        return -1;
#if 0
    case EVP_CTRL_AEAD_GET_TAG:
    case EVP_CTRL_AEAD_SET_TAG:
        {
            int taglen = arg;
            unsigned char *tag = ptr;

            gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
            if (c->c.type != GRASSHOPPER_CIPHER_MGM)
                return -1;

            if (taglen > KUZNYECHIK_MAC_MAX_SIZE) {
                CRYPTOCOMerr(CRYPTOCOM_F_GOST_GRASSHOPPER_CIPHER_CTL,
                        CRYPTOCOM_R_INVALID_TAG_LENGTH);
                return -1;
            }

            if (type == EVP_CTRL_AEAD_GET_TAG)
                memcpy(tag, c->final_tag, taglen);
            else
                memcpy(c->final_tag, tag, taglen);

            return 1;
        }
#endif
    case EVP_CTRL_PROCESS_UNPROTECTED:
    {
      STACK_OF(X509_ATTRIBUTE) *x = ptr;
      gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);

      if (c->c.type != GRASSHOPPER_CIPHER_CTRACPKMOMAC)
        return -1;

      return gost2015_process_unprotected_attributes(x, arg, KUZNYECHIK_MAC_MAX_SIZE, c->tag);
    }
    return 1;
    case EVP_CTRL_COPY: {
        EVP_CIPHER_CTX *out = ptr;

        gost_grasshopper_cipher_ctx_ctr *out_cctx = EVP_CIPHER_CTX_get_cipher_data(out);
        gost_grasshopper_cipher_ctx_ctr *in_cctx  = EVP_CIPHER_CTX_get_cipher_data(ctx);

        if (in_cctx->c.type != GRASSHOPPER_CIPHER_CTRACPKMOMAC)
            return -1;

        if (in_cctx->omac_ctx == out_cctx->omac_ctx) {
            out_cctx->omac_ctx = EVP_MD_CTX_new();
            if (out_cctx->omac_ctx == NULL) {
                GOSTerr(GOST_F_GOST_GRASSHOPPER_CIPHER_CTL, ERR_R_MALLOC_FAILURE);
                return -1;
            }
        }
        return EVP_MD_CTX_copy(out_cctx->omac_ctx, in_cctx->omac_ctx);
    }
    default:
        GOSTerr(GOST_F_GOST_GRASSHOPPER_CIPHER_CTL,
                GOST_R_UNSUPPORTED_CIPHER_CTL_COMMAND);
        return -1;
    }
    return 1;
}

  <<<<<<< openssl_1_1_0_release1
void cipher_gost_grasshopper_destroy(void)
{
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_ECB]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_ECB] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CBC]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CBC] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_OFB]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_OFB] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CFB]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CFB] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CTR]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CTR] = NULL;
}
  <<<<<<< magma_impl

const GRASSHOPPER_INLINE EVP_CIPHER* cipher_gost_grasshopper_ctracpkm() {
    return cipher_gost_grasshopper(EVP_CIPH_CTR_MODE, GRASSHOPPER_CIPHER_CTRACPKM);
}

void cipher_gost_grasshopper_destroy(void)
{
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_ECB]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_ECB] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CBC]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CBC] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_OFB]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_OFB] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CFB]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CFB] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CTR]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CTR] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CTRACPKM]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CTRACPKM] = NULL;
}

  =======
  >>>>>>> master
#if defined(__cplusplus)
  =======
/* Called directly by CMAC_ACPKM_Init() */
const GRASSHOPPER_INLINE EVP_CIPHER *cipher_gost_grasshopper_ctracpkm()
{
    return GOST_init_cipher(&grasshopper_ctr_acpkm_cipher);
  >>>>>>> master
}
/* vim: set expandtab cinoptions=\:0,l1,t0,g0,(0 sw=4 : */
