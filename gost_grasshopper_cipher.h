/*
 * Maxim Tishkov 2016
 * This file is distributed under the same license as OpenSSL
 */

#ifndef GOST_GRASSHOPPER_CIPHER_H
#define GOST_GRASSHOPPER_CIPHER_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "gost_grasshopper_defines.h"

#include <openssl/evp.h>

// not thread safe
// because of buffers
typedef struct {
    uint8_t type;
    grasshopper_key_t master_key;
    grasshopper_key_t key;
    grasshopper_round_keys_t encrypt_round_keys;
    grasshopper_round_keys_t decrypt_round_keys;
    grasshopper_w128_t buffer;
} gost_grasshopper_cipher_ctx;

typedef struct {
    gost_grasshopper_cipher_ctx c;
  <<<<<<< openssl_1_1_0_release1
    grasshopper_w128_t buffer1;
} gost_grasshopper_cipher_ctx_ofb;

typedef struct {
    gost_grasshopper_cipher_ctx c;
  <<<<<<< magma_impl
    grasshopper_w128_t partial_buffer;
    unsigned int section_size;  /* After how much bytes mesh the key,
				   if 0 never mesh and work like plain ctr. */
  =======
  =======
  >>>>>>> master
    grasshopper_w128_t partial_buffer;
    unsigned int section_size;  /* After how much bytes mesh the key,
				   if 0 never mesh and work like plain ctr. */
    unsigned char kdf_seed[8];
		unsigned char tag[16];
		EVP_MD_CTX *omac_ctx;
  >>>>>>> master
} gost_grasshopper_cipher_ctx_ctr;

  <<<<<<< mgm_impl
typedef enum {
	mgm_associated_data = 0,
	mgm_main_data,
} mgm_state;

typedef struct {
    gost_grasshopper_cipher_ctx c;
    grasshopper_w128_t partial_buffer;
	
		mgm_state mgm_state; /* associated_data/plain text */
		grasshopper_w128_t mgm_iv[16]; /* nonce */
		grasshopper_w128_t mgm_partial_buffer; /* Rest of associated data */
		size_t ad_length;
		size_t taglen; /* MAC length*/
		unsigned char tag[16]; /* MAC - intermediate state */
		unsigned char final_tag[16]; /* MAC - final state*/
} gost_grasshopper_cipher_ctx_mgm;

typedef int (* grasshopper_init_cipher_func)(EVP_CIPHER_CTX* ctx, const unsigned char* key, const unsigned char* iv,
                                             int enc);
  =======
static void gost_grasshopper_cipher_key(gost_grasshopper_cipher_ctx* c, const uint8_t* k);
  >>>>>>> master

static void gost_grasshopper_cipher_destroy(gost_grasshopper_cipher_ctx* c);

static int gost_grasshopper_cipher_init_ecb(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_cbc(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ofb(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_cfb(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ctr(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ctracpkm(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ctracpkm_omac(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init(EVP_CIPHER_CTX* ctx, const unsigned char* key,
    const unsigned char* iv, int enc);

  <<<<<<< magma_impl
int gost_grasshopper_cipher_init_ctracpkm(EVP_CIPHER_CTX* ctx, const unsigned char* key, const unsigned char* iv, int enc);

int gost_grasshopper_cipher_init_mgm(EVP_CIPHER_CTX* ctx, const unsigned char* key, const unsigned char* iv, int enc);

int gost_grasshopper_cipher_init(EVP_CIPHER_CTX* ctx, const unsigned char* key,
                                 const unsigned char* iv, int enc);
  =======
static int gost_grasshopper_cipher_do(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);
  >>>>>>> master

static int gost_grasshopper_cipher_do_ecb(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_cbc(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ofb(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_cfb(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ctr(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

  <<<<<<< magma_impl
int gost_grasshopper_cipher_do_ctr(EVP_CIPHER_CTX* ctx, unsigned char* out,
                                   const unsigned char* in, size_t inl);
int gost_grasshopper_cipher_do_ctracpkm(EVP_CIPHER_CTX* ctx, unsigned char* out,
                                   const unsigned char* in, size_t inl);
  <<<<<<< mgm_impl
int gost_grasshopper_cipher_do_mgm(EVP_CIPHER_CTX* ctx, unsigned char* out,
                                   const unsigned char* in, size_t inl);
  =======
  =======
static int gost_grasshopper_cipher_do_ctracpkm(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);
  >>>>>>> master
  >>>>>>> master

static int gost_grasshopper_cipher_do_ctracpkm_omac(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_cleanup(EVP_CIPHER_CTX* ctx);

static int gost_grasshopper_set_asn1_parameters(EVP_CIPHER_CTX* ctx, ASN1_TYPE* params);

static int gost_grasshopper_get_asn1_parameters(EVP_CIPHER_CTX* ctx, ASN1_TYPE* params);

static int gost_grasshopper_cipher_ctl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);

  <<<<<<< mgm_impl
const int cipher_gost_grasshopper_setup(EVP_CIPHER* cipher, uint8_t mode, int iv_size, bool padding, int extra_flags);
  =======
  <<<<<<< magma_impl
const int cipher_gost_grasshopper_setup(EVP_CIPHER* cipher, uint8_t mode, int iv_size, bool padding);
  >>>>>>> master

const EVP_CIPHER* cipher_gost_grasshopper(uint8_t mode, uint8_t num);

extern const EVP_CIPHER* cipher_gost_grasshopper_ecb();
extern const EVP_CIPHER* cipher_gost_grasshopper_cbc();
extern const EVP_CIPHER* cipher_gost_grasshopper_ofb();
extern const EVP_CIPHER* cipher_gost_grasshopper_cfb();
extern const EVP_CIPHER* cipher_gost_grasshopper_ctr();
extern const EVP_CIPHER* cipher_gost_grasshopper_ctracpkm();
extern const EVP_CIPHER* cipher_gost_grasshopper_mgm();

void cipher_gost_grasshopper_destroy(void);
  =======
const EVP_CIPHER* cipher_gost_grasshopper_ctracpkm();
  >>>>>>> master

void cipher_gost_grasshopper_destroy(void);
#if defined(__cplusplus)
}
#endif

#endif
