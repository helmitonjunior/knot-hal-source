#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include "nanoecc/ecc.h"
#include "aes/aes.h"
#include "include/linux_log.h"
#include "security.h"
#include "sec_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#define URANDOM_PATH	"/dev/urandom"
#define ECC_RETRIES	10

int encrypt(uint8_t *plaintext, size_t plaintext_len,
					uint8_t *key, unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx;
	int len, ciphertext_len;
	uint8_t ciphertext[NUM_ECC_DIGITS];
	/* Create and initialize the context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return ERROR_EVP_CIPHER_CTX_NEW;
	/*
	 * Initialize the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
		return ERROR_EVP_ENC_INIT;
	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
							plaintext_len) != 1)
		return ERROR_EVP_ENC_UPDATE;

	ciphertext_len = len;
	/*
	 * Finalize the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
		return ERROR_EVP_ENC_FINAL;

	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	memcpy(plaintext, ciphertext, ciphertext_len);

	return ciphertext_len;
}

int decrypt(uint8_t *ciphertext, size_t ciphertext_len,
		uint8_t *key, uint8_t *iv)
{
	EVP_CIPHER_CTX *ctx;
	int len, plaintext_len;
	uint8_t plaintext[NUM_ECC_DIGITS];

	/* Create and initialize the context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return ERROR_EVP_CIPHER_CTX_NEW;
	/*
	 * Initialize the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
		return ERROR_EVP_DEC_INIT;
	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
							ciphertext_len) != 1)
		return ERROR_EVP_DEC_UPDATE;

	plaintext_len = len;
	/*
	 * Finalize the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
		return ERROR_EVP_DEC_FINAL;

	plaintext_len += len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	memcpy(ciphertext, plaintext, plaintext_len);

	return plaintext_len;
}

int derive_secret(uint8_t stpubx[], uint8_t stpuby[], uint8_t lcpriv[],
				uint8_t lcpubx[], uint8_t lcpuby[], uint8_t secret[],
				uint8_t *iv)
{
	/* shared secret context */
	EVP_PKEY_CTX *ctx;
	/* shared secret */
	unsigned char *skey;
	/* shared secret buffer size */
	size_t skeylen;
	/* bignums for storing key values */
	/* private local key */
	BIGNUM *prv = BN_bin2bn(lcpriv, NUM_ECC_DIGITS, NULL);

	/* public local key */
	BIGNUM *locx = BN_bin2bn(lcpubx, NUM_ECC_DIGITS, NULL);
	BIGNUM *locy = BN_bin2bn(lcpuby, NUM_ECC_DIGITS, NULL);

	/* public imported key */
	BIGNUM *pubx = BN_bin2bn(stpubx, NUM_ECC_DIGITS, NULL);
	BIGNUM *puby = BN_bin2bn(stpuby, NUM_ECC_DIGITS, NULL);

	/*
	 * EC_KEY stores a public key (and optionally a private as well)
	 * myecc is the local key pair, peerecc is the public imported key
	 */
	EC_KEY *myecc = NULL, *peerecc = NULL;
	EVP_PKEY *pkey = NULL, *peerkey = NULL;

	/* Initializing EC POINT on public imported key */
	EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

	/* ECC point on public imported key */
	EC_POINT *ptimport = EC_POINT_new(curve);

	/* ECC point on public local key */
	EC_POINT *ptlocal = EC_POINT_new(curve);
	BN_CTX *bnctx = BN_CTX_new();

	EC_POINT_set_affine_coordinates_GFp(curve, ptimport, pubx, puby, bnctx);
	EC_POINT_set_affine_coordinates_GFp(curve, ptlocal, locx, locy, bnctx);

	/* Creating keys from curve */
	myecc = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (myecc == NULL)
		return ERROR_ECC_LOC_PKEY_CURVE;

	peerecc = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (peerecc == NULL)
		return ERROR_ECC_PEER_PKEY_CURVE;

	/* Certificate sign using OPENSSL_EC_NAMED_CURVE flag */
	EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);
	EC_KEY_set_asn1_flag(peerecc, OPENSSL_EC_NAMED_CURVE);

	/* Setting public keys (local and imported) on EC_KEY */
	if (EC_KEY_set_public_key(myecc, ptlocal) != 1)
		return ERROR_ECC_SET_LOC_PKEY;
	if (EC_KEY_set_public_key(peerecc, ptimport) != 1)
		return ERROR_ECC_SET_PEER_PKEY;
	/* Setting private local key on EC_KEY */
	if (EC_KEY_set_private_key(myecc, prv) != 1)
		return ERROR_ECC_SET_PRIV_KEY;

	/* Creating EVP_KEY struct to derive shared secret */
	peerkey = EVP_PKEY_new();

	/* Checks peerecc value */
	if (!EVP_PKEY_assign_EC_KEY(peerkey, peerecc))
		return ERROR_EVP_ASSIGN_PEER;

	pkey = EVP_PKEY_new();
	/* Checks myecc value */
	if (!EVP_PKEY_assign_EC_KEY(pkey, myecc))
		return ERROR_EVP_ASSIGN_KEY;

	/* Generating context for shared secret derivation */
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL)
		return ERROR_EVP_CIPHER_CTX_NEW;
	/* Initializing context */
	if (EVP_PKEY_derive_init(ctx) != 1)
		return ERROR_EVP_DERIVE_INIT;
	/* Setting imported public key onto derivation */
	if (EVP_PKEY_derive_set_peer(ctx, peerkey) != 1)
		return ERROR_EVP_DERIVE_SET_PEER;
	/* Dynamically allocating buffer size */
	if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0)
		return ERROR_EVP_DERIVE_ALLOC;

	skey = OPENSSL_malloc(skeylen);

	/* Derive shared secret */
	if ((EVP_PKEY_derive(ctx, skey, &skeylen)) != 1)
		return ERROR_EVP_DERIVE;
	/* Placing Secret */
	memcpy(secret, skey, skeylen);

	/* Freeing structs */
	EVP_cleanup();
	ERR_free_strings();
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerkey);
	EVP_PKEY_free(pkey);
	/*
	 * FIXME:
	 * EC_KEY_free(myecc); Causing double free error:Unknown reason
	 * EC_KEY_free(peerecc); Causing segmentation fault:Unknown reason
	 */
	EC_POINT_free(ptlocal);
	EC_POINT_free(ptimport);
	BN_CTX_free(bnctx);

	return 1;
}

extern void EccPoint_mult(EccPoint * p_result, EccPoint * p_point,
							uint8_t *p_scalar);

static int getRandomBytes(int randfd, void *p_dest, unsigned p_size)
{
	if (read(randfd, p_dest, p_size) != (int)p_size)
		return ERROR_GET_RANDOM;
	return 1;
}

int generate_keys(uint8_t *keys)
{
	int randfd, randb;
	EccPoint l_public;
	uint8_t l_private[NUM_ECC_DIGITS];
	//unsigned l_num = 1;
	int success = 0, count = 0;

	randfd = open(URANDOM_PATH, O_RDONLY);
	if (randfd == -1)
		return ERROR_ACCESS_URANDOM;

	/* if make_keys fails, try renew random values and retry */

	while (!success) {
		count++;
		randb = getRandomBytes(randfd, (char *) l_private, NUM_ECC_DIGITS *
							sizeof(uint8_t));
		success = ecc_make_key(&l_public, l_private, l_private);
		if (randb < 0)
			return randb;
		if (count > ECC_RETRIES)
			return ERROR_ECC_MK_KEYS;
	}
	memcpy(keys, l_private, NUM_ECC_DIGITS);
	memcpy(keys + NUM_ECC_DIGITS, l_public.x, NUM_ECC_DIGITS);
	memcpy(keys + (NUM_ECC_DIGITS * 2), l_public.y, NUM_ECC_DIGITS);

	return 1;
}