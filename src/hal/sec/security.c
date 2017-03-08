#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

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

#define URANDOM_PATH	"/dev/urandom"
#define ECC_RETRIES	10

size_t encrypt(uint8_t *plaintext, size_t plaintext_len,
					uint8_t *key, unsigned char *iv)
{
	#ifdef ARDUINO
	
	size_t i;
	uint8_t pad_value;

	/*Key Expanded Structure*/
	aes256_ctx_t ctx;

	/* Initialize AES with Key */
	aes256_init(key, &ctx);

	/* PKCS7 Padding for 16 bytes blocks */
	pad_value = 16 - (plaintext_len % 16);
	for(i = plaintext_len; i < plaintext_len + pad_value; i++)
		plaintext[i] = pad_value;

	/* Encrypt padded buffer */
	aes256_enc(plaintext, &ctx);
	if (plaintext_len > 16)
		aes256_enc(plaintext + 16, &ctx);

	return plaintext_len+pad_value;

	#else

	EVP_CIPHER_CTX *ctx;
	int len, ciphertext_len;
	uint8_t ciphertext[NUM_ECC_DIGITS];
	/* Create and initialize the context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		printf("Error EVP_CIPHER_CTX_new");
	/*
	 * Initialize the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
		printf("Error EVP_EncryptInit");
	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
							plaintext_len) != 1)
		printf("Error EVP_EncryptUpdate");

	ciphertext_len = len;
	/*
	 * Finalize the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
		printf("Error EVP_EncryptFinal_ex");

	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;

	#endif

}

int decrypt(uint8_t *ciphertext, size_t ciphertext_len,
		uint8_t *key, uint8_t *iv)
{

	#ifdef ARDUINO

	uint8_t i, pad_value, ispadded;
	/*Key Expanded Structure */
	aes256_ctx_t ctx;

	/* Initialize AES with Key */
	aes256_init(key, &ctx);
	
	/* Decrypt data*/
	aes256_dec(ciphertext, &ctx);
	if (ciphertext_len > 16)
		aes256_dec(ciphertext+16, &ctx);

	/* Unpadding PKCS7 */
	pad_value = ciphertext[size-1];
	ispadded = 1;
	for (i = 1; i < pad_value; i++) {
		if (ciphertext[size-i] != pad_value) {
			ispadded = 0;
			/*TO-DO: Define err number*/
			return -1;
		}
	}
	if (ispadded == 1) 
		for (i = 1; i <= pad_value; i++) 
			cdata[size-i] = 0x00;
		

	#else

	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	uint8_t plaintext[NUM_ECC_DIGITS];

	/* Create and initialize the context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		printf("Error EVP_CIPHER_CTX_new");
	/*
	 * Initialize the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
		printf("Error EVP_DecryptInit_ex");
	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
							ciphertext_len) != 1)
		printf("Error EVP_DecryptUpdate");

	plaintext_len = len;
	/*
	 * Finalize the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
		printf("Error EVP_DecriptFinal");

	plaintext_len += len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	memcpy(ciphertext, plaintext, plaintext_len);

	return plaintext_len;
}

void derive_secret(uint8_t stpubx[], uint8_t stpuby[], uint8_t lcpriv[],
			uint8_t lcpubx[], uint8_t lcpuby[], uint8_t secret[])
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
		printf("Error creating local key");

	peerecc = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (peerecc == NULL)
		printf("Error creating imported public key");

	/* Certificate sign using OPENSSL_EC_NAMED_CURVE flag */
	EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);
	EC_KEY_set_asn1_flag(peerecc, OPENSSL_EC_NAMED_CURVE);

	/* Setting public keys (local and imported) on EC_KEY */
	if (EC_KEY_set_public_key(myecc, ptlocal) != 1)
		printf("Error setting public local key");
	if (EC_KEY_set_public_key(peerecc, ptimport) != 1)
		printf("Error setting imported public key");
	/* Setting private local key on EC_KEY */
	if (EC_KEY_set_private_key(myecc, prv) != 1)
		printf("Error setting private key");

	/* Creating EVP_KEY struct to derive shared secret */
	peerkey = EVP_PKEY_new();
	/* FIXME: check peerkey? */
	if (!EVP_PKEY_assign_EC_KEY(peerkey, peerecc))
		printf("Error sign peerkey");

	pkey = EVP_PKEY_new();
	/* FIXME: check pkey? */
	if (!EVP_PKEY_assign_EC_KEY(pkey, myecc))
		printf("Error sign pkey");

	/* Generating context for shared secret derivation */
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL)
		printf("Error generating shared secret ctx");
	/* Initializing context */
	if (EVP_PKEY_derive_init(ctx) != 1)
		printf("Error initializing derivation");
	/* Setting imported public key onto derivation */
	if (EVP_PKEY_derive_set_peer(ctx, peerkey) != 1)
		printf("Error setting peer key");
	/* Dynamically allocating buffer size */
	if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0)
		printf("Error allocating buffer size");

	skey = OPENSSL_malloc(skeylen);

	/* Derive shared secret */
	if ((EVP_PKEY_derive(ctx, skey, &skeylen)) != 1)
		printf("Error deriving secret");
	/* Printing Shared Secret */
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
	#endif
}

extern void EccPoint_mult(EccPoint * p_result, EccPoint * p_point,
							uint8_t *p_scalar);

static void getRandomBytes(int randfd, void *p_dest, unsigned p_size)
{
	if (read(randfd, p_dest, p_size) != (int)p_size)
		printf("Failed to get random bytes.");
}

int generate_keys(uint8_t *keys)
{
	int randfd;
	EccPoint l_public;
	uint8_t l_private[NUM_ECC_DIGITS];
	//unsigned l_num = 1;
	int success = 0, count = 0;


	randfd = open(URANDOM_PATH, O_RDONLY);
	if (randfd == -1) {
		printf("Could not access urandom");
		return 0;
	}
	/* if make_keys fails, try renew random values and retry */
	/* FIXME: quit loop after ECC_RETRIES unsuccessful retries */
	while (!success) {
		count++;
		getRandomBytes(randfd, (char *) l_private, NUM_ECC_DIGITS *
							sizeof(uint8_t));
		success = ecc_make_key(&l_public, l_private, l_private);
		if (count > ECC_RETRIES)
			printf("Error: Cannot generate ecc key! \
						Something went wrong.\n");
	}
	memcpy(keys, l_private, NUM_ECC_DIGITS);
	memcpy(keys + NUM_ECC_DIGITS, l_public.x, NUM_ECC_DIGITS);
	memcpy(keys + (NUM_ECC_DIGITS * 2), l_public.y, NUM_ECC_DIGITS);

	return 1;
}