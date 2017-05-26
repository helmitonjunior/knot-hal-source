
/*FIX ME: Thing will need to access nanoecc and aes libs	*/
#include "nanoecc/ecc.h"
#include "aes/aes.h"
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

#define ECC_RETRIES	10

int encrypt(uint8_t *plaintext, size_t plaintext_len,
					uint8_t *key, unsigned char *iv)
{

	size_t i;
	uint8_t pad_value;

	/*Key Expanded Structure*/
	aes256_ctx_t ctx;

	/* Initialize AES with Key */
	aes256_init(key, &ctx);
	
	/* PKCS7 Padding for 16 bytes blocks */
	pad_value = plaintext_len % 16;
	if (pad_value > 0){
		pad_value = 16 - pad_value;
		for (i = plaintext_len; i < plaintext_len+pad_value; i++)
			plaintext[i] = pad_value;
	}

	/* Encrypt padded buffer */
	aes256_enc(plaintext, &ctx);
	if (plaintext_len > 16)
		aes256_enc(plaintext + 16, &ctx);

	return plaintext_len+pad_value;
}

int decrypt(uint8_t *ciphertext, size_t ciphertext_len,
		uint8_t *key, uint8_t *iv)
{

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
	pad_value = ciphertext[ciphertext_len-1];
	ispadded = 1;
	for (i = 1; i < pad_value; i++) {
		if (ciphertext[ciphertext_len-i] != pad_value) {
			ispadded = 0;
			return ERROR_BAD_PADDING;
		}
	}
	if (ispadded == 1) 
		for (i = 1; i <= pad_value; i++) 
			ciphertext[ciphertext_len-i] = 0x00;
	
	return ciphertext_len-pad_value;		

}

int derive_secret(uint8_t stpubx[], uint8_t stpuby[], uint8_t lcpriv[],
				uint8_t lcpubx[], uint8_t lcpuby[], uint8_t secret[],
				uint8_t *iv)
{
	uint8_t bytebuffer[NUM_ECC_DIGITS];
	EccPoint ecp;
	ecc_bytes2native (bytebuffer, stpubx);
	memcpy(ecp.x,bytebuffer,NUM_ECC_DIGITS);
	ecc_bytes2native (bytebuffer, stpuby);
	memcpy(ecp.y,bytebuffer,NUM_ECC_DIGITS);
	ecc_bytes2native (bytebuffer, lcpriv);
	memcpy(lcpriv,bytebuffer,NUM_ECC_DIGITS);
	if (ecdh_shared_secret(secret, &ecp, lcpriv, iv) == 1) {
		ecc_native2bytes (bytebuffer, secret);
		memcpy(secret, bytebuffer, NUM_ECC_DIGITS);
		return 1;
	} else {
		return ERROR_NANO_DERIVE_SKEY;
	}	
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
		return ERROR_FUNCTION_UNAVALIABLE;
}
