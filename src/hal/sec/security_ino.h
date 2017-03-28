#include <stdio.h>
#include <stdlib.h>

/*FIX ME: Thing will need to access nanoecc and aes libs	*/
#include "sec/nanoecc/ecc.h"
#include "sec/aes/aes.h"

#ifdef __cplusplus
extern "C"{
#endif

#define secp128r1	16
#define secp192r1	24
#define secp256r1	32
#define secp384r1	48
#define ECC_CURVE	secp256r1

#if (ECC_CURVE != secp192r1 && ECC_CURVE != secp256r1 \
	&& ECC_CURVE != secp384r1)
	#error "ERROR_CURVE_NOT_DEFINED"
#endif

#define NUM_ECC_DIGITS ECC_CURVE

int encrypt(uint8_t *plaintext, size_t plaintext_len,
			uint8_t *key, uint8_t *iv);
int decrypt(uint8_t *ciphertext, size_t ciphertext_len,
			uint8_t *key, uint8_t *iv);
int derive_secret(uint8_t stpx[],uint8_t stpy[], uint8_t lcpriv[],
			uint8_t lcpx[], uint8_t lcpy[], uint8_t secret[], uint8_t *iv);
/*Generating keys on arduino not avaliable in this version*/
int generate_keys(uint8_t *keys);

#ifdef __cplusplus
} // extern "C"
#endif