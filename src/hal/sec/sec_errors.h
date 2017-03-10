/*
 * Copyright (c) 2017, CESAR.
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license. See the LICENSE file for details.
 *
 */
#ifdef __cplusplus
extern "C" {
#endif

#define	ERROR_EVP_CIPHER_CTX_NEW	-1 /* Error creating context */
#define ERROR_EVP_ENC_INIT			-2 /* Error initializing encrypt function*/
#define ERROR_EVP_ENC_UPDATE		-3 /* Error updating encrypt function*/
#define ERROR_EVP_ENC_FINAL			-4 /* Error finilizing encrypt function*/
#define ERROR_EVP_DEC_INIT			-5 /* Error initializing decrypt function*/
#define ERROR_EVP_DEC_UPDATE		-6 /* Error updating decrypt function*/
#define ERROR_EVP_DEC_FINAL			-7 /* Error finilizing decrypt function*/
#define ERROR_ECC_LOC_PKEY_CURVE 	-8 /* Error creating local public key by curve name*/
#define ERROR_ECC_PEER_PKEY_CURVE 	-9 /* Error creating peer public key by curve name*/
#define ERROR_ECC_SET_LOC_PKEY		-10 /* Error setting local public key */
#define ERROR_ECC_SET_PEER_PKEY		-11 /* Error setting peer public key */
#define ERROR_ECC_SET_PRIV_KEY		-12 /* Error setting private key */
#define ERROR_EVP_ASSIGN_PEER		-13 /* Error assigning peer key */
#define ERROR_EVP_ASSIGN_KEY		-14 /* Error assigning private key */
#define ERROR_EVP_DERIVE_INIT		-15 /* Error initializing context derivation */
#define ERROR_EVP_DERIVE_SET_PEER	-16 /* Error setting peer key to context */
#define ERROR_EVP_DERIVE_ALLOC		-17 /* Error allocating derivation buffer */
#define ERROR_EVP_DERIVE 			-18 /* Error derivating key */
#define ERROR_GET_RANDOM			-19 /* Error getting random bytes*/
#define ERROR_ACCESS_URANDOM		-20 /* Cannot access urandom */
#define ERROR_ECC_MK_KEYS			-21 /* Error generating key pair */

#ifdef __cplusplus
}
#endif
