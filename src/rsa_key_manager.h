#ifndef RSA_KEY_MANAGER_H
#define RSA_KEY_MANAGER_H

#include <stddef.h>
#include <stdint.h>

#include <psa/crypto.h>

/* Sample uses RSA-2048 only. */
#define RSA_KEY_SIZE_BITS 2048

/* Convert PSA status to readable constant string. */
const char *rsa_key_manager_status_string(psa_status_t status);

/* Load persisted RSA key or generate/store one if missing. */
psa_status_t rsa_key_manager_load_or_generate(psa_key_id_t *key_id);

/* Encrypt plaintext using managed RSA key (PKCS#1 v1.5). */
psa_status_t rsa_key_manager_encrypt(psa_key_id_t key_id,
				     const uint8_t *plaintext,
				     size_t plaintext_len,
				     uint8_t *ciphertext,
				     size_t ciphertext_size,
				     size_t *ciphertext_len);

/* Decrypt ciphertext using managed RSA key (PKCS#1 v1.5). */
psa_status_t rsa_key_manager_decrypt(psa_key_id_t key_id,
				     const uint8_t *ciphertext,
				     size_t ciphertext_len,
				     uint8_t *plaintext,
				     size_t plaintext_size,
				     size_t *plaintext_len);

/* Export DER-encoded public key from the current key handle. */
psa_status_t rsa_key_manager_export_public_key(psa_key_id_t key_id,
					       uint8_t *public_key,
					       size_t public_key_size,
					       size_t *public_key_len);

#endif
