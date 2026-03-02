#ifndef RSA_KEY_MANAGER_H
#define RSA_KEY_MANAGER_H

#include <stddef.h>
#include <stdint.h>

#include <psa/crypto.h>

#define RSA_KEY_SIZE_BITS 2048

const char *rsa_key_manager_status_string(psa_status_t status);
psa_status_t rsa_key_manager_load_or_generate(psa_key_id_t *key_id);
psa_status_t rsa_key_manager_encrypt(psa_key_id_t key_id,
				     const uint8_t *plaintext,
				     size_t plaintext_len,
				     uint8_t *ciphertext,
				     size_t ciphertext_size,
				     size_t *ciphertext_len);
psa_status_t rsa_key_manager_decrypt(psa_key_id_t key_id,
				     const uint8_t *ciphertext,
				     size_t ciphertext_len,
				     uint8_t *plaintext,
				     size_t plaintext_size,
				     size_t *plaintext_len);

#endif
