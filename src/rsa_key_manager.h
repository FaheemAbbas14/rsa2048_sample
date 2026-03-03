#ifndef RSA_KEY_MANAGER_H
#define RSA_KEY_MANAGER_H

#include <stddef.h>
#include <stdint.h>

#include <zephyr/autoconf.h>
#include <psa/crypto.h>

/* Derive RSA key size from enabled PSA Kconfig option. */
#define RSA_KEY_SIZE_1024_ENABLED \
	(defined(CONFIG_PSA_WANT_RSA_KEY_SIZE_1024) && CONFIG_PSA_WANT_RSA_KEY_SIZE_1024)
#define RSA_KEY_SIZE_2048_ENABLED \
	(defined(CONFIG_PSA_WANT_RSA_KEY_SIZE_2048) && CONFIG_PSA_WANT_RSA_KEY_SIZE_2048)

#if RSA_KEY_SIZE_1024_ENABLED && RSA_KEY_SIZE_2048_ENABLED
#error "Enable only one RSA key size: 1024 or 2048"
#elif RSA_KEY_SIZE_1024_ENABLED
#define RSA_KEY_SIZE_BITS 1024
#elif RSA_KEY_SIZE_2048_ENABLED
#define RSA_KEY_SIZE_BITS 2048
#else
#error "Enable CONFIG_PSA_WANT_RSA_KEY_SIZE_1024=y or CONFIG_PSA_WANT_RSA_KEY_SIZE_2048=y"
#endif

#undef RSA_KEY_SIZE_1024_ENABLED
#undef RSA_KEY_SIZE_2048_ENABLED

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
