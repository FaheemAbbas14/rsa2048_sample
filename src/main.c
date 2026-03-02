#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <psa/crypto.h>

#include <string.h>

#define RSA_KEY_SIZE_BITS 2048

static const char *psa_status_to_string(psa_status_t status)
{
	switch (status) {
	case PSA_SUCCESS:
		return "PSA_SUCCESS";
	case PSA_ERROR_NOT_SUPPORTED:
		return "PSA_ERROR_NOT_SUPPORTED";
	case PSA_ERROR_INVALID_ARGUMENT:
		return "PSA_ERROR_INVALID_ARGUMENT";
	case PSA_ERROR_NOT_PERMITTED:
		return "PSA_ERROR_NOT_PERMITTED";
	case PSA_ERROR_BAD_STATE:
		return "PSA_ERROR_BAD_STATE";
	case PSA_ERROR_BUFFER_TOO_SMALL:
		return "PSA_ERROR_BUFFER_TOO_SMALL";
	case PSA_ERROR_INSUFFICIENT_MEMORY:
		return "PSA_ERROR_INSUFFICIENT_MEMORY";
	case PSA_ERROR_INSUFFICIENT_STORAGE:
		return "PSA_ERROR_INSUFFICIENT_STORAGE";
	default:
		return "PSA_ERROR_UNKNOWN";
	}
}

static void print_psa_error(const char *label, psa_status_t status)
{
	printk("%s failed: %d (%s)\n", label, status, psa_status_to_string(status));
}

int main(void)
{
	psa_status_t status;
	const unsigned char plaintext[] = "Hello from nRF5340 RSA-2048 sample";
	unsigned char ciphertext[RSA_KEY_SIZE_BITS / 8];
	unsigned char decrypted[128];
	size_t ciphertext_len = 0;
	size_t decrypted_len = 0;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	printk("\n=== RSA-2048 Encrypt/Decrypt Sample ===\n");

	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		print_psa_error("psa_crypto_init", status);
		goto cleanup;
	}

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_RSA_PKCS1V15_CRYPT);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_set_key_bits(&key_attributes, RSA_KEY_SIZE_BITS);

	status = psa_generate_key(&key_attributes, &key_id);
	if (status != PSA_SUCCESS) {
		print_psa_error("psa_generate_key", status);
		goto cleanup;
	}
	psa_reset_key_attributes(&key_attributes);

	printk("RSA key pair generated: %d bits\n", RSA_KEY_SIZE_BITS);

	status = psa_asymmetric_encrypt(key_id,
					PSA_ALG_RSA_PKCS1V15_CRYPT,
					plaintext,
					sizeof(plaintext) - 1,
					NULL,
					0,
					ciphertext,
					sizeof(ciphertext),
					&ciphertext_len);
	if (status != PSA_SUCCESS) {
		print_psa_error("psa_asymmetric_encrypt", status);
		goto cleanup;
	}

	printk("Encryption success. Ciphertext length: %u bytes\n", (unsigned int)ciphertext_len);

	status = psa_asymmetric_decrypt(key_id,
					PSA_ALG_RSA_PKCS1V15_CRYPT,
					ciphertext,
					ciphertext_len,
					NULL,
					0,
					decrypted,
					sizeof(decrypted) - 1,
					&decrypted_len);
	if (status != PSA_SUCCESS) {
		print_psa_error("psa_asymmetric_decrypt", status);
		goto cleanup;
	}

	decrypted[decrypted_len] = '\0';

	printk("Decryption success. Plaintext: %s\n", decrypted);

	if (decrypted_len == sizeof(plaintext) - 1 &&
	    memcmp(decrypted, plaintext, decrypted_len) == 0) {
		printk("Result: PASS (decrypted text matches original)\n");
	} else {
		printk("Result: FAIL (decrypted text mismatch)\n");
	}

cleanup:
	psa_reset_key_attributes(&key_attributes);
	if (key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(key_id);
	}

	return 0;
}
