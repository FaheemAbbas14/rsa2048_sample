#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <psa/crypto.h>

#include <string.h>

#include "rsa_key_manager.h"

/* Print PSA errors with readable status name from rsa_key_manager. */
static void print_psa_error(const char *label, psa_status_t status)
{
	printk("%s failed: %d (%s)\n", label, status, rsa_key_manager_status_string(status));
}

int main(void)
{
	/* Demo message that will be encrypted/decrypted with RSA. */
	psa_status_t status;
	const unsigned char plaintext[] = "Hello from nRF5340 RSA";
	/* RSA ciphertext size is RSA_KEY_SIZE_BITS / 8 bytes. */
	unsigned char ciphertext[RSA_KEY_SIZE_BITS / 8];
	unsigned char decrypted[128];
	size_t ciphertext_len = 0;
	size_t decrypted_len = 0;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;

	printk("\n=== RSA Encrypt/Decrypt ===\n");

	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		print_psa_error("psa_crypto_init", status);
		goto cleanup;
	}

	/* Load persisted key from LittleFS, or generate + store once. */
	status = rsa_key_manager_load_or_generate(&key_id);
	if (status != PSA_SUCCESS) {
		print_psa_error("rsa_key_manager_load_or_generate", status);
		goto cleanup;
	}

	printk("RSA key pair ready: %d bits\n", RSA_KEY_SIZE_BITS);

	status = rsa_key_manager_encrypt(key_id,
					 plaintext,
					 sizeof(plaintext) - 1,
					 ciphertext,
					 sizeof(ciphertext),
					 &ciphertext_len);
	if (status != PSA_SUCCESS) {
		print_psa_error("rsa_key_manager_encrypt", status);
		goto cleanup;
	}

	printk("Encryption success. Ciphertext length: %u bytes\n", (unsigned int)ciphertext_len);

	status = rsa_key_manager_decrypt(key_id,
					 ciphertext,
					 ciphertext_len,
					 decrypted,
					 sizeof(decrypted) - 1,
					 &decrypted_len);
	if (status != PSA_SUCCESS) {
		print_psa_error("rsa_key_manager_decrypt", status);
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
	/* Key handle is volatile and should be destroyed before exit. */
	if (key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(key_id);
	}

	return 0;
}
