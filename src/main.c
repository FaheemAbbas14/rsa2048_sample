#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>

#include <string.h>

#define RSA_KEY_SIZE_BITS 2048
#define RSA_PUBLIC_EXPONENT 65537

static void print_mbedtls_error(const char *label, int ret)
{
	printk("%s failed: -0x%04x\n", label, -ret);
}

int main(void)
{
	int ret;
	const unsigned char plaintext[] = "Hello from nRF5340 RSA-2048 sample";
	unsigned char ciphertext[RSA_KEY_SIZE_BITS / 8];
	unsigned char decrypted[128];
	size_t ciphertext_len = 0;
	size_t decrypted_len = 0;
	const char *personalization = "rsa2048_sample";

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_pk_context keypair;

	printk("\n=== RSA-2048 Encrypt/Decrypt Sample ===\n");

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_pk_init(&keypair);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
				    mbedtls_entropy_func,
				    &entropy,
				    (const unsigned char *)personalization,
				    strlen(personalization));
	if (ret != 0) {
		print_mbedtls_error("mbedtls_ctr_drbg_seed", ret);
		goto cleanup;
	}

	ret = mbedtls_pk_setup(&keypair, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	if (ret != 0) {
		print_mbedtls_error("mbedtls_pk_setup", ret);
		goto cleanup;
	}

	ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(keypair),
				 mbedtls_ctr_drbg_random,
				 &ctr_drbg,
				 RSA_KEY_SIZE_BITS,
				 RSA_PUBLIC_EXPONENT);
	if (ret != 0) {
		print_mbedtls_error("mbedtls_rsa_gen_key", ret);
		goto cleanup;
	}

	printk("RSA key pair generated: %d bits\n", RSA_KEY_SIZE_BITS);

	ret = mbedtls_pk_encrypt(&keypair,
				 plaintext,
				 sizeof(plaintext) - 1,
				 ciphertext,
				 &ciphertext_len,
				 sizeof(ciphertext),
				 mbedtls_ctr_drbg_random,
				 &ctr_drbg);
	if (ret != 0) {
		print_mbedtls_error("mbedtls_pk_encrypt", ret);
		goto cleanup;
	}

	printk("Encryption success. Ciphertext length: %u bytes\n", (unsigned int)ciphertext_len);

	ret = mbedtls_pk_decrypt(&keypair,
				 ciphertext,
				 ciphertext_len,
				 decrypted,
				 &decrypted_len,
				 sizeof(decrypted) - 1,
				 mbedtls_ctr_drbg_random,
				 &ctr_drbg);
	if (ret != 0) {
		print_mbedtls_error("mbedtls_pk_decrypt", ret);
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
	mbedtls_pk_free(&keypair);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return 0;
}
