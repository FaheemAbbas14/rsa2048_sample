#include "rsa_key_manager.h"

#include "lfs_key_store.h"

#include <zephyr/sys/printk.h>

#include <errno.h>
#include <string.h>

#define KEY_FILE_PATH "/lfs/rsa_keypair.bin"
#define KEY_FILE_MAGIC 0x52534132U
#define KEY_BLOB_MAX_SIZE 4096

/*
 * File format stored in LittleFS:
 * [key_file_header][raw PSA-exported private key blob]
 */
struct key_file_header {
	uint32_t magic;
	uint32_t key_blob_len;
};

/* Convert common PSA status codes to readable strings for logs. */
const char *rsa_key_manager_status_string(psa_status_t status)
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
	case PSA_ERROR_DOES_NOT_EXIST:
		return "PSA_ERROR_DOES_NOT_EXIST";
	default:
		return "PSA_ERROR_UNKNOWN";
	}
}

/*
 * Persist a private key blob in LittleFS using a tiny header
 * so we can validate content on reboot.
 */
static int write_key_blob_to_file(const uint8_t *key_blob, size_t key_blob_len)
{
	uint8_t file_data[sizeof(struct key_file_header) + KEY_BLOB_MAX_SIZE];
	struct key_file_header header = {
		.magic = KEY_FILE_MAGIC,
		.key_blob_len = (uint32_t)key_blob_len,
	};

	if (key_blob_len > KEY_BLOB_MAX_SIZE) {
		return -EINVAL;
	}

	(void)memcpy(file_data, &header, sizeof(header));
	(void)memcpy(file_data + sizeof(header), key_blob, key_blob_len);

	return lfs_key_store_write(KEY_FILE_PATH, file_data, sizeof(header) + key_blob_len);
}

/*
 * Load and validate a private key blob from LittleFS.
 * Returns standard negative errno values on file/format errors.
 */
static int read_key_blob_from_file(uint8_t *key_blob, size_t key_blob_size, size_t *key_blob_len)
{
	uint8_t file_data[sizeof(struct key_file_header) + KEY_BLOB_MAX_SIZE];
	struct key_file_header header;
	size_t file_len;
	int ret;

	if (key_blob_size < KEY_BLOB_MAX_SIZE) {
		return -EINVAL;
	}

	ret = lfs_key_store_read(KEY_FILE_PATH, file_data, sizeof(file_data), &file_len);
	if (ret < 0) {
		return ret;
	}

	if (file_len < sizeof(header)) {
		return -EIO;
	}

	(void)memcpy(&header, file_data, sizeof(header));

	if (header.magic != KEY_FILE_MAGIC ||
	    header.key_blob_len == 0U ||
	    header.key_blob_len > KEY_BLOB_MAX_SIZE ||
	    file_len != sizeof(header) + header.key_blob_len) {
		return -EINVAL;
	}

	(void)memcpy(key_blob, file_data + sizeof(header), header.key_blob_len);
	*key_blob_len = header.key_blob_len;
	return 0;
}

/*
 * Import a previously saved private key into PSA as a volatile key handle.
 * This is used at startup so the key can be used by crypto APIs immediately.
 */
static psa_status_t import_saved_key(psa_key_id_t *key_id)
{
	psa_status_t status;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t key_blob[KEY_BLOB_MAX_SIZE];
	size_t key_blob_len = 0;
	int ret;

	ret = read_key_blob_from_file(key_blob, sizeof(key_blob), &key_blob_len);
	if (ret == -ENOENT) {
		return PSA_ERROR_DOES_NOT_EXIST;
	}

	if (ret < 0) {
		printk("Failed reading key file (%d)\n", ret);
		return PSA_ERROR_GENERIC_ERROR;
	}

	psa_set_key_usage_flags(&key_attributes,
				PSA_KEY_USAGE_ENCRYPT |
				PSA_KEY_USAGE_DECRYPT |
				PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_RSA_PKCS1V15_CRYPT);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_set_key_bits(&key_attributes, RSA_KEY_SIZE_BITS);

	status = psa_import_key(&key_attributes, key_blob, key_blob_len, key_id);
	psa_reset_key_attributes(&key_attributes);
	(void)memset(key_blob, 0, sizeof(key_blob));

	return status;
}

/*
 * One-time generation path:
 * 1) generate RSA key pair,
 * 2) export private key blob,
 * 3) save it to LittleFS,
 * 4) re-import as a runtime key handle.
 */
static psa_status_t generate_and_store_key(psa_key_id_t *key_id)
{
	psa_status_t status;
	psa_key_attributes_t gen_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_attributes_t import_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t generated_key_id = PSA_KEY_ID_NULL;
	uint8_t key_blob[KEY_BLOB_MAX_SIZE];
	size_t key_blob_len = 0;
	int ret;

	psa_set_key_usage_flags(&gen_attributes,
				PSA_KEY_USAGE_ENCRYPT |
				PSA_KEY_USAGE_DECRYPT |
				PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&gen_attributes, PSA_ALG_RSA_PKCS1V15_CRYPT);
	psa_set_key_type(&gen_attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_set_key_bits(&gen_attributes, RSA_KEY_SIZE_BITS);

	status = psa_generate_key(&gen_attributes, &generated_key_id);
	psa_reset_key_attributes(&gen_attributes);
	if (status != PSA_SUCCESS) {
		(void)memset(key_blob, 0, sizeof(key_blob));
		return status;
	}

	status = psa_export_key(generated_key_id, key_blob, sizeof(key_blob), &key_blob_len);
	if (status != PSA_SUCCESS) {
		(void)psa_destroy_key(generated_key_id);
		(void)memset(key_blob, 0, sizeof(key_blob));
		return status;
	}

	ret = write_key_blob_to_file(key_blob, key_blob_len);
	if (ret < 0) {
		(void)psa_destroy_key(generated_key_id);
		(void)memset(key_blob, 0, sizeof(key_blob));
		printk("Failed writing key file (%d)\n", ret);
		return PSA_ERROR_GENERIC_ERROR;
	}

	(void)psa_destroy_key(generated_key_id);

	psa_set_key_usage_flags(&import_attributes,
				PSA_KEY_USAGE_ENCRYPT |
				PSA_KEY_USAGE_DECRYPT |
				PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&import_attributes, PSA_ALG_RSA_PKCS1V15_CRYPT);
	psa_set_key_type(&import_attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_set_key_bits(&import_attributes, RSA_KEY_SIZE_BITS);

	status = psa_import_key(&import_attributes, key_blob, key_blob_len, key_id);
	psa_reset_key_attributes(&import_attributes);
	(void)memset(key_blob, 0, sizeof(key_blob));

	return status;
}

/*
 * Public entry point used by main flow:
 * - load key from storage if present,
 * - otherwise generate and persist it.
 */
psa_status_t rsa_key_manager_load_or_generate(psa_key_id_t *key_id)
{
	psa_status_t status;

	status = import_saved_key(key_id);
	if (status == PSA_SUCCESS) {
		printk("Loaded RSA key pair from %s\n", KEY_FILE_PATH);
		return PSA_SUCCESS;
	}

	if (status != PSA_ERROR_DOES_NOT_EXIST) {
		printk("import_saved_key failed: %d (%s)\n", status, rsa_key_manager_status_string(status));
		return status;
	}

	printk("No saved key found. Generating new RSA-2048 key pair...\n");
	status = generate_and_store_key(key_id);
	if (status != PSA_SUCCESS) {
		return status;
	}

	printk("Generated and stored RSA key pair at %s\n", KEY_FILE_PATH);
	return PSA_SUCCESS;
}

/* Encrypt with the managed RSA key (PKCS#1 v1.5). */
psa_status_t rsa_key_manager_encrypt(psa_key_id_t key_id,
				     const uint8_t *plaintext,
				     size_t plaintext_len,
				     uint8_t *ciphertext,
				     size_t ciphertext_size,
				     size_t *ciphertext_len)
{
	return psa_asymmetric_encrypt(key_id,
				     PSA_ALG_RSA_PKCS1V15_CRYPT,
				     plaintext,
				     plaintext_len,
				     NULL,
				     0,
				     ciphertext,
				     ciphertext_size,
				     ciphertext_len);
}

/* Decrypt with the managed RSA key (PKCS#1 v1.5). */
psa_status_t rsa_key_manager_decrypt(psa_key_id_t key_id,
				     const uint8_t *ciphertext,
				     size_t ciphertext_len,
				     uint8_t *plaintext,
				     size_t plaintext_size,
				     size_t *plaintext_len)
{
	return psa_asymmetric_decrypt(key_id,
				     PSA_ALG_RSA_PKCS1V15_CRYPT,
				     ciphertext,
				     ciphertext_len,
				     NULL,
				     0,
				     plaintext,
				     plaintext_size,
				     plaintext_len);
}

/* Export DER-encoded RSA public key from the current key handle. */
psa_status_t rsa_key_manager_export_public_key(psa_key_id_t key_id,
					       uint8_t *public_key,
					       size_t public_key_size,
					       size_t *public_key_len)
{
	return psa_export_public_key(key_id, public_key, public_key_size, public_key_len);
}
