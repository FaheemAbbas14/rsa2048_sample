#ifndef LFS_KEY_STORE_H
#define LFS_KEY_STORE_H

#include <stddef.h>
#include <stdint.h>

/* Write binary data to a LittleFS file path. Returns 0 or negative errno. */
int lfs_key_store_write(const char *path, const uint8_t *data, size_t data_len);

/* Read file bytes into buffer. Returns 0 or negative errno and fills data_len. */
int lfs_key_store_read(const char *path, uint8_t *data, size_t data_size, size_t *data_len);

#endif
