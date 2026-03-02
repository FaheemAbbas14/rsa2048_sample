#include "lfs_key_store.h"

#include <zephyr/fs/fs.h>

#include <errno.h>

int lfs_key_store_write(const char *path, const uint8_t *data, size_t data_len)
{
	struct fs_file_t file;
	ssize_t written;
	int ret;

	fs_file_t_init(&file);

	ret = fs_open(&file, path, FS_O_CREATE | FS_O_WRITE | FS_O_TRUNC);
	if (ret < 0) {
		return ret;
	}

	written = fs_write(&file, data, data_len);
	if (written != (ssize_t)data_len) {
		(void)fs_close(&file);
		return -EIO;
	}

	ret = fs_close(&file);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

int lfs_key_store_read(const char *path, uint8_t *data, size_t data_size, size_t *data_len)
{
	struct fs_file_t file;
	ssize_t read_len;
	size_t total = 0;
	int ret;

	*data_len = 0;
	fs_file_t_init(&file);

	ret = fs_open(&file, path, FS_O_READ);
	if (ret < 0) {
		return ret;
	}

	while (total < data_size) {
		read_len = fs_read(&file, data + total, data_size - total);
		if (read_len < 0) {
			(void)fs_close(&file);
			return (int)read_len;
		}

		if (read_len == 0) {
			break;
		}

		total += (size_t)read_len;
	}

	if (total == data_size) {
		uint8_t extra_byte;

		read_len = fs_read(&file, &extra_byte, 1);
		if (read_len < 0) {
			(void)fs_close(&file);
			return (int)read_len;
		}

		if (read_len > 0) {
			(void)fs_close(&file);
			return -EFBIG;
		}
	}

	ret = fs_close(&file);
	if (ret < 0) {
		return ret;
	}

	*data_len = total;
	return 0;
}
