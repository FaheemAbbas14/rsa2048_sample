cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(rsa2048_sample)

target_sources(app PRIVATE
	src/main.c
	src/rsa_key_manager.c
	src/lfs_key_store.c
)
