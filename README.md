# RSA Encrypt/Decrypt Sample (nRF5340 + Zephyr)

---
Faheem Abbas  
Sr Software Engineer  
faheemabbas60@yahoo.com  
https://www.linkedin.com/in/faheem-abbas-5a35b029/

This sample uses PSA Crypto to create an RSA key pair (size selected via Kconfig), stores it once in LittleFS (`/lfs/rsa_keypair.bin`), loads it again on reboot, encrypts a plaintext message, decrypts it, and verifies the decrypted output matches the original plaintext.

## Code structure

- `src/main.c`: application flow only (init, invoke methods, print result)
- `src/rsa_key_manager.c/.h`: RSA key lifecycle and encrypt/decrypt methods
- `src/lfs_key_store.c/.h`: LittleFS file read/write helpers

## Build

Before configuring/building, install required Python packages in your active NCS environment:

```bash
pip install -r rsa2048_sample/requirements.txt
```

Also ensure Zephyr toolchain is available (for example Zephyr SDK installed and exported, or build from an activated nRF Connect SDK environment where toolchain variables are preconfigured).

From workspace root:

```bash
rm -rf build_rsa2048
/opt/homebrew/bin/cmake -S rsa2048_sample -B build_rsa2048 -G Ninja -DBOARD=nrf5340dk/nrf5340/cpuapp
/opt/homebrew/bin/cmake --build build_rsa2048
```

If your `west` workspace is initialized, this also works:

```bash
source ncs_venv/bin/activate
west build -s rsa2048_sample -b nrf5340dk/nrf5340/cpuapp -d build_rsa2048 --pristine=always
```

## Flash

```bash
west flash -d build_rsa2048
```

## Key size configuration

Key size is not hardcoded in source. It is selected by PSA Kconfig options in `prj.conf`:

- `CONFIG_PSA_WANT_RSA_KEY_SIZE_2048=y`
- `CONFIG_PSA_WANT_RSA_KEY_SIZE_1024=y`

Enable only one of the above at a time.

## Expected UART output

- First boot: `No saved key found. Generating new RSA key pair...`
- First boot: `Generated and stored RSA key pair at /lfs/rsa_keypair.bin`
- Reboot: `Loaded RSA key pair from /lfs/rsa_keypair.bin`
- `RSA key pair ready: <configured key size> bits`
- `Encryption success. Ciphertext length: <key_size_bits/8> bytes`
- `Decryption success. Plaintext: Hello from nRF5340 RSA`
- `Result: PASS (decrypted text matches original)`
