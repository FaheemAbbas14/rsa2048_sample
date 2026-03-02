# RSA-2048 Encrypt/Decrypt Sample (nRF5340 + Zephyr)

This sample creates an RSA-2048 key pair at runtime, encrypts a plaintext message, decrypts it, and verifies the decrypted output matches the original plaintext.

## Build

From workspace root:

```bash
rm -rf build_rsa2048
/opt/homebrew/bin/cmake -S rsa2048_sample -B build_rsa2048 -G Ninja -DBOARD=bl5340_dvk/nrf5340/cpuapp
/opt/homebrew/bin/cmake --build build_rsa2048
```

If your `west` workspace is initialized, this also works:

```bash
source ncs_venv/bin/activate
west build -s rsa2048_sample -b bl5340_dvk/nrf5340/cpuapp -d build_rsa2048 --pristine=always
```

## Flash

```bash
west flash -d build_rsa2048
```

## Expected UART output

- `RSA key pair generated: 2048 bits`
- `Encryption success. Ciphertext length: 256 bytes`
- `Decryption success. Plaintext: Hello from nRF5340 RSA-2048 sample`
- `Result: PASS (decrypted text matches original)`
