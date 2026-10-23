# Javelin Anti-Cheat (C++ & Python Integrity Verification)

Minimal anti-cheat guards featuring debugger detection, suspicious process scanning, and optional self-integrity verification (CRC32 & SHA-256).

## Setting Expected Integrity Hashes

### 1. C++ Implementation (`AntiCheat.cpp`)
Pass `JAVELIN_EXPECTED_CRC32` or `JAVELIN_EXPECTED_SHA256` at build time:

```bash
# Compile with MSVC and embed expected SHA-256 or CRC32 constant:
cl /EHsc /O2 /DJAVELIN_EXPECTED_CRC32=0x12345678 /DJAVELIN_EXPECTED_SHA256=\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\" AntiCheat.cpp
```
If the running executable's hash does not match the build-time constant, `main()` performs a guarded exit with return code `0xCRC`.

### 2. Python Implementation (`anticheat.py`)
Compute the SHA-256 hash of `anticheat.py` and set the `JAVELIN_EXPECTED_SHA256` environment variable:

```bash
# 1. Compute SHA-256 of the script:
export JAVELIN_EXPECTED_SHA256=$(sha256sum anticheat.py | awk '{print $1}')

# 2. Run with integrity guard enabled:
python3 anticheat.py
```
If `anticheat.py` is modified or tampered with, the hash comparison fails and immediately triggers a guarded exit (`sys.exit(0xCEC)`).
