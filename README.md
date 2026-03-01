# Javelin Anti-Cheat

Minimal anti-cheat system with debugger detection, suspicious process scanning, and self-integrity verification using both CRC32 and SHA-256.

## Features

| Feature | C++ | Python |
|---------|-----|--------|
| Debugger detection (PEB/IsDebuggerPresent) | ✅ | — |
| Suspicious process scanning | ✅ | — |
| CRC32 self-integrity check | ✅ | — |
| **SHA-256 self-integrity check** | ✅ | ✅ |
| Tamper detection | ✅ | ✅ |
| Unit tests | — | ✅ (11 tests) |

## Quick Start

### Python (integrity_check.py)

```bash
# 1. Compute the hash of your script
python integrity_check.py --compute-hash
# Output: SHA-256 of /path/to/integrity_check.py:
#   a1b2c3d4...

# 2. Set the expected hash
export JAVELIN_EXPECTED_SHA256="a1b2c3d4..."

# 3. Run with verification enabled
python integrity_check.py
# Output: [Javelin AntiCheat] Integrity check PASSED (SHA-256: a1b2c3d4...)
```

**Programmatic usage:**

```python
from integrity_check import verify_integrity, compute_file_sha256

# Verify the current script
if not verify_integrity():
    sys.exit(1)

# Or verify any file
hash_value = compute_file_sha256("/path/to/your/binary")
```

### C++ (AntiCheat.cpp)

```bash
# 1. Compile without integrity constants (all checks run, integrity skipped)
cl /EHsc /O2 AntiCheat.cpp /Fe:anticheat.exe

# 2. Compute hashes of the compiled binary
anticheat.exe --compute-hash
# Output:
#   CRC32:  0xDEADBEEF
#   SHA-256: 0123456789abcdef...

# 3. Recompile with integrity constants baked in
cl /EHsc /O2 /DJAVELIN_EXPECTED_CRC32=0xDEADBEEF /DJAVELIN_EXPECTED_SHA256="0123456789abcdef..." AntiCheat.cpp /Fe:anticheat.exe

# 4. Run — integrity checks are now active
anticheat.exe
```

**MinGW / g++:**

```bash
g++ -O2 -o anticheat.exe AntiCheat.cpp -lkernel32
./anticheat.exe --compute-hash
# Then recompile with -DJAVELIN_EXPECTED_CRC32=... -DJAVELIN_EXPECTED_SHA256="..."
```

## How It Works

### Self-Integrity Verification

Both implementations follow the same pattern:

1. **Build/deploy time**: Compute the cryptographic hash of the file.
2. **Runtime**: Re-compute the hash and compare against the known-good value.
3. **Mismatch = tampering detected** → exit immediately.

**C++ approach**: Hashes are compiled as preprocessor constants (`-DJAVELIN_EXPECTED_SHA256="..."`).
This means the expected hash is embedded in the binary itself — any modification to the binary
changes its hash, triggering detection.

**Python approach**: Expected hash is set via the `JAVELIN_EXPECTED_SHA256` environment variable.
This allows integrity verification without modifying the script file.

### SHA-256 Implementation

The C++ SHA-256 is a **zero-dependency, header-only implementation** following RFC 6234.
No OpenSSL, no Boost, no external libraries required. This keeps the anti-cheat minimal
and avoids supply-chain attack surface.

## Testing

```bash
# Run all 11 unit tests
python -m unittest tests.test_integrity -v
```

Test coverage:
- `compute_file_sha256`: known content, empty files, large files, missing files
- `verify_integrity`: matching hash, mismatch, no env var, case insensitivity, whitespace trimming, tampered files, missing paths

## Project Structure

```
.
├── AntiCheat.cpp        # C++ anti-cheat (debugger + process + CRC32 + SHA-256)
├── integrity_check.py   # Python SHA-256 integrity verification
├── tests/
│   ├── __init__.py
│   └── test_integrity.py  # 11 unit tests
├── README.md
└── LICENSE
```

## Security Notes

- **CRC32 is not cryptographically secure** — it guards against accidental corruption.
  SHA-256 is the recommended check for tamper detection.
- The Python implementation skips verification gracefully when the environment variable
  is not set, allowing development usage without friction.
- For production deployment, always set the expected hash value.

## License

MIT — see [LICENSE](LICENSE).
