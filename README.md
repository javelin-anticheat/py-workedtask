# py-workedtask

## Integrity Verification

### C++ (AntiCheat.cpp)

By default, integrity verification is disabled.

Enable SHA-256 verification (preferred) by compiling with:

- JAVELIN_EXPECTED_SHA256_HEX = SHA-256 hex digest (lower/upper ok) of the built executable

Example (MSVC):

- /DJAVELIN_EXPECTED_SHA256_HEX=\"0123...<64 hex>...abcd\"

If you don't want SHA-256, you can use CRC32 instead:

- /DJAVELIN_EXPECTED_CRC32=0x12345678

On mismatch, the program exits with code 2.

### Python (integrity_check.py)

Set JAVELIN_EXPECTED_SHA256 to the SHA-256 hex digest of integrity_check.py.

Example:

- export JAVELIN_EXPECTED_SHA256=$(python3 -c "import hashlib;print(hashlib.sha256(open('integrity_check.py','rb').read()).hexdigest())")
- python3 integrity_check.py

On mismatch, the script exits with code 2.
