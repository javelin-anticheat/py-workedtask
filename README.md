# py-workedtask

## Integrity verification

This repo includes optional self-integrity checks to detect basic tampering.

### C++ (Windows) executable integrity (SHA-256)

Build with `JAVELIN_EXPECTED_SHA256_HEX` set to the expected SHA-256 of the shipped `.exe`.

- The value must be exactly 64 hex characters.
- If the runtime hash doesn't match, the program exits early.

Example (MSVC):

```bat
cl /EHsc AntiCheat.cpp /DJAVELIN_EXPECTED_SHA256_HEX="\"<64-hex-sha256>\""
```

To compute the hash for a built executable (PowerShell):

```powershell
Get-FileHash .\AntiCheat.exe -Algorithm SHA256
```

### C++ (Windows) executable integrity (CRC32)

CRC32 is kept as a lightweight alternative:

```bat
cl /EHsc AntiCheat.cpp /DJAVELIN_EXPECTED_CRC32=0x12345678
```
