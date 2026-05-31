# py-workedtask

Minimal Windows anti-cheat guard with:

- debugger detection
- suspicious process detection
- CRC32 self-integrity checks
- SHA-256 self-integrity checks

## Build-time integrity configuration

The integrity checker reads the running executable with `GetModuleFileNameW`
and compares it against the expected hashes compiled into the binary.

CRC32 can be enabled with:

```powershell
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

SHA-256 can be enabled with:

```powershell
cl /EHsc /DJAVELIN_EXPECTED_SHA256=\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" AntiCheat.cpp
```

Both checks can be enabled together. Leaving both values empty or zero keeps the
integrity check disabled, which is useful while producing the first release
build before calculating its final hashes.
