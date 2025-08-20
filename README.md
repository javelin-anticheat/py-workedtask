# py-workedtask

Integrity verification feature for Javelin examples (C++ and Python).

## C++ executable integrity (CRC32 or SHA-256)

The C++ sample (`AntiCheat.cpp`) can verify the integrity of the running executable using either:

- SHA-256 (preferred): define `JAVELIN_EXPECTED_SHA256_STR` as a 64-char hex string at build time.
- CRC32 (fallback): define `JAVELIN_EXPECTED_CRC32` as a 32-bit hex value at build time.

Behavior:

- If `JAVELIN_EXPECTED_SHA256_STR` is non-empty, SHA-256 is used.
- Else, if `JAVELIN_EXPECTED_CRC32 != 0`, CRC32 is used.
- On mismatch, the program exits with a non-zero code.

If SHA-256 is requested but the build environment lacks bcrypt (Bcrypt.lib/bcrypt.h), the program will automatically fall back to CRC32 only if `JAVELIN_EXPECTED_CRC32` is also defined; otherwise it skips integrity check with a warning.

Build-time defines (examples):

- MSVC (Developer Command Prompt):
	- Define SHA-256: add `/D JAVELIN_EXPECTED_SHA256_STR=\"<64-hex>\"`
	- Define CRC32: add `/D JAVELIN_EXPECTED_CRC32=0x12345678`

Notes:

- The code uses Windows CNG (Bcrypt) for SHA-256 and links `Bcrypt.lib`.
- Suspicious process and debugger checks still apply.

## Python script integrity (SHA-256)

`integrity_check.py` verifies its own script file hash against the environment variable `JAVELIN_EXPECTED_SHA256`.

Usage:

1) Compute the expected SHA-256 of the file you will deploy:
	- On Python: `python - <<PY\nimport hashlib, sys; print(hashlib.sha256(open('integrity_check.py','rb').read()).hexdigest())\nPY`

2) Set the environment variable before running:
	- PowerShell: `$env:JAVELIN_EXPECTED_SHA256 = "<64-hex>"`
	- CMD: `set JAVELIN_EXPECTED_SHA256=<64-hex>`
	- Bash (Git Bash): `export JAVELIN_EXPECTED_SHA256=<64-hex>`

3) Run the script. A mismatch exits with code 0x05A6.

## Verifying expected hash values

For C++ SHA-256:

1) Build the executable once without `JAVELIN_EXPECTED_SHA256_STR`.
2) Compute the SHA-256 of the produced .exe (use `certutil -hashfile app.exe SHA256` or Python as above).
3) Rebuild with `/D JAVELIN_EXPECTED_SHA256_STR=\"<64-hex>\"`.

For C++ CRC32:

1) Build once, compute CRC32 of the exe (you can add a small tool or rely on the program's logged CRC temporarily).
2) Rebuild with `/D JAVELIN_EXPECTED_CRC32=0xXXXXXXXX`.

Return codes (selected):

- 0x0DEB: debugger detected
- 0x0BAD: suspicious process detected
- 0x0C1C: integrity failed (CRC32)
- 0x05A6: integrity failed (SHA-256 and Python)
