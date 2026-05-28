# py-workedtask

Javelin Project - Minimal Anti-Cheat guards for C++ and Python.

## Features

- **Debugger detection** - detects attached debuggers via IsDebuggerPresent and PEB check
- **Suspicious process scan** - scans running processes for known cheating/reverse-engineering tools
- **Self-integrity verification** - detects tampering of the executable/script via CRC32 and SHA-256

## C++ Build

### Requirements
- Windows SDK (Windows 10+)
- MSVC or Clang with crypt.lib

### Build
`cmd
cl /EHsc /O2 AntiCheat.cpp /link bcrypt.lib
`

### Integrity Check Configuration (C++)

Set the expected hash at build time via preprocessor defines:

**CRC32 (lightweight):**
`cmd
cl /EHsc /O2 /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp /link bcrypt.lib
`

**SHA-256 (stronger):**
`cmd
cl /EHsc /O2 /DJAVELIN_EXPECTED_SHA256=\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\" AntiCheat.cpp /link bcrypt.lib
`

You can use both simultaneously. The SHA-256 check runs after CRC32 if both are configured.

**Getting the expected hash value for a built executable:**

`cmd
certutil -hashfile AntiCheat.exe SHA256
`

or use the provided Python helper:
`cmd
python -c "import hashlib; print(hashlib.sha256(open('AntiCheat.exe','rb').read()).hexdigest())"
`

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All clear |
| 0xDEB (3563) | Debugger detected |
| 0xBAD (2989) | Suspicious process detected |
| 0xCRC (3276) | CRC32 mismatch |
| 0x256 (598)  | SHA-256 mismatch |

## Python Usage

### Requirements
- Python 3.7+

### Integrity Check (Python)

The Python script nti_cheat.py computes SHA-256 of itself and compares against the expected value.

`cmd
set JAVELIN_EXPECTED_SHA256=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
python anti_cheat.py
`

**Getting the expected hash:**
`cmd
python -c "import hashlib; print(hashlib.sha256(open('anti_cheat.py','rb').read()).hexdigest())"
`

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Check passed or skipped (env var not set) |
| 0x256 (598) | SHA-256 mismatch (tampering detected) |
| 1 | File read error |

## License

MIT
