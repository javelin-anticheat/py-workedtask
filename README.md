# py-workedtask
## Integrity verification

Optional self-integrity checks detect tampering of the shipped artifacts.

### C++ (AntiCheat.cpp)

The executable computes a CRC32 of itself at runtime and compares it against

the build-time constant JAVELIN_EXPECTED_CRC32.

1. Build once: g++ AntiCheat.cpp o anticheat

2. Compute the CRC32 of the binary, then rebuild: g++ -DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat. cpp -o anticheat A mismatch causes a guarded exit with code OxCC ( 204).

### Python (anticheat.py)

The script computes its own SHA-256 and compares it against the JAVELIN_EXPECTED_SHA256 environment variable (opt-in: skipped when unset). python3 -c "import hashlib; print(hashlib.sha256( open('anticheat.py', 'rb').read()).hexdigest())" JAVELIN_EXPECTED_SHA256=<hash> python3 anticheat.py A mismatch prints to stderr and exits with code 0xCC ( 204).

Accepts a sha256: prefix on the expected value.
