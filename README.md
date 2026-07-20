# py-workedtask (Javelin integrity)

Minimal anti-cheat sample with **optional integrity verification** (issue #4 / $100 bounty).

## Python: SHA-256 of the script

`javelin_integrity.py` hashes itself and compares to env var `JAVELIN_EXPECTED_SHA256`.

### Set expected hash

```bash
# Compute hash of the shipped script
python3 -c "import hashlib,pathlib; p=pathlib.Path('javelin_integrity.py'); print(hashlib.sha256(p.read_bytes()).hexdigest())"

# Run with expected value
export JAVELIN_EXPECTED_SHA256=<hex from above>
python3 javelin_integrity.py
```

- If `JAVELIN_EXPECTED_SHA256` is **unset**: check skipped (exit 0).
- If set and **matches**: exit 0.
- If set and **mismatches**: guarded exit `0xC1` (193).

### Tests

```bash
python3 -m pytest tests/test_integrity.py -q
```

## C++: CRC32 of the running executable

`AntiCheat.cpp` already computes CRC32 of the running module path.

### Set expected CRC at build time

```bash
# After building once, compute CRC of the binary and rebuild with define, e.g.:
# cl /DJAVELIN_EXPECTED_CRC32=0xAABBCCDD AntiCheat.cpp
# or g++ -DJAVELIN_EXPECTED_CRC32=0xAABBCCDD AntiCheat.cpp -o anticheat
```

- If `JAVELIN_EXPECTED_CRC32` is `0` (default): integrity check skipped.
- If non-zero and CRC mismatches: guarded exit `0xC1`.

## Files

| File | Role |
|------|------|
| `javelin_integrity.py` | Python SHA-256 integrity |
| `AntiCheat.cpp` | Windows debugger / process / CRC32 integrity |
| `tests/test_integrity.py` | Python unit tests |
