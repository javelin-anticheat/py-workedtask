# Integrity verification

## Python

1. Compute the hash of `anticheat.py` after you freeze the file:

```bash
python -c "import hashlib,pathlib; p=pathlib.Path('anticheat.py'); print(hashlib.sha256(p.read_bytes()).hexdigest())"
```

2. Set the env var before launch:

```bash
export JAVELIN_EXPECTED_SHA256=<64-char-hex>
python anticheat.py
```

3. On mismatch the process exits with code `0xA56` (2646) and does not continue.

Unset `JAVELIN_EXPECTED_SHA256` to skip the check (dev mode).

## C++ (Windows)

### CRC32 (existing)

Compile with a build-time CRC of the final `.exe`:

```text
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0xDEADBEEF AntiCheat.cpp
```

Use `0` (default) to skip CRC checks while iterating.

### SHA-256 (optional)

```text
cl /EHsc /DJAVELIN_EXPECTED_SHA256=\"<64-hex>\" AntiCheat.cpp
```

Compute the SHA-256 of the **built executable** after linking, then recompile once with that constant, or inject via your packer/CI.

Mismatch exits with code `0xA56`.

## Notes

- Hash the **artifact you ship** (script or exe), not intermediate objects.
- Recompute after every intentional release; CI should fail if constants go stale.
