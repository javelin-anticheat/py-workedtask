# py-workedtask

## Integrity verification

### Python script guard

`javelin_integrity.py` provides optional SHA-256 verification for Python
entrypoints. When `JAVELIN_EXPECTED_SHA256` is set, the guard hashes the target
script and exits if the digest does not match. When the variable is unset, the
guard is disabled.

Generate an expected hash:

```bash
python - <<'PY'
from javelin_integrity import sha256_file
print(sha256_file("your_game_entrypoint.py"))
PY
```

Run with the guard enabled:

```bash
JAVELIN_EXPECTED_SHA256=<expected-sha256> python your_game_entrypoint.py
```

Add this near the top of a Python entrypoint:

```python
from javelin_integrity import guard_script_integrity

guard_script_integrity(__file__)
```

### C++ executable guard

`AntiCheat.cpp` already includes a CRC32 self-integrity check. Embed the
expected CRC at build time; the guard exits if the running executable no longer
matches.

```bash
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```
