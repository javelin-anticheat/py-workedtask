# py-workedtask

Minimal anti-cheat guard examples for C++ and Python.

## C++ integrity check

`AntiCheat.cpp` computes CRC32 for the running executable when `JAVELIN_EXPECTED_CRC32` is set at build time. Leave it as `0` during development to disable the check.

Example MSVC build with an expected CRC32:

```bat
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

If the computed CRC does not match the build-time constant, the program exits through the guarded integrity failure path.

## Python integrity check

`AntiCheat.py` computes SHA-256 for the script file and compares it with the `JAVELIN_EXPECTED_SHA256` environment variable. Leave the variable unset during development to disable the check.

Compute the current script hash:

```bash
python -c "from pathlib import Path; from AntiCheat import sha256_file; print(sha256_file(Path('AntiCheat.py')))"
```

Run with the expected hash:

```bash
export JAVELIN_EXPECTED_SHA256=<hash-from-command-above>
python AntiCheat.py
```

On Windows PowerShell:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = '<hash-from-command-above>'
python AntiCheat.py
```

If the hash does not match, the script exits through the guarded integrity failure path with a non-zero status.
