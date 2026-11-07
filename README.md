# py-workedtask

Minimal Javelin anti-cheat examples for C++ and Python.

## Python integrity verification

The Python guard can optionally verify that `anti_cheat.py` has not been
tampered with. The check is disabled by default and becomes active when the
`JAVELIN_EXPECTED_SHA256` environment variable is set.

Generate the expected hash:

```bash
python3 - <<'PY'
from pathlib import Path
import hashlib
print(hashlib.sha256(Path("anti_cheat.py").read_bytes()).hexdigest())
PY
```

Run with the expected hash:

```bash
export JAVELIN_EXPECTED_SHA256=<sha256-from-command-above>
python3 anti_cheat.py
```

If the file contents do not match the expected hash, the process exits with a
guarded failure code and prints an integrity failure message.

## C++ integrity verification

`AntiCheat.cpp` supports an optional build-time CRC32 check of the running
executable. Leave `JAVELIN_EXPECTED_CRC32` as `0` to disable the check while
developing. Set it at compile time when shipping a known-good build.

Example MSVC build flag:

```powershell
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

When the computed CRC32 of the running executable does not match the expected
value, the guard exits before continuing.
