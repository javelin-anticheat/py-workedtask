# py-workedtask

Baseline anti-cheat guards for the Javelin Project.

## What Is Covered

- C++ client debugger detection.
- C++ client suspicious process detection.
- Optional C++ self-integrity verification using a build-time CRC32 value.
- Python monitor debugger detection.
- Python monitor suspicious process detection.
- Optional Python self-integrity verification using `JAVELIN_EXPECTED_SHA256`.

The guards fail closed: when a configured check fails, the process exits before the protected application would continue.

## Run The Python Monitor

```bash
python3 anti_cheat.py
```

To enable Python script integrity verification, compute the SHA-256 of the monitor and pass it through the environment:

```bash
export JAVELIN_EXPECTED_SHA256="$(python3 - <<'PY'
import hashlib
from pathlib import Path
print(hashlib.sha256(Path("anti_cheat.py").read_bytes()).hexdigest())
PY
)"
python3 anti_cheat.py
```

If the script changes after the hash is generated, the monitor exits with the integrity failure code.

## Build The C++ Client

Linux/macOS:

```bash
c++ -std=c++17 -Wall -Wextra -pedantic AntiCheat.cpp -o javelin-anticheat
./javelin-anticheat
```

Windows Developer Command Prompt:

```bat
cl /std:c++17 /EHsc AntiCheat.cpp /Fe:javelin-anticheat.exe
javelin-anticheat.exe
```

To enable C++ executable integrity verification, build once, calculate the CRC32 of the release executable, and rebuild with the expected value:

```bash
python3 - <<'PY'
import binascii
from pathlib import Path
print(hex(binascii.crc32(Path("javelin-anticheat").read_bytes()) & 0xffffffff))
PY
c++ -std=c++17 -DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp -o javelin-anticheat
```

Replace `0x12345678` with the CRC32 produced for your release artifact. A mismatch exits before the protected application continues.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | All checks passed |
| `0xDB` | Debugger detected |
| `0xBA` | Suspicious process detected |
| `0xC0` | Integrity verification failed |

## Tests

```bash
python3 -m unittest discover -s tests
python3 -m py_compile anti_cheat.py
c++ -std=c++17 -Wall -Wextra -pedantic AntiCheat.cpp -o /tmp/javelin-anticheat-check
/tmp/javelin-anticheat-check
git diff --check
```
