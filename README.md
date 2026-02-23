# Javelin Anti‑Cheat – py‑workedtask

Minimal anti‑cheat guards for Windows, written in C++ and Python.

## Features

* **Debugger detection** – detects attached user‑mode debuggers (IsDebuggerPresent, PEB check).
* **Suspicious process scan** – looks for known cheating tools (Cheat Engine, OllyDbg, x64dbg, etc.).
* **Self‑integrity verification** – optional CRC32 or SHA‑256 hash check of the executable/script.

## C++ Version (`AntiCheat.cpp`)

Compile with any C++17 compiler (Windows only). Example using Microsoft Visual C++:

```cmd
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

Or with SHA‑256 (provide the expected hash as a hex string):

```cmd
cl /EHsc /DJAVELIN_EXPECTED_SHA256=\"a1b2c3...\" AntiCheat.cpp
```

If both CRC32 and SHA‑256 constants are provided, both checks are performed.

### Integrity verification (C++)

1. **CRC32** – define `JAVELIN_EXPECTED_CRC32` as a 32‑bit unsigned integer (e.g., `0x12345678`).  
   The executable will compute its own CRC32 and compare it with this value.

2. **SHA‑256** – define `JAVELIN_EXPECTED_SHA256` as a 64‑character hex string (lower‑ or uppercase).  
   The executable will compute its own SHA‑256 hash and compare it with this string.

If a mismatch is detected, the program exits with code `0x1CE` (same code for both CRC32 and SHA‑256 mismatch).

## Python Version (`anti_cheat.py`)

The Python module provides the same checks in a portable way (though debugger detection is Windows‑only).

### Installation

```bash
pip install psutil
```

### Usage as a module

```python
import anti_cheat

# Run all checks (returns an exit code)
exit_code = anti_cheat.run_checks()
if exit_code != 0:
    sys.exit(exit_code)
```

### Integrity verification (Python)

Set the environment variable `JAVELIN_EXPECTED_SHA256` to the expected SHA‑256 hash of the **script file** (the `anti_cheat.py` file itself). The check is performed automatically when `run_checks()` is called.

Example (bash):

```bash
export JAVELIN_EXPECTED_SHA256="a1b2c3..."
python -m anti_cheat
```

If the hash does not match, the script exits with code `0x1CE`.

### Running the tests

Tests are located in `test_anti_cheat.py` (requires `pytest` and `psutil`).  
Run them with:

```bash
pytest test_anti_cheat.py
```

## Exit codes

| Code (hex) | Meaning            |
|------------|--------------------|
| `0xDEB`    | Debugger detected  |
| `0xBAD`    | Suspicious process |
| `0x1CE`    | Integrity mismatch |

A zero exit code means all checks passed.

## License

MIT – see [LICENSE](LICENSE).