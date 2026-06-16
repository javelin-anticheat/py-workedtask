# py-workedtask

Minimal anti-cheat guards for the Javelin project, provided in both C++
(`AntiCheat.cpp`) and Python (`anti_cheat.py`).

## Python anti-cheat (`anti_cheat.py`)

Cross-platform (Linux/Windows), standard-library only. It runs three guards:

1. **Debugger detection** — `sys.gettrace`, `/proc/self/status` `TracerPid`
   (Linux), `IsDebuggerPresent` (Windows).
2. **Suspicious process scan** — known cheat/reversing tools.
3. **Self-integrity verification (SHA-256)** — see below.

### Self-integrity verification (SHA-256)

`anti_cheat.py` computes the **SHA-256 of its own script file** and compares it
to the value in the `JAVELIN_EXPECTED_SHA256` environment variable. If the
hashes do not match, the program performs a **guarded exit** (exit code
`0x0C8C`, surfaced as `0x8C`/140 on POSIX) instead of continuing to run
possibly-tampered code. If the variable is unset or empty, the integrity check
is skipped (it is optional, matching the build-time constant on the C++ side).

#### How to set the expected value

1. Compute the SHA-256 of the trusted, unmodified script:

   ```bash
   # Linux / macOS
   sha256sum anti_cheat.py
   # or, portably:
   python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" anti_cheat.py
   ```

   ```powershell
   # Windows (PowerShell)
   (Get-FileHash -Algorithm SHA256 .\anti_cheat.py).Hash.ToLower()
   ```

2. Export it as the expected hash, then run:

   ```bash
   export JAVELIN_EXPECTED_SHA256="<hash-from-step-1>"
   python3 anti_cheat.py
   ```

   ```powershell
   $env:JAVELIN_EXPECTED_SHA256 = "<hash-from-step-1>"
   python .\anti_cheat.py
   ```

If the script is modified after the hash is recorded, the check fails and the
program exits without continuing.

### Exit codes

| Code      | Meaning                              |
|-----------|--------------------------------------|
| `0`       | All checks passed / not configured   |
| `0xDEB`   | Debugger detected                    |
| `0xBAD`   | Suspicious process detected          |
| `0x0C8C`  | Integrity check failed (SHA-256)     |

## Tests

```bash
python3 -m pytest test_anti_cheat.py -v
# or, without pytest installed:
python3 test_anti_cheat.py
```

## C++ anti-cheat (`AntiCheat.cpp`)

The native implementation provides the same guards and supports an optional
CRC32 build-time integrity constant (`JAVELIN_EXPECTED_CRC32`).
