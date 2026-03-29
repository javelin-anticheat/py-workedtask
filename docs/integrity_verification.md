# Integrity Verification

Javelin AntiCheat performs integrity verification to ensure that neither the
Python task-runner scripts nor the C++ runtime binary have been tampered with
before work begins.

---

## Python script integrity

### How it works

At start-up the entry-point script calls `verify_script_integrity(__file__)`.
The helper computes the SHA-256 digest of the script file and compares it
against the value stored in the `JAVELIN_EXPECTED_SHA256` environment variable.
If the digests do not match the process raises `IntegrityError` and immediately
exits via `sys.exit(1)`, ensuring that **no task work is performed on a
tampered script file**.

### Configuration

| Environment variable      | Description                                                   |
|---------------------------|---------------------------------------------------------------|
| `JAVELIN_EXPECTED_SHA256` | Expected lowercase hex SHA-256 digest of the entry-point script. Leave unset to skip the check (opt-in). |

### Generating the expected digest

```bash
# Linux / macOS
sha256sum task_runner.py

# macOS alternative
shasum -a 256 task_runner.py

# Windows (PowerShell)
Get-FileHash task_runner.py -Algorithm SHA256
```

Copy the hex string into your deployment environment:

```bash
export JAVELIN_EXPECTED_SHA256=<hex-digest>
```

### Usage

Place the check at the very top of your entry-point script, before any other
application code:

```python
from integrity import verify_script_integrity

# Must be called before any task logic.
# Exits via sys.exit(1) on mismatch; returns None silently on success.
verify_script_integrity(__file__)   # exits via sys.exit(1) on mismatch

# --- rest of your script below ---
```

> **Note:** `JAVELIN_EXPECTED_SHA256` is opt-in.  When the variable is not set
> `verify_script_integrity` returns immediately without performing any check.
> This allows local development without the overhead of re-computing digests on
> every change.

### Behaviour on failure

When a mismatch is detected `verify_script_integrity` (via `_guarded_exit`):

1. Raises `integrity.IntegrityError` with a message showing both the expected
   and the actual digest.
2. Calls `sys.exit(1)` immediately after, terminating the process.

In unit tests you can mock `sys.exit` **and** catch `IntegrityError` to assert
on the failure details without the process terminating:

```python
from unittest.mock import patch
import pytest
from integrity import IntegrityError, verify_script_integrity

def test_mismatch_raises_and_exits(tmp_path):
    script = tmp_path / "runner.py"
    script.write_text("print('hello')")
    env = {"JAVELIN_EXPECTED_SHA256": "deadbeef" * 8}

    with patch("sys.exit") as mock_exit, \
         pytest.raises(IntegrityError):
        import os
        with patch.dict(os.environ, env):
            verify_script_integrity(script)

    mock_exit.assert_called_once_with(1)
```

### Error handling for unreadable files

If the script file cannot be read (e.g. wrong permissions, file deleted between
process start and the integrity check) `verify_script_integrity` will propagate
an `OSError`/`PermissionError` to the caller.  The check does **not** silently
pass for unreadable files — handle this exception at the application level as
appropriate for your deployment.

---

## C++ runtime integrity

### How it works

The C++ integrity checks are implemented directly in the runtime (see
`AntiCheat.cpp` in this repository) rather than in a standalone public header.
That code is invoked early during process startup and, depending on build
configuration, performs either a CRC32 or SHA-256 integrity check of the
running binary against a compile-time ("baked-in") expected value.

In all configurations, the integrity check logic:

- Runs before any anti-cheat scanning begins.
- Compares the digest of the running binary against the value embedded at
  compile time.
- Terminates the process immediately if the check fails, preventing tampered
  binaries from operating.

### Build configuration

The check variant is selected at compile time via preprocessor flags:

| Flag                          | Behaviour                                      |
|-------------------------------|------------------------------------------------|
| `JAVELIN_INTEGRITY_SHA256`    | Enable SHA-256 binary integrity check.         |
| `JAVELIN_INTEGRITY_CRC32`     | Enable CRC32 binary integrity check (faster).  |
| *(neither)*                   | Integrity check disabled (development builds). |

Refer to `AntiCheat.cpp` for implementation details and the exact symbols used
to embed the expected digest.

---

## Combining Python and C++ checks

For maximum protection enable both layers:

1. **C++ layer** — catches tampering of the compiled anti-cheat binary before
   it even starts.
2. **Python layer** — catches tampering of the task-runner script that drives
   work submission.

Both checks are independent and fail-fast: if either detects a mismatch the
process exits before any task work is performed.
