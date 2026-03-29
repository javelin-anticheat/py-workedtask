# Integrity Verification

Javelin Anti-Cheat uses **SHA-256** integrity verification to ensure that task
scripts (Python) and the runtime binary (C++) have not been tampered with
before any privileged work begins.

---

## Python Script Integrity

### Overview

The `integrity` package provides a single entry-point function,
`verify_script_integrity()`, which:

1. Reads the environment variable `JAVELIN_EXPECTED_SHA256`.
2. Computes the SHA-256 digest of the running script file.
3. Compares the two values (case-insensitive hex string comparison).

On **any** mismatch or misconfiguration, `IntegrityError` is raised and
`sys.exit(1)` is called immediately, ensuring **no task work is performed on a
tampered script file**.

### Configuration

Set `JAVELIN_EXPECTED_SHA256` to the lowercase hex SHA-256 digest of the
trusted version of your script before running it:

```bash
# Compute the expected digest
export JAVELIN_EXPECTED_SHA256=$(sha256sum task_script.py | awk '{print $1}')

# Run the script
python task_script.py
```

On macOS, use `shasum -a 256` in place of `sha256sum`.

### Usage

Call `verify_script_integrity(__file__)` at the **very top** of the protected
script, before any task logic:

```python
import os
from integrity import verify_script_integrity

# Exits via sys.exit(1) on mismatch; raises IntegrityError before exiting.
verify_script_integrity(__file__)

# ... rest of task work only runs if the hash matched ...
```

`verify_script_integrity` resolves the supplied path to an absolute path before
hashing, so symlinks and relative paths are handled correctly.

### Failure behaviour

| Condition | Effect |
|-----------|--------|
| `JAVELIN_EXPECTED_SHA256` not set | `IntegrityError` raised → `sys.exit(1)` |
| Script file unreadable / missing | `IntegrityError` raised → `sys.exit(1)` |
| Hash mismatch | `IntegrityError` raised → `sys.exit(1)` |
| Hash matches | Returns `None`, execution continues normally |

> **Testing tip:** Mock `sys.exit` (e.g., with `unittest.mock.patch`) to
> prevent process termination in unit tests.  `IntegrityError` is raised
> *before* `sys.exit` is called, so you can also use `pytest.raises(IntegrityError)`
> to assert on failure paths.

### API reference

```python
from integrity import verify_script_integrity, IntegrityError

verify_script_integrity(script_path: str) -> None
```

**Parameters**

- `script_path` — path to the script to verify; pass `__file__` from the
  protected module.

**Raises**

- `IntegrityError` — on any failure (missing env var, unreadable file, hash
  mismatch).  `sys.exit(1)` is called immediately after.

---

## C++ Runtime Integrity

### Overview

The C++ integrity checks are implemented directly in the runtime (see
`AntiCheat.cpp` in this repository) rather than in a standalone public header.
That code is invoked early during process startup and, depending on build
configuration, performs either a CRC32 or SHA-256 integrity check of the
running binary against a compile-time ("baked-in") expected value.

In all configurations, the integrity check logic:

- Runs before any privileged anti-cheat work begins.
- Terminates the process immediately if the computed digest does not match the
  baked-in expected value.
- Logs a diagnostic message to the configured logger before terminating.

### Configuration

The expected hash is embedded at compile time via a preprocessor definition.
In your CMake configuration (or equivalent build system), set:

```cmake
target_compile_definitions(javelin_anticheat PRIVATE
    JAVELIN_EXPECTED_CRC32=0xDEADBEEF   # CRC32 build
    # or
    JAVELIN_EXPECTED_SHA256="<64-char hex string>"  # SHA-256 build
)
```

Refer to `AntiCheat.cpp` for the exact preprocessor symbols consumed and the
locations where the integrity check is invoked.

### Build modes

| Build mode | Hash algorithm | Symbol |
|------------|---------------|--------|
| `JAVELIN_USE_CRC32` defined | CRC32 | `JAVELIN_EXPECTED_CRC32` |
| Default / `JAVELIN_USE_SHA256` | SHA-256 | `JAVELIN_EXPECTED_SHA256` |

---

## Security notes

- **Environment variables are not secret.** `JAVELIN_EXPECTED_SHA256` should
  be treated as a tamper-detection mechanism, not an authentication secret.
  Consider distributing the expected hash out-of-band (e.g., signed manifest)
  for higher-assurance deployments.
- The Python implementation reads the script file as **bytes** before hashing,
  so line-ending differences between platforms will produce different digests.
  Always hash and distribute the script in its canonical byte form.
- For C++, the binary hash must be recomputed and the compile-time constant
  updated with every release build.
