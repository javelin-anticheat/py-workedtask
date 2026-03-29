# Integrity Verification

This document explains how to configure and use the optional integrity
verification feature for both the **Python** and **C++** implementations.

---

## Python — SHA-256 of Script File

### How it works

At startup the module computes a SHA-256 digest of the **script file itself**
(i.e. `__file__` resolved to an absolute path) and compares it against the
value stored in the environment variable `JAVELIN_EXPECTED_SHA256`.

If the digests do not match (or the env-var is absent and strict mode is
enabled), the process exits immediately via the guarded-exit helper so that
**no task work is performed on a tampered binary**.

### Generating the expected hash

```bash
# Linux / macOS
sha256sum path/to/your_script.py

# macOS (alternative)
shasum -a 256 path/to/your_script.py

# Windows (PowerShell)
Get-FileHash path\to\your_script.py -Algorithm SHA256
```

Copy the hex digest (64 characters) that is printed.

### Setting the environment variable

```bash
# Linux / macOS — one-shot
export JAVELIN_EXPECTED_SHA256="<paste-digest-here>"
python your_script.py

# Windows CMD
set JAVELIN_EXPECTED_SHA256=<paste-digest-here>
python your_script.py

# Windows PowerShell
$env:JAVELIN_EXPECTED_SHA256 = "<paste-digest-here>"
python your_script.py
```

You can also persist it in a `.env` file (never commit this file):

```
JAVELIN_EXPECTED_SHA256=abcdef0123456789...
```

### Usage in code

```python
# At the very top of your script, before any other logic:
from integrity import verify_script_integrity

verify_script_integrity(__file__)   # raises IntegrityError / exits on mismatch
```

Optional keyword arguments:

| Argument | Type | Default | Description |
|---|---|---|---|
| `strict` | `bool` | `False` | When `True`, exit even if the env-var is **not set** (treats "no expected value" as a mismatch). |
| `env_var` | `str` | `"JAVELIN_EXPECTED_SHA256"` | Override the env-var name. |

### Exit behaviour

A non-matching hash calls `sys.exit(1)` after printing a short tamper-warning
to `stderr`.  The same code path is used when `strict=True` and the env-var is
absent.

---

## C++ — CRC32 / SHA-256 of Running Executable

### How it works

`integrity/integrity.hpp` provides two free functions:

| Function | Algorithm | Use when… |
|---|---|---|
| `javelin::verify_crc32(expected)` | CRC32 | Fast, minimal code-size overhead |
| `javelin::verify_sha256(expected)` | SHA-256 (pure C++ / OpenSSL) | Higher collision resistance |

Both functions:
1. Resolve the path of the **currently running executable** (`/proc/self/exe`
   on Linux, `GetModuleFileName` on Windows, `_NSGetExecutablePath` on macOS).
2. Compute the chosen digest over the entire file.
3. Compare it (constant-time) to the `expected` string you baked in at
   build time.
4. Call `std::exit(1)` on mismatch after printing a warning to `stderr`.

### Generating the expected hash

```bash
# CRC32  (requires 'crc32' utility, part of libarchive-zip-perl or zlib)
crc32 ./your_binary          # prints an 8-char hex value

# SHA-256
sha256sum ./your_binary      # prints a 64-char hex value
```

On Windows (PowerShell):

```powershell
# SHA-256
(Get-FileHash .\your_binary.exe -Algorithm SHA256).Hash.ToLower()
```

### Embedding the expected hash

The expected value is a **build-time constant** defined *before* including the
header (or via a compiler `-D` flag):

```cpp
// Option A — define before include
#define JAVELIN_EXPECTED_CRC32  "a1b2c3d4"
#define JAVELIN_EXPECTED_SHA256 "abcdef0123456789..."
#include "integrity/integrity.hpp"

// Option B — pass via CMake / compiler flag
// cmake -DJAVELIN_EXPECTED_SHA256="abcdef..." .
// In CMakeLists.txt:
//   target_compile_definitions(my_target PRIVATE
//       JAVELIN_EXPECTED_SHA256="${JAVELIN_EXPECTED_SHA256}")
```

### Usage in code

```cpp
#include "integrity/integrity.hpp"

int main() {
    // Check CRC32 (fast)
    javelin::verify_crc32(JAVELIN_EXPECTED_CRC32);

    // — or — check SHA-256 (stronger)
    javelin::verify_sha256(JAVELIN_EXPECTED_SHA256);

    // ... rest of your program
}
```

### Platform notes

| Platform | Executable path API |
|---|---|
| Linux | `/proc/self/exe` (symlink) |
| macOS | `_NSGetExecutablePath` |
| Windows | `GetModuleFileNameA` |

The SHA-256 implementation shipped in `integrity.hpp` is a self-contained
pure-C++ version (no external dependencies).  If you prefer OpenSSL, define
`JAVELIN_USE_OPENSSL` before including the header.

---

## Security notes

* The hash comparison uses a **constant-time** comparison (`std::equal` with
  a fixed-length loop in C++; `hmac.compare_digest` in Python) to prevent
  timing side-channels.
* The expected hash should be treated as a **secret build artifact** — do not
  commit it in plaintext to a public repository.
* This feature is a *defence-in-depth* measure.  A determined attacker with
  write access to the binary can also patch the embedded constant; combine
  this with code-signing for stronger guarantees.
