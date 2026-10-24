# Javelin Anti-Cheat (`py-workedtask`)

Minimal Anti-Cheat guard implementations in **C++** (`AntiCheat.cpp`) and **Python** (`anticheat.py`) featuring:

- **Debugger detection** (Windows `IsDebuggerPresent` / PEB `BeingDebugged` in C++; `sys.gettrace()` in Python)
- **Suspicious process scanning** (`cheatengine.exe`, `x64dbg.exe`, `ollydbg.exe`, `ida64.exe`, `processhacker.exe`, etc.)
- **Self-Integrity Verification (CRC32 & SHA-256)** with guarded non-zero exit on hash mismatch or file tampering

---

## 1. Python Script Integrity Verification (`anticheat.py`)

`anticheat.py` computes the SHA-256 digest of the running script file and compares it in constant time (`hmac.compare_digest`) against the `JAVELIN_EXPECTED_SHA256` environment variable.

### Computing & Setting `JAVELIN_EXPECTED_SHA256`

#### Linux / macOS (Bash / Zsh)

```bash
# Compute the SHA-256 hash of anticheat.py
export JAVELIN_EXPECTED_SHA256="$(python3 anticheat.py --print-sha256)"
# Or using sha256sum:
# export JAVELIN_EXPECTED_SHA256="$(sha256sum anticheat.py | awk '{print $1}')"

# Run with integrity verification enabled
python3 anticheat.py
```

#### Windows (PowerShell)

```powershell
# Compute the SHA-256 hash and set JAVELIN_EXPECTED_SHA256
$env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash .\anticheat.py -Algorithm SHA256).Hash.ToLower()

# Run with integrity verification enabled
python .\anticheat.py
```

#### Strict Mode (Require `JAVELIN_EXPECTED_SHA256` to be set)

Set `JAVELIN_STRICT_INTEGRITY=1` or pass `--require-sha256` so execution fails closed even if `JAVELIN_EXPECTED_SHA256` is unset:

```bash
JAVELIN_STRICT_INTEGRITY=1 python3 anticheat.py
```

---

## 2. C++ Executable Integrity Verification (`AntiCheat.cpp`)

`AntiCheat.cpp` supports two optional build-time constants:

- `JAVELIN_EXPECTED_CRC32` — 32-bit unsigned integer (`0u` disables CRC32 check)
- `JAVELIN_EXPECTED_SHA256` — 64-character hexadecimal SHA-256 digest (`""` disables SHA-256 check)

### Setting Build-Time Integrity Constants

#### MSVC (Windows)

```powershell
# Compile with an expected SHA-256 or CRC32 constant
cl /std:c++17 /EHsc /O2 /DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp /Fe:AntiCheat.exe
cl /std:c++17 /EHsc /O2 /DJAVELIN_EXPECTED_SHA256="\"<64-char-sha256-hex>\"" AntiCheat.cpp /Fe:AntiCheat.exe
```

#### GCC / Clang

```bash
# Compile with an expected SHA-256 constant
g++ -std=c++17 -O2 -DJAVELIN_EXPECTED_SHA256="\"<64-char-sha256-hex>\"" AntiCheat.cpp -o anticheat

# Print the CRC32 and SHA-256 of the compiled binary or a target file
./anticheat --print-hash
./anticheat --print-hash --file ./target_binary
```

> **Note on self-hashing executables:** Embedding a new build-time constant inside the executable changes the binary's own bytes. In production pipelines, either verify a companion module/payload via `--file <path>`, store the signature in an external manifest/PE overlay excluded from the hash range, or use `JAVELIN_EXPECTED_CRC32` / `JAVELIN_EXPECTED_SHA256` against the target artifact.

---

## 3. Guarded Exit Codes

| Exit Code (Hex) | Exit Code (Dec) | Meaning |
| --- | --- | --- |
| `0x00` | `0` | All checks passed |
| `0xDE` | `222` | Debugger detected |
| `0xBA` | `186` | Suspicious process detected |
| `0xCF` | `207` | Integrity check failed (CRC32 / SHA-256 mismatch or unreadable file) |

---

## 4. Running Tests

```bash
python3 -m unittest discover -s tests -v
```
