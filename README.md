# Javelin Anti-Cheat (`py-workedtask`) — Integrity Verification

Implements optional self-integrity verification for both **C++** and **Python** implementations to detect binary/script tampering and perform a guarded exit on mismatch.

---

## 1. Python Implementation (`anticheat.py`)

Computes the **SHA-256** digest of the running script (`__file__`) and compares it against the `JAVELIN_EXPECTED_SHA256` environment variable.

### How to Set `JAVELIN_EXPECTED_SHA256`

1. **Print the current script SHA-256:**
   ```bash
   python anticheat.py --print-hash
   ```
2. **Set the environment variable and run:**
   - **PowerShell (Windows):**
     ```powershell
     $env:JAVELIN_EXPECTED_SHA256 = (python anticheat.py --print-hash)
     python anticheat.py
     ```
   - **Bash (Linux/macOS):**
     ```bash
     export JAVELIN_EXPECTED_SHA256=$(python3 anticheat.py --print-hash)
     python3 anticheat.py
     ```
3. **Tamper Detection Behavior:**
   If `anticheat.py` is modified or `JAVELIN_EXPECTED_SHA256` does not match, the guard exits immediately with a non-zero exit code (`stderr: [Javelin AntiCheat] Integrity check failed (SHA-256 mismatch with JAVELIN_EXPECTED_SHA256). Guarded exit.`).

---

## 2. C++ Implementation (`AntiCheat.cpp`)

Supports build-time integrity verification using either **CRC32** (`JAVELIN_EXPECTED_CRC32`) or **SHA-256** (`JAVELIN_EXPECTED_SHA256`) computed over the running executable (`GetModuleFileNameW`).

### How to Set Build-Time Constants
1. **Compile with MSVC or MinGW:**
   ```bash
   cl /EHsc AntiCheat.cpp /link Advapi32.lib
   # or with g++ (MinGW):
   g++ -O2 AntiCheat.cpp -lcrypt32 -ladvapi32 -o AntiCheat.exe
   ```
2. **Note the baseline hash:**
   ```bash
   AntiCheat.exe --print-hash
   ```
3. **Pass the expected constant at build time:**
   ```bash
   # CRC32 build-time constant:
   g++ -O2 AntiCheat.cpp -DJAVELIN_EXPECTED_CRC32=0x12345678u -ladvapi32 -o AntiCheat.exe

   # SHA-256 build-time constant:
   g++ -O2 AntiCheat.cpp -DJAVELIN_EXPECTED_SHA256="\"<64-char-hex-digest>\"" -ladvapi32 -o AntiCheat.exe
   ```
