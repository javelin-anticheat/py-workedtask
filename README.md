# py-workedtask

This repository provides minimal Anti-Cheat guards for Windows (C++) and an optional Python integrity helper.

Features:
- Debugger detection and suspicious process scan (C++)
- Optional self-integrity verification of the running executable via CRC32 or SHA-256 (C++)
- Optional integrity verification of a Python script via SHA-256 (Python helper)

C++ build and integrity configuration:
- Build normally on Windows with a C++17-capable compiler.
- You can embed an expected executable hash at build time.
  - Prefer SHA-256:
    - Example (MSVC): cl /std:c++17 AntiCheat.cpp /DJAVELIN_EXPECTED_SHA256=\"<sha256-hex>\"
    - Example (MinGW): g++ -std=c++17 AntiCheat.cpp -o anticheat.exe -DJAVELIN_EXPECTED_SHA256=\"<sha256-hex>\"
  - Or CRC32 (legacy):
    - Example (MSVC): cl /std:c++17 AntiCheat.cpp /DJAVELIN_EXPECTED_CRC32=0x12345678
    - Example (MinGW): g++ -std=c++17 AntiCheat.cpp -o anticheat.exe -DJAVELIN_EXPECTED_CRC32=0x12345678
- On mismatch, the binary exits with code 0x1C7 and prints an integrity failure message.

To compute the executable SHA-256 after building:
- PowerShell: Get-FileHash .\\anticheat.exe -Algorithm SHA256 | Select-Object -ExpandProperty Hash | ForEach-Object { $_.ToLower() }
- Python: python - <<PY\nimport hashlib,sys; d=hashlib.sha256(open('anticheat.exe','rb').read()).hexdigest(); print(d)\nPY

Python integrity helper usage:
- The helper computes SHA-256 of its own file and enforces it only when JAVELIN_EXPECTED_SHA256 is set.
- Set the expected hash in the environment:
  - Linux/macOS: export JAVELIN_EXPECTED_SHA256=$(sha256sum py_integrity_guard.py | awk '{print $1}')
  - Windows PowerShell: $env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash .\\py_integrity_guard.py -Algorithm SHA256).Hash.ToLower()
- Run: python py_integrity_guard.py
- On mismatch, the script exits with code 0x1C7 and prints an integrity failure message.

Notes:
- Integrity checks are optional and only enforced when an expected value is configured (non-empty for SHA-256, non-zero for CRC32).
- The C++ path prefers SHA-256 when both are provided.
