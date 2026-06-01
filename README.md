# py-workedtask

Minimal anti-cheat integrity guards for the Javelin Project.

## C++ Executable Integrity

`AntiCheat.cpp` supports optional CRC32 verification of the running executable.
The check is disabled when `JAVELIN_EXPECTED_CRC32` is unset or `0u`.

Build once and print the canonical CRC32 for that executable:

```bash
c++ -std=c++17 -Wall -Wextra -pedantic -Wl,--build-id=none AntiCheat.cpp -o javelin-anticheat
./javelin-anticheat --print-integrity-crc32
```

Rebuild with the printed value:

```bash
c++ -std=c++17 -Wall -Wextra -pedantic -Wl,--build-id=none \
  -DJAVELIN_EXPECTED_CRC32=0x12345678 \
  AntiCheat.cpp -o javelin-anticheat
./javelin-anticheat
```

Replace `0x12345678` with the value printed by the first build. The executable
stores that value in a fixed marker and zeros the marker value bytes before
hashing, so embedding the expected CRC does not invalidate the binary being
checked.

On mismatch, the program exits with guarded code `0xC0`.

Linux builds should disable linker build-id generation for this exact CRC flow
(`-Wl,--build-id=none`), otherwise the ELF build-id changes when the expected
CRC is embedded. Windows/MSVC builds do not use that linker note.

## Python Script Integrity

`anti_cheat.py` supports optional SHA-256 verification of the script file. The
check is disabled when `JAVELIN_EXPECTED_SHA256` is unset or empty.

Print the expected SHA-256:

```bash
python3 anti_cheat.py --print-integrity-sha256
```

Run with the expected value:

```bash
JAVELIN_EXPECTED_SHA256=<64-character-sha256> python3 anti_cheat.py
```

If the script changes after the expected hash is generated, the script exits
with guarded code `0xC0`.

## Validation

```bash
python3 -m unittest discover -s tests
python3 -m py_compile anti_cheat.py tests/test_integrity.py
c++ -std=c++17 -Wall -Wextra -pedantic -Wl,--build-id=none AntiCheat.cpp -o /tmp/javelin-anticheat
/tmp/javelin-anticheat --print-integrity-crc32
```
