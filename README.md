# py-workedtask

Minimal Javelin anti-cheat guards in C++ and Python.

## C++ integrity check

`AntiCheat.cpp` computes CRC32 over the running executable. The check is optional
and is disabled when `JAVELIN_EXPECTED_CRC32` is left at its default `0u`.

Build without integrity enforcement:

```powershell
cl /EHsc AntiCheat.cpp
```

Compute the CRC32 for the executable you want to trust:

```powershell
python -c "import pathlib,zlib; p=pathlib.Path(r'.\AntiCheat.exe'); print(f'0x{zlib.crc32(p.read_bytes()) & 0xffffffff:08X}')"
```

Build with the expected CRC32 as a build-time constant:

```powershell
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

For MinGW or other GCC-compatible toolchains, use:

```powershell
g++ -std=c++17 -DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp -o AntiCheat.exe
```

If the computed CRC32 does not match the build-time value, the program exits via
the guarded integrity path.

The expected CRC must match the exact executable bytes that will run. If your
release flow embeds or patches the constant after linking, compute the final
trusted value from the same artifact that will be shipped.

## Python integrity check

`anti_cheat.py` computes SHA-256 over the script file. The check is optional and
is disabled when `JAVELIN_EXPECTED_SHA256` is unset or empty.

Compute the expected SHA-256:

```powershell
python -c "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path('anti_cheat.py').read_bytes()).hexdigest())"
```

Set the expected value for the current PowerShell session and run the guard:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = "<sha256 from previous command>"
python .\anti_cheat.py
```

If the script bytes do not match `JAVELIN_EXPECTED_SHA256`, the Python guard exits
through the integrity failure path.

## Tests

```powershell
python -m unittest
```
