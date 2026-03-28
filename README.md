# py-workedtask

Minimal anti-cheat integrity guard examples for C++ and Python.

## C++ executable integrity

`AntiCheat.cpp` supports both CRC32 and SHA-256 checks for the running executable.

- CRC32 build-time define: `JAVELIN_EXPECTED_CRC32`
- SHA-256 build-time define: `JAVELIN_EXPECTED_SHA256`

Example (MSVC):

```powershell
cl /EHsc AntiCheat.cpp /DJAVELIN_EXPECTED_CRC32=0x12345678 /DJAVELIN_EXPECTED_SHA256=\"aabbcc...\" bcrypt.lib
```

If an expected value is provided and does not match the current executable, the program exits with a non-zero code.

## Python script integrity

`anti_cheat.py` computes SHA-256 for the script file and compares it with `JAVELIN_EXPECTED_SHA256`.

Compute hash:

```powershell
python -c "import hashlib;print(hashlib.sha256(open('anti_cheat.py','rb').read()).hexdigest())"
```

Set expected hash:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = "<64-char-hex>"
```

Run guarded script:

```powershell
python anti_cheat.py
```

If the hash mismatches or the expected hash is malformed, it exits immediately with a non-zero code.

## Tests

Run Python verification:

```powershell
python -m py_compile anti_cheat.py
python -m unittest discover -s . -p "test_*.py"
```
