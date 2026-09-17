# py-workedtask

Optional integrity checks for the Javelin Windows executable and Python script.
Any configured malformed, unreadable or mismatched baseline stops the program
with exit code **3**, before continuing to application checks.

## Python (3.11 or newer)

`AntiCheat.py` hashes its own script file, including its exact line endings, using
SHA-256. With `JAVELIN_EXPECTED_SHA256` absent, verification is disabled. An empty
value is an error, not an instruction to disable checking. The value must contain
exactly 64 hexadecimal characters (either case), with no whitespace.

PowerShell:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash .\AntiCheat.py -Algorithm SHA256).Hash
python .\AntiCheat.py
$LASTEXITCODE # 0
```

POSIX shell:

```sh
export JAVELIN_EXPECTED_SHA256="$(python -c 'import hashlib; print(hashlib.sha256(open("AntiCheat.py", "rb").read()).hexdigest())')"
python AntiCheat.py
```

Set the expected digest from a trusted copy during packaging/deployment. Keep it
outside the script; do not recalculate it from an untrusted file on every start.
Editing the script after computing this value makes its next run fail.

## C++ (Windows, MSVC, C++17)

`JAVELIN_EXPECTED_CRC32` is an optional **build-time** unsigned 32-bit constant.
When omitted, verification is disabled. Defining it to zero enables verification
against CRC32 zero. The guard streams the **entire running executable on disk**,
including its headers, sections and overlay, rather than a file in the current
working directory. Read errors fail closed.

In an x64 or x86 Visual Studio Developer Command Prompt:

```bat
cl /nologo /EHsc /std:c++17 /O2 /W4 /DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp /Fe:AntiCheat.exe
python tools\seal_crc32.py AntiCheat.exe 0x12345678
AntiCheat.exe --check-integrity
echo %ERRORLEVEL%
```

Use the same value in both commands. The sealing tool appends four correction
bytes so the CRC32 of the complete final executable equals the compiled constant.
This avoids a circular dependency: hashing one build and then recompiling its
hash into the next build would change the bytes being checked. Running the seal
again with the same target is a no-op. Rebuild and reseal after changing code.

The tool validates PE32/PE32+ headers and refuses signed or malformed input before
modifying the executable. It writes atomically and preserves the executable's
mode. This workflow supports **unsigned executables**. Signing after sealing
changes the hash, and sealing an already signed executable is refused.

`--check-integrity` runs the same startup integrity guard and then exits, without
running the unrelated debugger/process checks. Running without that flag performs
the integrity guard followed by the existing checks. A changed or unsealed binary
with verification enabled returns 3 and prints an integrity error.

CRC32 detects accidental changes; it does **not** establish cryptographic
authenticity or prevent an attacker from resealing a modified binary. Neither a
checksum embedded in an executable nor a script-controlled environment can resist
an attacker who can replace both the guard and its trusted baseline. The checks
also do not measure in-memory changes after startup.

## Tests

No third-party Python packages are required:

```sh
python -m unittest discover -s tests -v
```

The portable suite covers SHA-256 matching/mismatch, malformed and absent values,
file read failures, entry-point exits, raw bytes, the CRC correction algorithm,
PE validation, atomic-write failure and repeated sealing.

In a Visual Studio Developer Command Prompt, require native tests as well:

```bat
set REQUIRE_NATIVE=1
python -m unittest discover -s tests -v
```

Run once in an x64 developer prompt and once in an x86 prompt. Native tests compile
the actual program with `/O2 /W4 /WX`, with checks disabled and with zero/nonzero
constants. They execute the produced programs before and after sealing, modify
the final bytes, and check nonzero exits and Unicode executable paths. Without
MSVC, the native class is skipped unless `REQUIRE_NATIVE=1`; that setting turns a
missing compiler into a test failure. `CXX` may specify an absolute `cl.exe` path.
