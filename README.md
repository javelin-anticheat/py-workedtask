# Javelin startup guards

The Windows C++ example checks for debuggers, suspicious processes, and optionally
the integrity of its **own running executable**. The Python example optionally
checks its **own script file** before continuing. An integrity mismatch, invalid
Python configuration, or read failure exits with status **3**, before application
startup. Both integrity checks are disabled by default.

## Python: SHA-256

Requires Python 3.8+ and the standard library. Compute the expected value from the
final, trusted release file, then supply it from your launch configuration:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash ./AntiCheat.py -Algorithm SHA256).Hash
python ./AntiCheat.py
```

The value must be exactly 64 hexadecimal characters; uppercase is accepted.
An unset variable disables the check. An empty or malformed value fails closed.
The script hashes `__file__`, independently of the current working directory,
and reads in 64 KiB chunks. Changes including line endings or comments change the
baseline. After an intentional update, calculate a new value from a trusted copy.
To disable the check in PowerShell: `Remove-Item Env:JAVELIN_EXPECTED_SHA256`.

Do not automatically recalculate the expected hash at every untrusted startup:
the example command provisions the baseline once, before distributing the script.
Keep the deployed baseline in a separately controlled launcher/environment.

## Windows C++: whole-executable CRC32

Requires a C++17 Windows compiler and Python 3.8+ for the build finalizer. From a
Visual Studio Developer PowerShell:

```powershell
./build.ps1 -RunTests
./build/AntiCheat.exe --verify-integrity
./build/AntiCheat.exe
```

Alternatively use a portable Zig compiler (tested with Zig 0.15.2):

```powershell
./build.ps1 -Compiler C:/tools/zig/zig.exe -RunTests
```

`build.ps1` embeds the nonzero `JAVELIN_EXPECTED_CRC32` constant (default
`0xC0DE2026`) and finalizes the just-built executable so the CRC32 of **all of its
bytes** equals that constant. `-ExpectedCrc 305419896` selects another value
(`0x12345678`). The CRC is CRC-32/ISO-HDLC, compatible with `zlib.crc32`.

Embedding a file's measured CRC into its next build would change that file and
invalidate the measurement. To avoid this circularity, the finalizer appends a
versioned trailer containing a calculated four-byte CRC correction. Nothing is
excluded from the runtime checksum, including the trailer. Finalizing the same
build twice is idempotent. Finalize only the trusted build output, before
distribution. The unfinalized intermediate deliberately fails the guard.

Equivalent manual commands with MSVC:

```powershell
New-Item -ItemType Directory -Force build
cl /nologo /EHsc /std:c++17 /O2 /DJAVELIN_EXPECTED_CRC32=0xC0DE2026u AntiCheat.cpp /Fe:build/AntiCheat.exe /Fo:build/
python tools/finalize_crc32.py build/AntiCheat.exe 0xC0DE2026
```

Omit the macro or set it to `0u` to disable the optional CRC check; no finalizer
is needed for that build. Missing/unreadable executable files fail closed when
enabled. File reads are streamed; Windows Unicode filenames are supported. The
`--verify-integrity` command exits after the same integrity guard used at normal
startup, allowing release validation without debugger/process scanning. It does
not continue to application startup.

Do not edit, repackage, or append data to the finalized executable. Those changes
invalidate the whole-file CRC. Authenticode signing also modifies the file: this
minimal whole-file scheme does not support subsequently signed executables;
a signed release needs an appropriate signature-verification design instead.

## Tests and reproducible demo

`./build.ps1 -RunTests` builds guarded, unfinalized, and disabled variants, checks
native CRC reference vectors and file errors, and runs Python subprocess tests.
The tests execute the real Windows binaries, including a Unicode filename copy
and a copy with one changed overlay byte. The latter remains a runnable PE but
must exit 3. Python tests cover matching/mutated scripts, missing files, malformed
configuration, chunk boundaries, and the disabled setting.

Python-only checks can run on any platform:

```powershell
python -m unittest discover -s tests -v
```

Native integration cases skip unless the `JAVELIN_TEST_EXE`,
`JAVELIN_TEST_UNFINALIZED_EXE`, and `JAVELIN_TEST_DISABLED_EXE` paths are supplied;
the build script supplies them automatically. Run `./demo.ps1` after building to
show the actual successful and rejected startup paths without touching the
trusted source/build files. Temporary demonstration copies are removed afterward.

## Trust limits

These are optional local integrity alarms, not a secure anti-cheat boundary.
CRC32 detects ordinary corruption but is not cryptographic; an attacker who can
patch a binary can also change its guard or recompute a CRC correction. Python's
SHA-256 check assumes the script, interpreter, and expected-hash configuration
have a trusted deployment path; an attacker controlling them can bypass it.
Use signed releases and independently enforced trust for adversarial protection.
