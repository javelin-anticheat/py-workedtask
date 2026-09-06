# py-workedtask

Optional integrity guards for the Windows executable and Python entry script.
Both return exit code 3 on mismatch, malformed Python baseline, or read failure.
No baseline means the corresponding check is disabled. A defined CRC32 of zero
is a valid enabled baseline. Python requires version 3.11 or newer.

## Windows C++ build

Using MinGW g++ and PowerShell:

```powershell
g++ -std=c++17 -static -DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp -o AntiCheat.exe
python seal_crc.py AntiCheat.exe 0x12345678
.\AntiCheat.exe
```

The build embeds the expected CRC32. Recompiling to insert the hash of an earlier
build changes the executable and invalidates that hash. The sealing step instead
appends a four-byte correction to the final unsigned PE executable so the CRC32
of every byte equals the compiled constant. Windows permits this overlay. Seal
only your newly built unsigned executable. Do not modify or sign it afterward.
The sealing tool rejects malformed PE headers and populated certificate tables
before writing to the file.
Rebuild and reseal after code changes. Omit the compiler definition to disable.

The C++ code retains its debugger and suspicious-process guards. MSVC-specific
PEB checks are compiled only with MSVC; other Windows compilers still use
IsDebuggerPresent. C++17 is required.

## Python script

Set the baseline from a trusted release artifact before launching it:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash .\integrity.py -Algorithm SHA256).Hash
python integrity.py
```

Pin that value in the deployment environment. Do not recompute the trusted
baseline automatically at every startup. Empty or malformed values fail closed.
To disable intentionally, remove JAVELIN_EXPECTED_SHA256 from the environment.
When embedding verify_script in another program, pass that program's __file__.
The standalone entry checks its own script, regardless of working directory.

## Verify

```powershell
python -B -m unittest -v test_integrity
```

Tests compile and execute the real Windows C++ program, verify disabled and
enabled-zero CRC configurations, reject unsealed and modified executables, and
run the Python script with absent, valid, malformed, mismatched, and tampered
baselines. Builds run in automatically removed temporary directories with
60-second compile and 10-second execution timeouts. Non-Windows hosts explicitly
skip the Windows executable test. No external dependencies or services required.

CRC32 detects accidental changes but is not protection against an adversary who
can patch the program or reseal it. A script hash likewise relies on a trusted
environment and check code. Use a trusted signature-verification boundary when
authenticity against deliberate tampering is required.
