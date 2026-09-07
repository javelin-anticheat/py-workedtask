# py-workedtask

Minimal Windows anti-cheat guards, plus an optional file-integrity check for
the Python script. Integrity failures exit with code **3**. No external Python
packages are needed (Python 3.8+).

## Python: SHA-256 of the script

`AntiCheat.py` is an integrity-only Python entry point; it does not enumerate
processes or implement the C++ debugger checks. With `JAVELIN_EXPECTED_SHA256`
unset, the integrity check is disabled. When set, it must contain exactly 64
hexadecimal characters (upper or lower case). An empty/malformed value, an
unreadable script, or a mismatch causes a guarded exit before continuing.

Create the baseline from the trusted, final script, then set it in the launch
environment. For example, in PowerShell:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath .\AntiCheat.py).Hash
python .\AntiCheat.py
# After changing the script without updating the trusted baseline: exit code 3.
Remove-Item Env:JAVELIN_EXPECTED_SHA256  # disable the optional check
```

For a POSIX shell:

```sh
export JAVELIN_EXPECTED_SHA256="$(python3 -c 'import hashlib; print(hashlib.sha256(open("AntiCheat.py", "rb").read()).hexdigest())')"
python3 AntiCheat.py
unset JAVELIN_EXPECTED_SHA256
```

The guard reads `__file__`, not `argv[0]` or a similarly named file in the current
directory. Provision the expected value through a trusted deployment process;
do **not** regenerate it from a possibly modified script on every launch.

## C++: CRC32 of the entire running executable

`JAVELIN_EXPECTED_CRC32` remains a **compile-time** constant. The default value
`0` disables the check. Choose a nonzero 32-bit target when enabling it. The
runtime reads the full executable on disk, including its appended bytes, and
compares the IEEE CRC32 with that constant. Failure to read the executable also
fails the guard. Existing debugger and suspicious-process checks remain enabled
in the normal executable.

### Why a post-build sealing step is necessary

Hashing a binary and then recompiling that hash into it changes the binary again.
Instead, compile with the chosen target and then append a four-byte CRC correction
to the final **unsigned** linker output. The helper solves the 32-bit linear CRC
mapping and verifies the result before writing a separate output file. No hash
field is excluded from the runtime calculation, and no rebuild is required.

In a Visual Studio Developer Command Prompt:

```bat
mkdir build
cl /nologo /std:c++17 /EHsc /W4 /DJAVELIN_EXPECTED_CRC32=0x4A415645u AntiCheat.cpp /Fo:build\AntiCheat.obj /Fe:build\AntiCheat.unsealed.exe
python tools\seal_crc32.py build\AntiCheat.unsealed.exe build\AntiCheat.exe --expected 0x4A415645
```

Use **the same target** for compilation and sealing. The helper never overwrites
an existing output or changes its input; use a new output filename for each build.
Already-matching input is copied without appending another correction. All
byte-changing build steps must precede sealing. A change that alters the CRC32,
including a single-bit change to the correction, fails the check. CRC32 collisions
are possible; see the limits below.

This workflow is for freshly built unsigned Windows desktop executables. Do not
apply it to signed, packed, third-party, or overlay-sensitive executables. Code
signing after sealing changes the checked bytes; signing/packaging compatibility
is outside this demo's scope.

### Limits

CRC32 detects file changes; it is **not a cryptographic authenticity check**.
Someone able to change the program can deliberately repair the CRC, patch out
the guard, or replace the Python expected-hash environment variable. SHA-256
likewise needs a trusted expected value and trusted checking code. These checks
inspect the file on disk, not the loaded memory image, and do not eliminate
time-of-check/time-of-use races. Use an appropriate signed/trusted distribution
mechanism when defending against an active adversary.

## Tests — safe, local fixtures only

```bat
python -m unittest discover -s tests -v
```

Outside a Visual Studio Developer Command Prompt, the two native tests are
explicitly skipped. Inside it, the tests compile and execute
`tests/integrity_harness.cpp`. That harness calls the same production integrity
guard but **never invokes the debugger checks or process enumeration**. It only
hashes its own newly compiled temporary executable. The normal anti-cheat
executable is compiled separately when needed but is not run by the tests.

Coverage includes absent/matching/uppercase/malformed/mismatched Python values,
read failures and multi-chunk files; CRC correction vectors (including zero and
`0xffffffff`), idempotency, input preservation and overwrite refusal; native
disabled/unsealed/sealed behavior and a changed executable overlay, including a
path with spaces and Unicode.

[Short demonstration video](docs/integrity-demo.mp4): a 36-second replay of
outputs captured from real fixture commands, not a desktop recording. It shows
Python match/mismatch and native unsealed/sealed/tampered results using the
integrity-only harness. No real process inspection is performed.
