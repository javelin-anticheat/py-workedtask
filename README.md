# Javelin integrity verification

This repository contains optional integrity guards for both implementations:

- AntiCheat.cpp calculates CRC32 for the running Windows executable.
- anti_cheat.py calculates SHA-256 for its own script file.

An expected value of zero or an unset environment variable leaves the matching
guard disabled, which allows a baseline hash to be generated first.

## C++ executable

Build once without an expected CRC, then ask that executable for its normalized
CRC32:

~~~powershell
cl /EHsc /std:c++17 AntiCheat.cpp
.\AntiCheat.exe --print-self-crc32
~~~

Rebuild with the printed value:

~~~powershell
cl /EHsc /std:c++17 /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
.\AntiCheat.exe
~~~

For MinGW, the equivalent commands are:

~~~sh
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -static AntiCheat.cpp -o AntiCheat.exe
EXPECTED_CRC=$(wine ./AntiCheat.exe --print-self-crc32 | tr -d '\r')
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -static \
  -DJAVELIN_EXPECTED_CRC32=$EXPECTED_CRC AntiCheat.cpp -o AntiCheat.exe
wine ./AntiCheat.exe
~~~

The expected CRC field, PE build timestamp, and PE checksum are normalized to
zero while hashing. Rebuilding with the expected value therefore produces the
same calculated CRC even when the linker updates its metadata. Changing any
other byte causes a guarded exit.

## Python script

Print the script's current SHA-256, export it, and run the guard:

~~~sh
export JAVELIN_EXPECTED_SHA256=$(python3 anti_cheat.py --print-sha256)
python3 anti_cheat.py
~~~

PowerShell uses the same value through an environment variable:

~~~powershell
$env:JAVELIN_EXPECTED_SHA256 = (python .\anti_cheat.py --print-sha256)
python .\anti_cheat.py
~~~

If JAVELIN_EXPECTED_SHA256 is unset or empty, the Python guard is disabled.
Invalid or non-matching values cause a guarded exit.

## Tests

~~~sh
python3 -m unittest discover -s tests
~~~
