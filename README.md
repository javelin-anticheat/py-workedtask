# py-workedtask

Baseline anti-cheat implementation for Javelin issue #2.

## Included checks

Both runtime paths cover the acceptance criteria:

- debugger detection
- suspicious process detection
- guarded exit behavior

### C++

`AntiCheat.cpp` uses the Windows APIs `IsDebuggerPresent`,
`CheckRemoteDebuggerPresent`, and Toolhelp process enumeration.

It also builds on non-Windows CI hosts with a conservative fallback so that
syntax/build validation is portable.

### Python

`anti_cheat.py` uses Windows debugger APIs through `ctypes` and process
enumeration through `tasklist`. It has no third-party dependencies.

## Validation

```bash
python -m unittest discover -s tests -v
python -m py_compile anti_cheat.py tests/test_anti_cheat.py
```

On a C++17 compiler:

```bash
c++ -std=c++17 -Wall -Wextra -pedantic AntiCheat.cpp -o anti-cheat-check
./anti-cheat-check
```

On Windows with MSVC:

```bat
cl /std:c++17 /EHsc /W4 AntiCheat.cpp
AntiCheat.exe
```

## Bounty submission

The pull request for issue #2 must include `/claim #2` in its body and a short
demo video as required by the Algora bounty instructions.

AI assistance should be disclosed explicitly in the pull request.
