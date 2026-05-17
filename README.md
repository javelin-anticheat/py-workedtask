# py-workedtask

Baseline anti-cheat protection for the Javelin Project.

## Components

- `AntiCheat.cpp`: native client guard for debugger and suspicious process detection.
- `anti_cheat.py`: Python monitor with the same baseline checks.

Both paths block known cheat/debugging tools such as Cheat Engine, x64dbg,
OllyDbg, IDA, Process Hacker, and Frida utilities.

## Run

```sh
python3 anti_cheat.py
```

Build the native client:

```sh
c++ -std=c++17 -Wall -Wextra -pedantic AntiCheat.cpp -o javelin-anticheat
./javelin-anticheat
```

On Windows, build `AntiCheat.cpp` with MSVC or another compiler that provides
the Windows SDK headers.

## Test

```sh
python3 -m unittest discover -s tests
c++ -std=c++17 -Wall -Wextra -pedantic AntiCheat.cpp -o /tmp/javelin-anticheat-check
/tmp/javelin-anticheat-check
```
