# py-workedtask

Baseline anti-cheat guards for the Javelin project.

## C++ client

`AntiCheat.cpp` checks for an attached debugger and a short list of suspicious
Windows process names. It also supports an optional build-time CRC guard:

```sh
c++ -std=c++17 -Wall -Wextra -pedantic AntiCheat.cpp -o anticheat
```

On non-Windows systems the platform-specific checks are compiled as no-ops so
the client remains buildable in CI.

## Python monitor

`anti_cheat.py` mirrors the baseline checks for the Python runtime path:

```sh
python3 anti_cheat.py
python3 -m unittest discover -s tests
```

The monitor exits with a non-zero status when it detects an attached debugger
or a known suspicious process.
