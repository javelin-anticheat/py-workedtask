# py-workedtask

Baseline anti-cheat protection for the Javelin project.

Included implementations:

- `AntiCheat.cpp`: Windows client checks for debugger attachment, suspicious processes, and optional CRC32 self-integrity.
- `anti_cheat.py`: Python monitor with debugger detection, suspicious-process scanning, and optional SHA-256 integrity verification.

Python integrity verification:

- set `JAVELIN_EXPECTED_SHA256` to the expected script hash
- when the environment variable is present and does not match the current script, the monitor exits with a guarded failure code

Run Python tests:

```bash
python3 -m unittest discover -s . -p "test_*.py" -v
```
