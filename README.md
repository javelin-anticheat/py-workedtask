# py-workedtask

Baseline anti-cheat protection for the Javelin project.

Included implementations:

- `AntiCheat.cpp`: Windows client checks for debugger attachment, suspicious processes, and optional CRC32 self-integrity.
- `anti_cheat.py`: Python monitor with debugger detection and suspicious-process scanning.

Run Python tests:

```bash
python3 -m unittest discover -s . -p "test_*.py" -v
```
