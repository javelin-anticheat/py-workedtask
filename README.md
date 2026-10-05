# py-workedtask (Javelin AntiCheat)

Minimal anti-cheat guards:

- Debugger detection (Windows C++)
- Suspicious process scan (Windows C++)
- **Self-integrity**: CRC32 / SHA-256 of running executable (C++), SHA-256 of script via `JAVELIN_EXPECTED_SHA256` (Python)

See [INTEGRITY.md](INTEGRITY.md) for how to set expected hashes.
