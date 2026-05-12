# py-workedtask

Javelin Anti-Cheat — Minimal anti-cheat guards with integrity verification.

## Components

### C++ (`AntiCheat.cpp`)
- Debugger detection
- Suspicious process scanning
- Self-integrity check (CRC32)

### Python (`integrity.py`)
- SHA-256 script integrity verification
- Environment variable based expected hash
- Guarded exit on tampering detection

## Python Integrity Verification

### Setup

1. Compute the hash of your script:
```bash
python integrity.py your_script.py
# Output: a1b2c3d4...  your_script.py
```

2. Set the expected hash as environment variable:
```bash
export JAVELIN_EXPECTED_SHA256=a1b2c3d4e5f6...
```

3. Add verification to your script:
```python
from integrity import verify_integrity

# Call at startup - exits if tampered
verify_integrity()

# Your application code here...
```

### How It Works

- On startup, computes SHA-256 of the running script file
- Compares against `JAVELIN_EXPECTED_SHA256` environment variable
- If mismatch: prints error and exits with code 1
- If env var not set: verification is skipped (opt-in)

### Running Tests

```bash
pip install pytest
pytest test_integrity.py -v
```
