# py-workedtask

Minimal reference implementation for Javelin's Python worked-task prototype.

## Integrity verification (Python)

This repo includes an optional integrity check that computes the SHA-256 of the
running script and compares it to an expected value.

- Env var: `JAVELIN_EXPECTED_SHA256`
- Behavior:
  - If unset/empty: check is skipped (exit 0)
  - If set and mismatched: guarded exit with non-zero code

### Get the expected hash

```bash
python -c "import hashlib, pathlib; p=pathlib.Path('integrity_check.py'); print(hashlib.sha256(p.read_bytes()).hexdigest())"
```

### Run

```bash
export JAVELIN_EXPECTED_SHA256=<64-hex-digest>
python integrity_check.py
```

### Tests

```bash
pytest -q
```
