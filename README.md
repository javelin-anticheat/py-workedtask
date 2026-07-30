# Javelin Anti-Cheat Project

A minimal anti-cheat module providing debugger detection, suspicious process scanning, and self-integrity verification.

## Features

- **Debugger Detection**: Identifies if a debugger is attached to the process.
- **Process Scanning**: Scans for known suspicious tools (e.g., Cheat Engine, x64dbg).
- **Integrity Verification**: Ensures the executable or script has not been tampered with.

## Implementations

### C++ (Windows)

The C++ implementation uses CRC32 to verify the integrity of the running executable.

#### Build-time Configuration

To enable integrity checks, define `JAVELIN_EXPECTED_CRC32` during compilation:

```bash
# Example using MSVC
cl /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

#### How to set the expected CRC32

1. Build the executable with the default `JAVELIN_EXPECTED_CRC32=0`.
2. Run the executable with the `--print-integrity` flag:
   ```bash
   AntiCheat.exe --print-integrity
   ```
3. Rebuild the project using the printed CRC32 value.

### Python

The Python implementation uses SHA-256 to verify the script file.

#### Environment Configuration

The Python guard is driven by the `JAVELIN_EXPECTED_SHA256` environment variable.

```bash
# Set the expected hash (Linux/macOS)
export JAVELIN_EXPECTED_SHA256="your_sha256_hash_here"

# Set the expected hash (Windows)
set JAVELIN_EXPECTED_SHA256=your_sha256_hash_here
```

#### How to set the expected SHA-256

1. Run the script with the `--print-integrity` flag to get the current hash:
   ```bash
   python AntiCheat.py --print-integrity
   ```
2. Set the `JAVELIN_EXPECTED_SHA256` environment variable to this value before running the script in production.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0x000` | Success (All clear) |
| `0xDEB` | Debugger detected |
| `0xBAD` | Suspicious process detected |
| `0xCEC` | Integrity verification failed |
