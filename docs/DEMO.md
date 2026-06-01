# Integrity Verification Demo

`javelin-integrity-demo.mp4` is a short terminal-style demo for the bounty PR.
It shows:

- the focused Python and C++ integrity tests passing;
- C++ printing the canonical executable CRC32;
- C++ rebuilt with the matching CRC passing the guard;
- C++ rebuilt with a wrong CRC exiting with guarded code `0xC0`;
- Python SHA-256 matching and mismatching flows.

The same output is available as text in `demo-transcript.txt`.
