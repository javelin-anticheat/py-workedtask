# py-workedtask

Basic anti-cheat protection for Javelin project.

## What it does

- Detects debuggers (prevents debugging)
- Scans for cheat tools/processes 
- Basic file integrity checking
- Mostly designed for Windows

### Detects these tools
- Cheat Engine, OllyDbg, x64dbg
- IDA Pro, Process Hacker, Scylla
- Other debugging/reversing tools

## Files

**AntiCheat.cpp** - C++ version, windows only
```bash
g++ -o anticheat.exe AntiCheat.cpp
./anticheat.exe
```

**anti_cheat.py** - Python version, should work cross-platform
```bash
pip install psutil
python3 anti_cheat.py
```

## Exit codes
- 0: all good
- 0xDEB: debugger found
- 0xBAD: suspicious process found  
- 0x12C: file integrity failed

## Testing
Try running with cheat engine open, should detect it and exit.

## Notes
This is basic protection, can probably be bypassed easily. 
Consider using server-side validation too.

## TODO
- [ ] Better anti-debug techniques
- [ ] VM detection
- [ ] More process checks