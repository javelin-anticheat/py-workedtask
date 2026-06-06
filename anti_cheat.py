import sys
import subprocess
import os

TAG = "[Javelin AntiCheat] "

SUSPICIOUS_PROCESSES = [
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
    "gdb",
    "lldb"
]

def check_debugger() -> bool:
    if getattr(sys, "gettrace", None) and sys.gettrace():
        return True
    
    # Check if a debugger is attached via ptrace on Linux
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split()[1])
                        if tracer_pid != 0:
                            return True
        except Exception:
            pass
            
    # Check for Windows debugger
    if sys.platform == "win32":
        import ctypes
        try:
            if ctypes.windll.kernel32.IsDebuggerPresent():
                return True
        except Exception:
            pass
            
    return False

def check_suspicious_processes() -> bool:
    try:
        if sys.platform == "win32":
            output = subprocess.check_output(["tasklist", "/nh", "/fo", "csv"], universal_newlines=True)
            output_lower = output.lower()
            for bad_proc in SUSPICIOUS_PROCESSES:
                if f'"{bad_proc}"' in output_lower:
                    return True
        else:
            output = subprocess.check_output(["ps", "-A", "-o", "comm="], universal_newlines=True)
            output_lower = output.lower()
            for bad_proc in SUSPICIOUS_PROCESSES:
                if bad_proc in output_lower:
                    return True
    except Exception:
        pass
    return False

def main():
    print(f"{TAG}starting checks...")
    
    if check_debugger():
        print(f"{TAG}Debugger detected. Exiting.", file=sys.stderr)
        sys.exit(0xDEB)
        
    if check_suspicious_processes():
        print(f"{TAG}Suspicious process detected. Exiting.", file=sys.stderr)
        sys.exit(0xBAD)
        
    print(f"{TAG}All clear. Continue.")
    sys.exit(0)

if __name__ == "__main__":
    main()
