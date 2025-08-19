#!/usr/bin/env python3
# quick test for anti_cheat.py

import subprocess
import sys

def test_basic():
    print("testing basic run...")
    
    try:
        result = subprocess.run([sys.executable, 'anti_cheat.py'], 
                              capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            print("✓ runs ok")
            print(f"output: {result.stdout.strip()}")
        else:
            print(f"✗ failed with code {result.returncode}")
            print(f"error: {result.stderr.strip()}")
            
    except Exception as e:
        print(f"✗ exception: {e}")

def test_import():
    print("testing import...")
    
    try:
        import anti_cheat
        print("✓ import works")
        
        # check functions exist
        assert hasattr(anti_cheat, 'checkDebugger')
        assert hasattr(anti_cheat, 'checkSuspiciousProcesses') 
        print("✓ functions found")
        
    except Exception as e:
        print(f"✗ import failed: {e}")

if __name__ == "__main__":
    print("running tests...")
    test_import()
    test_basic()
    print("done")
