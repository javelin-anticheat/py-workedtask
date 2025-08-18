// AntiCheat.cpp
// Javelin Project - Basic Anti-Cheat Protection
// Features: Debugger detection, suspicious process scan

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

// Suspicious process list
static std::vector<std::string> suspiciousProcesses = {
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe"
};

// Convert to lowercase
std::string toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Check if debugger is attached
bool isDebuggerAttached() {
    return IsDebuggerPresent();
}

// Scan running processes
bool detectSuspiciousProcesses() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
        return false;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return false;
    }

    do {
        std::string processName = toLower(pe32.szExeFile);
        for (auto &badProc : suspiciousProcesses) {
            if (processName == badProc) {
                CloseHandle(hProcessSnap);
                return true;
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return false;
}

int main() {
    std::cout << "[Anti-Cheat] Running protection checks...\n";

    if (isDebuggerAttached()) {
        std::cerr << "[Anti-Cheat] Debugger detected! Exiting.\n";
        return -1;
    }

    if (detectSuspiciousProcesses()) {
        std::cerr << "[Anti-Cheat] Suspicious process found! Exiting.\n";
        return -2;
    }

    std::cout << "[Anti-Cheat] No cheat detected. Safe to continue.\n";
    return 0;
}
