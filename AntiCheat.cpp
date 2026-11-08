// AntiCheat.cpp
// Javelin Project - baseline anti-cheat guards.
//
// Windows: debugger detection + suspicious process enumeration.
// Other platforms: builds cleanly and provides a conservative fallback so the
// source remains testable in cross-platform CI.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

static const char* kTag = "[Javelin AntiCheat] ";

static const std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe"
};

static std::string toLower(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); }
    );
    return value;
}

static bool checkDebugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        return true;
    }

    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(
            GetCurrentProcess(),
            &remoteDebugger
        ) && remoteDebugger) {
        return true;
    }
#endif
    return false;
}

static bool checkSuspiciousProcesses() {
#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        std::string name = toLower(entry.szExeFile);
        for (const auto& suspicious : kSuspiciousProcesses) {
            if (name == suspicious) {
                CloseHandle(snapshot);
                return true;
            }
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
#endif
    return false;
}

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return 11;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return 12;
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
