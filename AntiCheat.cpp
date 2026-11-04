// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, basic self-integrity (CRC32)

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cwctype>
#include "integrity.h"

static const char* kTag = "[Javelin AntiCheat] ";

// --- Configurable lists ---
static std::vector<std::wstring> kSuspiciousProcesses = {
    L"cheatengine.exe",
    L"ollydbg.exe",
    L"x64dbg.exe",
    L"httpdebuggerui.exe",
    L"ida.exe",
    L"ida64.exe",
    L"scylla.exe",
    L"processhacker.exe"
};

// --- Utils ---
static std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

// --- Checks ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;

    // Use the documented API instead of architecture/compiler-specific PEB reads.
    BOOL remoteDebugger = FALSE;
    return CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger;
}

static bool checkSuspiciousProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
        std::wstring name = toLower(pe.szExeFile);
        for (const auto& bad : kSuspiciousProcesses) {
            if (name == toLower(bad)) {
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return false;
}

// --- Entry helper (embed a baseline CRC once you ship a build) ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Zero disables this optional check; see README.
#endif
static_assert(JAVELIN_EXPECTED_CRC32 >= 0 && JAVELIN_EXPECTED_CRC32 <= 0xFFFFFFFFull,
              "JAVELIN_EXPECTED_CRC32 must be an unsigned 32-bit value");

int main(int argc, char* argv[]) {
    std::cout << kTag << "starting checks...\n";

    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!javelin::selfIntegrity(static_cast<std::uint32_t>(JAVELIN_EXPECTED_CRC32))) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch or unreadable executable). Exiting.\n";
            return 3;
        }
        std::cout << kTag << "Executable integrity verified.\n";
    } else {
        std::cout << kTag << "Executable integrity disabled (JAVELIN_EXPECTED_CRC32 is zero).\n";
    }
    // Standalone diagnostic: verify the running image without scanning processes.
    if (argc == 2 && std::string(argv[1]) == "--verify-integrity") return 0;

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return 0xDEB; // code for debugger
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return 0xBAD; // code for bad process
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
