// AntiCheat.cpp
// Javelin Project - Basic Anti-Cheat Protection
// Features:
//   1. Multi-layer Debugger Detection (IsDebuggerPresent, CheckRemoteDebuggerPresent, PEB BeingDebugged & NtGlobalFlag)
//   2. Suspicious Process & Reverse-Engineering Tool Detection (Toolhelp32 process snapshot + substring match)
//   3. Self-Integrity Verification (CRC32 baseline check)

#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>

static const char* kTag = "[Javelin AntiCheat] ";

static const int kExitDebuggerDetected   = 0xDEB;
static const int kExitSuspiciousProcess  = 0xBAD;
static const int kExitIntegrityMismatch  = 0xC3C;

// --- Configurable blacklist of known cheat & debugger executables ---
static const std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "cheatengine-x86_64.exe",
    "cheatengine-i386.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "scylla_x64.exe",
    "processhacker.exe",
    "dnspy.exe",
    "ghidra.exe"
};

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static bool readFile(const std::wstring& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(out.data()), size)) return false;
    return true;
}

// --- 1. Debugger Detection ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) {
        return true;
    }

    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        return true;
    }

#ifdef _M_IX86
    __try {
        BYTE* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
        if (peb && (peb[2] != 0 || (peb[0x68] & 0x70) != 0)) {
            return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_M_X64)
    __try {
        BYTE* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
        if (peb && (peb[2] != 0 || (peb[0xBC] & 0x70) != 0)) {
            return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif

    return false;
}

// --- 2. Suspicious Process Scan ---
static bool checkSuspiciousProcesses(std::string* matchedOut = nullptr) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
        std::string name = toLower(std::string(pe.szExeFile));
        for (const auto& bad : kSuspiciousProcesses) {
            std::string loweredBad = toLower(bad);
            if (name == loweredBad || name.find("cheatengine") != std::string::npos) {
                if (matchedOut) {
                    *matchedOut = name;
                }
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
}

// --- 3. Self-Integrity Check ---
static bool checkSelfIntegrity(uint32_t expectedCrc) {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebuggerDetected;
    }

    std::string matchedProc;
    if (checkSuspiciousProcesses(&matchedProc)) {
        std::cerr << kTag << "Suspicious process detected (" << matchedProc << "). Exiting.\n";
        return kExitSuspiciousProcess;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrity(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
            return kExitIntegrityMismatch;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
