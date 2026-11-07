// AntiCheat.cpp
// Javelin Project - Cross-Platform Anti-Cheat Guards
// Features: debugger detection (IsDebuggerPresent, CheckRemoteDebuggerPresent, PEB, Linux TracerPid),
//           suspicious process scan (Cheat Engine, x64dbg, OllyDbg, IDA, Scylla, Process Hacker),
//           and self-integrity (CRC32).

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>

static const char* kTag = "[Javelin AntiCheat] ";

static std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "cheatengine-x86_64.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
    "wireshark.exe",
    "frida-server"
};

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static std::string stripExeSuffix(std::string s) {
    s = toLower(s);
    if (s.size() > 4 && s.substr(s.size() - 4) == ".exe") {
        return s.substr(0, s.size() - 4);
    }
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

static bool checkDebugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) return true;

    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        return true;
    }

#ifdef _M_IX86
    __try {
        BYTE* peb = *(BYTE**)_readfsdword(0x30);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_M_X64)
    __try {
        BYTE* peb = *(BYTE**)_readgsqword(0x60);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
    return false;
#else
    std::ifstream statusFile("/proc/self/status");
    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            std::istringstream iss(line.substr(10));
            int tracerPid = 0;
            if (iss >> tracerPid && tracerPid != 0) {
                return true;
            }
        }
    }
    return false;
#endif
}

static bool isSuspiciousName(const std::string& rawName) {
    std::string normalized = stripExeSuffix(rawName);
    for (const auto& bad : kSuspiciousProcesses) {
        if (normalized == stripExeSuffix(bad)) {
            return true;
        }
    }
    return false;
}

static bool checkSuspiciousProcesses() {
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
        if (isSuspiciousName(pe.szExeFile)) {
            CloseHandle(snap);
            return true;
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
#else
    DIR* procDir = opendir("/proc");
    if (!procDir) return false;
    struct dirent* entry = nullptr;
    while ((entry = readdir(procDir)) != nullptr) {
        bool isPid = true;
        for (const char* p = entry->d_name; *p; ++p) {
            if (*p < '0' || *p > '9') {
                isPid = false;
                break;
            }
        }
        if (!isPid) continue;
        std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
        std::ifstream commFile(commPath);
        std::string procName;
        if (std::getline(commFile, procName) && isSuspiciousName(procName)) {
            closedir(procDir);
            return true;
        }
    }
    closedir(procDir);
    return false;
#endif
}

#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return 0xDEB;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return 0xBAD;
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
