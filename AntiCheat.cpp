// AntiCheat.cpp
// Javelin Project - Basic Anti-Cheat Protection
// Features:
//   1. Multi-layer Debugger Detection (Win32 IsDebuggerPresent, CheckRemoteDebuggerPresent,
//      MSVC PEB BeingDebugged/NtGlobalFlag, and POSIX /proc/self/status TracerPid)
//   2. Suspicious Process & Reverse-Engineering Tool Detection (Toolhelp32 on Windows,
//      /proc/<pid>/comm scan on Linux)
//   3. Self-Integrity Verification (CRC32 baseline check)

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#endif

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static const char* kTag = "[Javelin AntiCheat] ";

static const int kExitDebuggerDetected  = 0xDEB;
static const int kExitSuspiciousProcess = 0xBAD;
static const int kExitIntegrityMismatch = 0xC3C;

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

static std::string stripExeSuffix(std::string s) {
    s = toLower(s);
    if (s.size() > 4 && s.compare(s.size() - 4, 4, ".exe") == 0) {
        s.erase(s.size() - 4);
    }
    return s;
}

static bool isSuspiciousName(const std::string& rawName) {
    std::string normalized = stripExeSuffix(rawName);
    if (normalized.empty()) {
        return false;
    }
    if (normalized.find("cheatengine") != std::string::npos) {
        return true;
    }
    for (const auto& entry : kSuspiciousProcesses) {
        if (normalized == stripExeSuffix(entry)) {
            return true;
        }
    }
    return false;
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

#ifdef _WIN32
static bool readBinaryFile(const std::wstring& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
#else
static bool readBinaryFile(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
#endif
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), size));
}

// --- 1. Debugger Detection ---
static bool checkDebugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        return true;
    }

    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        return true;
    }

#ifdef _MSC_VER
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
#endif
    return false;
#else
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            std::string val = line.substr(10);
            long tracerPid = std::strtol(val.c_str(), nullptr, 10);
            if (tracerPid != 0) {
                return true;
            }
            break;
        }
    }
    return false;
#endif
}

// --- 2. Suspicious Process Scan ---
static bool checkSuspiciousProcesses(std::string* matchedOut = nullptr) {
#ifdef _WIN32
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
        std::string name(pe.szExeFile);
        if (isSuspiciousName(name)) {
            if (matchedOut) {
                *matchedOut = toLower(name);
            }
            CloseHandle(snap);
            return true;
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
#else
    DIR* procDir = opendir("/proc");
    if (!procDir) {
        return false;
    }

    struct dirent* entry = nullptr;
    while ((entry = readdir(procDir)) != nullptr) {
        const char* dname = entry->d_name;
        if (!dname[0] || !std::isdigit(static_cast<unsigned char>(dname[0]))) {
            continue;
        }
        std::ifstream commFile(std::string("/proc/") + dname + "/comm");
        std::string comm;
        if (std::getline(commFile, comm) && isSuspiciousName(comm)) {
            if (matchedOut) {
                *matchedOut = toLower(comm);
            }
            closedir(procDir);
            return true;
        }
    }

    closedir(procDir);
    return false;
#endif
}

// --- 3. Self-Integrity Check ---
static bool checkSelfIntegrity(uint32_t expectedCrc) {
    std::vector<uint8_t> bytes;
#ifdef _WIN32
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    if (!readBinaryFile(path, bytes)) return false;
#else
    char path[PATH_MAX]{};
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len <= 0) return false;
    path[len] = '\0';
    if (!readBinaryFile(std::string(path), bytes)) return false;
#endif
    return crc32(bytes) == expectedCrc;
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
