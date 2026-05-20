// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, optional self-integrity (CRC32)

#include <windows.h>
#include <tlhelp32.h>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <limits>
#include <vector>
#include <string>
#include <algorithm>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

static const char* kTag = "[Javelin AntiCheat] ";
static constexpr int kExitDebugger = 0x0DEB;
static constexpr int kExitSuspiciousProcess = 0x0BAD;
static constexpr int kExitIntegrity = 0xC0DE;

// --- Configurable lists ---
static std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe"
};

// --- Utils ---
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return s;
}

// Simple CRC32 (polynomial 0xEDB88320)
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
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0) {
        CloseHandle(file);
        return false;
    }

    auto fileSizeBytes = static_cast<unsigned long long>(fileSize.QuadPart);
    if (fileSizeBytes > static_cast<unsigned long long>(std::numeric_limits<size_t>::max())) {
        CloseHandle(file);
        return false;
    }

    out.resize(static_cast<size_t>(fileSizeBytes));
    size_t offset = 0;
    while (offset < out.size()) {
        DWORD bytesToRead = static_cast<DWORD>(
            std::min<size_t>(out.size() - offset, 1024 * 1024));
        DWORD bytesRead = 0;
        if (!ReadFile(file, out.data() + offset, bytesToRead, &bytesRead, nullptr) ||
            bytesRead == 0) {
            CloseHandle(file);
            return false;
        }
        offset += bytesRead;
    }

    CloseHandle(file);
    return true;
}

// --- Checks ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;

    // Secondary anti-debug: CheckBeingDebugged flag in PEB (best-effort)
#if defined(_MSC_VER) && defined(_M_IX86)
    // 32-bit: fs:[30h] -> PEB, offset 2 = BeingDebugged (BYTE)
    __try {
        BYTE* peb = *(BYTE**)_readfsdword(0x30);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_MSC_VER) && defined(_M_X64)
    // 64-bit: gs:[60h] -> PEB
    __try {
        BYTE* peb = *(BYTE**)_readgsqword(0x60);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif

    return false;
}

static bool checkSuspiciousProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32A pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstA(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
        std::string name = toLower(pe.szExeFile);
        for (const auto& bad : kSuspiciousProcesses) {
            if (name == toLower(bad)) {
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32NextA(snap, &pe));

    CloseHandle(snap);
    return false;
}

static bool checkSelfIntegrity(uint32_t expectedCrc) {
    wchar_t path[MAX_PATH]{};
    DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (length == 0 || length == MAX_PATH) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

// --- Entry helper (embed a baseline CRC once you ship a build) ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set at build time, e.g. /DJAVELIN_EXPECTED_CRC32=0x12345678.
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebugger;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kExitSuspiciousProcess;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrity(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
            return kExitIntegrity;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
