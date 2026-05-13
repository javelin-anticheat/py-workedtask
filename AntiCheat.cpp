// AntiCheat.cpp
// Javelin Project - baseline anti-cheat guards.
//
// The Windows build exits when a debugger is attached or when a known
// cheat/debugging tool is running. Non-Windows builds compile to a no-op
// helper so the repository can still be checked on Linux/macOS CI.

#include <iostream>

static const char* kTag = "[Javelin AntiCheat] ";
static constexpr int kExitOk = 0;

#ifndef _WIN32

int main() {
    std::cout << kTag << "Windows-only checks skipped on this platform.\n";
    return kExitOk;
}

#else

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <fstream>
#include <string>
#include <tlhelp32.h>
#include <vector>
#include <windows.h>

static constexpr int kExitDebugger = 0x0D;
static constexpr int kExitSuspiciousProcess = 0x0B;
static constexpr int kExitIntegrity = 0x0C;

static const std::vector<std::wstring> kSuspiciousProcesses = {
    L"cheatengine.exe",
    L"cheatengine-x86_64.exe",
    L"ollydbg.exe",
    L"x64dbg.exe",
    L"x32dbg.exe",
    L"httpdebuggerui.exe",
    L"ida.exe",
    L"ida64.exe",
    L"scylla.exe",
    L"processhacker.exe"
};

static std::wstring toLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

static uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static bool readFile(const std::wstring& path, std::vector<uint8_t>& out) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    file.seekg(0, std::ios::end);
    const std::streamsize size = file.tellg();
    if (size <= 0) {
        return false;
    }

    file.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    return static_cast<bool>(file.read(reinterpret_cast<char*>(out.data()), size));
}

static bool checkDebugger() {
    if (IsDebuggerPresent()) {
        return true;
    }

    BOOL remoteDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebuggerPresent)) {
        return remoteDebuggerPresent == TRUE;
    }

    return false;
}

static bool checkSuspiciousProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W process{};
    process.dwSize = sizeof(process);
    if (!Process32FirstW(snapshot, &process)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        const std::wstring processName = toLower(process.szExeFile);
        for (const std::wstring& suspiciousName : kSuspiciousProcesses) {
            if (processName == suspiciousName) {
                CloseHandle(snapshot);
                return true;
            }
        }
    } while (Process32NextW(snapshot, &process));

    CloseHandle(snapshot);
    return false;
}

static bool checkSelfIntegrity(uint32_t expectedCrc) {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) {
        return false;
    }

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) {
        return false;
    }

    return crc32(bytes) == expectedCrc;
}

#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
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

    if (JAVELIN_EXPECTED_CRC32 != 0u && !checkSelfIntegrity(JAVELIN_EXPECTED_CRC32)) {
        std::cerr << kTag << "Integrity check failed. Exiting.\n";
        return kExitIntegrity;
    }

    std::cout << kTag << "All clear. Continue.\n";
    return kExitOk;
}

#endif
