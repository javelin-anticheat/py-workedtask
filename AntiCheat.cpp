// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, basic self-integrity (CRC32)

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <type_traits>
#ifdef _MSC_VER
#include <intrin.h>
#endif

static const char* kTag = "[Javelin AntiCheat] ";

#ifdef JAVELIN_EXPECTED_CRC32
static_assert(std::is_integral<decltype(JAVELIN_EXPECTED_CRC32)>::value,
    "JAVELIN_EXPECTED_CRC32 must be an unsigned 32-bit integer value");
static_assert(static_cast<uint64_t>(JAVELIN_EXPECTED_CRC32) <= 0xFFFFFFFFULL,
    "JAVELIN_EXPECTED_CRC32 must fit in an unsigned 32-bit integer");
#endif

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
static std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return s;
}

// Simple CRC32 (polynomial 0xEDB88320)
static uint32_t crc32Update(uint32_t crc, const uint8_t* data, size_t size) {
    for (size_t n = 0; n < size; ++n) {
        uint8_t b = data[n];
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc;
}

static bool executableCrc32(uint32_t& result) {
    // Windows supports paths longer than MAX_PATH. Never hash a truncated name.
    std::vector<wchar_t> path(32768);
    DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) return false;

    HANDLE file = CreateFileW(path.data(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    uint8_t buffer[65536];
    uint32_t crc = 0xFFFFFFFFu;
    for (;;) {
        DWORD count = 0;
        if (!ReadFile(file, buffer, sizeof(buffer), &count, nullptr)) {
            CloseHandle(file);
            return false;
        }
        if (count == 0) break;
        crc = crc32Update(crc, buffer, count);
    }
    CloseHandle(file);
    result = ~crc;
    return true;
}

// --- Checks ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;

    // Secondary anti-debug: CheckBeingDebugged flag in PEB (best-effort)
#ifdef _M_IX86
    // 32-bit: fs:[30h] -> PEB, offset 2 = BeingDebugged (BYTE)
    __try {
        BYTE* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_M_X64)
    // 64-bit: gs:[60h] -> PEB
    __try {
        BYTE* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif

    return false;
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
            if (name == toLower(std::wstring(bad.begin(), bad.end()))) {
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return false;
}

[[maybe_unused]] static bool checkSelfIntegrity(uint32_t expectedCrc) {
    uint32_t current = 0;
    return executableCrc32(current) && current == expectedCrc;
}

// Defining the macro enables checking, including when the expected CRC is zero.
// Seal the final executable with tools/seal_crc32.py; see README.md.
int main(int argc, char* argv[]) {
    std::cout << kTag << "starting checks...\n";

#ifdef JAVELIN_EXPECTED_CRC32
    if (!checkSelfIntegrity(static_cast<uint32_t>(JAVELIN_EXPECTED_CRC32))) {
        std::cerr << kTag << "Integrity check failed (CRC mismatch or read error). Exiting.\n";
        return 3;
    }
#endif

    // Exercise the real executable integrity guard without unrelated process scans.
    if (argc == 2 && std::string(argv[1]) == "--check-integrity") return 0;

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
