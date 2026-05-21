// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, optional self-integrity (CRC32)

#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>

static const char* kTag = "[Javelin AntiCheat] ";

// --- Entry helper (embed a baseline CRC once you ship a build) ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set at build time, e.g. /DJAVELIN_EXPECTED_CRC32=0x12345678
#endif

static constexpr int kExitDebugger = 0x0DEB;
static constexpr int kExitSuspiciousProcess = 0x0BAD;
static constexpr int kExitIntegrity = 0x0C0D;

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
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
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

static std::vector<uint8_t> expectedCrcMarkerBytes(uint32_t expectedCrc) {
    return {
        'J', 'V', 'L', 'N', '_', 'C', 'R', 'C', '3', '2', '_',
        static_cast<uint8_t>((expectedCrc >> 0) & 0xFFu),
        static_cast<uint8_t>((expectedCrc >> 8) & 0xFFu),
        static_cast<uint8_t>((expectedCrc >> 16) & 0xFFu),
        static_cast<uint8_t>((expectedCrc >> 24) & 0xFFu),
        '_', 'E', 'N', 'D'
    };
}

static const uint8_t kExpectedCrcMarker[] = {
    'J', 'V', 'L', 'N', '_', 'C', 'R', 'C', '3', '2', '_',
    static_cast<uint8_t>((JAVELIN_EXPECTED_CRC32 >> 0) & 0xFFu),
    static_cast<uint8_t>((JAVELIN_EXPECTED_CRC32 >> 8) & 0xFFu),
    static_cast<uint8_t>((JAVELIN_EXPECTED_CRC32 >> 16) & 0xFFu),
    static_cast<uint8_t>((JAVELIN_EXPECTED_CRC32 >> 24) & 0xFFu),
    '_', 'E', 'N', 'D'
};

static bool findMarkerOffset(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& marker, size_t& offset) {
    auto it = std::search(bytes.begin(), bytes.end(), marker.begin(), marker.end());
    if (it == bytes.end()) return false;
    offset = static_cast<size_t>(std::distance(bytes.begin(), it));
    return true;
}

static bool normalizeEmbeddedExpectedCrc(std::vector<uint8_t>& bytes, uint32_t expectedCrc) {
    const std::vector<uint8_t> marker = expectedCrcMarkerBytes(expectedCrc);
    size_t markerOffset = 0;
    if (!findMarkerOffset(bytes, marker, markerOffset)) return false;

    const size_t crcOffset = markerOffset + 11;
    for (size_t i = 0; i < 4; ++i) {
        bytes[crcOffset + i] = 0;
    }
    return true;
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

static bool readSelfExecutable(std::vector<uint8_t>& bytes) {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    return readFile(path, bytes);
}

static bool computeNormalizedSelfCrc(uint32_t& outCrc) {
    std::vector<uint8_t> bytes;
    if (!readSelfExecutable(bytes)) return false;

    if (!normalizeEmbeddedExpectedCrc(bytes, JAVELIN_EXPECTED_CRC32)) {
        return false;
    }

    outCrc = crc32(bytes);
    return true;
}

// --- Checks ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;

    // Secondary anti-debug: CheckBeingDebugged flag in PEB (best-effort)
#ifdef _M_IX86
    // 32-bit: fs:[30h] -> PEB, offset 2 = BeingDebugged (BYTE)
    __try {
        BYTE* peb = *(BYTE**)_readfsdword(0x30);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_M_X64)
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

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
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
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
}

static bool checkSelfIntegrity(uint32_t expectedCrc) {
    uint32_t current = 0;
    if (!computeNormalizedSelfCrc(current)) return false;
    return current == expectedCrc;
}

int main(int argc, char* argv[]) {
    (void)kExpectedCrcMarker;

    if (argc > 1 && std::string(argv[1]) == "--print-integrity-crc32") {
        uint32_t crc = 0;
        if (!computeNormalizedSelfCrc(crc)) {
            std::cerr << kTag << "Unable to compute self CRC32.\n";
            return kExitIntegrity;
        }
        std::cout << "0x" << std::hex << std::uppercase << std::setw(8)
                  << std::setfill('0') << crc << "\n";
        return 0;
    }

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
