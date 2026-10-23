// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, optional self-integrity (CRC32)

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>

#ifdef _MSC_VER
#include <intrin.h>
#endif

static const char* kTag = "[Javelin AntiCheat] ";

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

// --- Optional self-integrity configuration ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set at build time, e.g. /DJAVELIN_EXPECTED_CRC32=0x12345678
#endif

// The expected CRC is embedded between stable marker bytes. The CRC routine zeros
// this field before hashing so rebuilding with the expected value does not change
// the hash that is being verified.
static const uint8_t kCrcMarkerBegin[16] = {
    'J', 'V', 'L', 'N', 'C', 'R', 'C', '3', '2', 'B', 'E', 'G', 'I', 'N', '!', '!'
};
static const uint8_t kCrcMarkerEnd[16] = {
    'J', 'V', 'L', 'N', 'C', 'R', 'C', '3', '2', 'E', 'N', 'D', '!', '!', '!', '!'
};

struct IntegrityMarker {
    uint8_t begin[16];
    uint32_t expectedCrc32;
    uint8_t end[16];
};

static volatile const IntegrityMarker kIntegrityMarker = {
    { 'J', 'V', 'L', 'N', 'C', 'R', 'C', '3', '2', 'B', 'E', 'G', 'I', 'N', '!', '!' },
    JAVELIN_EXPECTED_CRC32,
    { 'J', 'V', 'L', 'N', 'C', 'R', 'C', '3', '2', 'E', 'N', 'D', '!', '!', '!', '!' }
};

// --- Utils ---
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
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

static bool normalizeExpectedCrcMarker(std::vector<uint8_t>& bytes) {
    const size_t beginSize = sizeof(kCrcMarkerBegin);
    const size_t endSize = sizeof(kCrcMarkerEnd);
    const size_t crcOffset = beginSize;
    const size_t totalSize = beginSize + sizeof(uint32_t) + endSize;

    if (bytes.size() < totalSize) return false;

    bool found = false;
    for (size_t i = 0; i <= bytes.size() - totalSize; ++i) {
        if (std::equal(kCrcMarkerBegin, kCrcMarkerBegin + beginSize, bytes.begin() + i) &&
            std::equal(kCrcMarkerEnd, kCrcMarkerEnd + endSize, bytes.begin() + i + beginSize + sizeof(uint32_t))) {
            std::fill(bytes.begin() + i + crcOffset,
                      bytes.begin() + i + crcOffset + sizeof(uint32_t),
                      0u);
            found = true;
        }
    }

    return found;
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

static bool computeSelfCrc32(uint32_t& outCrc) {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;
    if (!normalizeExpectedCrcMarker(bytes)) return false;

    outCrc = crc32(bytes);
    return true;
}

static bool checkSelfIntegrity(uint32_t expectedCrc) {
    uint32_t current = 0u;
    return computeSelfCrc32(current) && current == expectedCrc;
}

int main(int argc, char* argv[]) {
    const uint32_t expectedCrc = kIntegrityMarker.expectedCrc32;

    if (argc > 1 && std::string(argv[1]) == "--print-crc32") {
        uint32_t current = 0u;
        if (!computeSelfCrc32(current)) {
            std::cerr << kTag << "Unable to compute executable CRC32.\n";
            return 1;
        }

        std::cout << "0x" << std::hex << std::uppercase << std::setw(8)
                  << std::setfill('0') << current << std::dec << "\n";
        return 0;
    }

    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return 0xDEB; // code for debugger
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return 0xBAD; // code for bad process
    }

    if (expectedCrc != 0u) {
        if (!checkSelfIntegrity(expectedCrc)) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
            return 0xC0DE; // code for integrity failure
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
