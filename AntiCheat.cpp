// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32 + SHA-256)

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>

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

// --- Utils ---
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// ============================================================
// CRC32 (original - polynomial 0xEDB88320)
// ============================================================
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

// ============================================================
// SHA-256 (RFC 6234 - pure C++, no external dependencies)
// ============================================================
namespace sha256_impl {

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t Sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t Sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t sigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

std::string compute(const std::vector<uint8_t>& data) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Pre-processing: pad message
    size_t origLen = data.size();
    size_t bitLen = origLen * 8;
    std::vector<uint8_t> msg(data);
    msg.push_back(0x80);
    while ((msg.size() % 64) != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xFF));

    // Process each 512-bit block
    for (size_t offset = 0; offset < msg.size(); offset += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(msg[offset + i*4]) << 24)
                 | (uint32_t(msg[offset + i*4+1]) << 16)
                 | (uint32_t(msg[offset + i*4+2]) << 8)
                 | uint32_t(msg[offset + i*4+3]);
        }
        for (int i = 16; i < 64; ++i)
            w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = hh + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
            uint32_t T2 = Sigma0(a) + Maj(a, b, c);
            hh = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    std::ostringstream oss;
    for (int i = 0; i < 8; ++i)
        oss << std::hex << std::setfill('0') << std::setw(8) << h[i];
    return oss.str();
}

} // namespace sha256_impl

// ============================================================
// File I/O
// ============================================================
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

// --- Checks ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;

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
                std::cerr << kTag << "SUSPICIOUS process detected: " << pe.szExeFile << "\n";
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
}

// ============================================================
// Self-Integrity Checks
// ============================================================

// Build-time constants: set these to the known-good hashes of this binary.
// Use --compute-hash mode to generate them, then recompile with the values.
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // 0 = skip CRC32 check
#endif

#ifndef JAVELIN_EXPECTED_SHA256
#define JAVELIN_EXPECTED_SHA256 ""  // empty = skip SHA-256 check
#endif

static bool checkSelfIntegrityCRC32() {
    if (JAVELIN_EXPECTED_CRC32 == 0u) {
        std::cout << kTag << "CRC32 integrity check SKIPPED (no expected hash set).\n";
        return true;
    }

    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::vector<uint8_t> data;
    if (!readFile(path, data)) {
        std::cerr << kTag << "CRC32 check FAILED: cannot read own binary.\n";
        return false;
    }

    uint32_t actual = crc32(data);
    if (actual != JAVELIN_EXPECTED_CRC32) {
        std::cerr << kTag << "CRC32 MISMATCH! Expected 0x" << std::hex << JAVELIN_EXPECTED_CRC32
                  << ", got 0x" << actual << std::dec << ".\n";
        return false;
    }

    std::cout << kTag << "CRC32 integrity check PASSED.\n";
    return true;
}

static bool checkSelfIntegritySHA256() {
    std::string expected(JAVELIN_EXPECTED_SHA256);
    if (expected.empty()) {
        std::cout << kTag << "SHA-256 integrity check SKIPPED (no expected hash set).\n";
        return true;
    }

    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::vector<uint8_t> data;
    if (!readFile(path, data)) {
        std::cerr << kTag << "SHA-256 check FAILED: cannot read own binary.\n";
        return false;
    }

    std::string actual = sha256_impl::compute(data);
    // Case-insensitive compare
    std::string expLower = toLower(expected);
    if (actual != expLower) {
        std::cerr << kTag << "SHA-256 MISMATCH!\n"
                  << "  Expected: " << expLower << "\n"
                  << "  Actual:   " << actual << "\n";
        return false;
    }

    std::cout << kTag << "SHA-256 integrity check PASSED.\n";
    return true;
}

// ============================================================
// Main
// ============================================================
int main(int argc, char* argv[]) {
    // Utility mode: compute hashes of own binary
    if (argc > 1 && std::string(argv[1]) == "--compute-hash") {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::vector<uint8_t> data;
        if (!readFile(path, data)) {
            std::cerr << kTag << "Cannot read own binary for hash computation.\n";
            return 1;
        }
        uint32_t crc = crc32(data);
        std::string sha = sha256_impl::compute(data);
        std::cout << "Binary hashes (use these as build-time constants):\n";
        std::cout << "  CRC32:  0x" << std::hex << crc << std::dec << "\n";
        std::cout << "  SHA-256: " << sha << "\n";
        std::cout << "\nRecompile with:\n";
        std::cout << "  -DJAVELIN_EXPECTED_CRC32=0x" << std::hex << crc << std::dec << "\n";
        std::cout << "  -DJAVELIN_EXPECTED_SHA256=\"" << sha << "\"\n";
        return 0;
    }

    int failCount = 0;

    // 1. Debugger detection
    if (checkDebugger()) {
        std::cerr << kTag << "DEBUGGER DETECTED. Exiting.\n";
        return 1;
    }
    std::cout << kTag << "No debugger detected.\n";

    // 2. Suspicious process scan
    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "SUSPICIOUS PROCESS DETECTED. Exiting.\n";
        return 1;
    }
    std::cout << kTag << "No suspicious processes found.\n";

    // 3. Self-integrity: CRC32
    if (!checkSelfIntegrityCRC32()) {
        std::cerr << kTag << "CRC32 INTEGRITY FAILURE.\n";
        ++failCount;
    }

    // 4. Self-integrity: SHA-256
    if (!checkSelfIntegritySHA256()) {
        std::cerr << kTag << "SHA-256 INTEGRITY FAILURE.\n";
        ++failCount;
    }

    if (failCount > 0) {
        std::cerr << kTag << failCount << " integrity check(s) failed. Exiting.\n";
        return 1;
    }

    std::cout << kTag << "All checks passed. Application may proceed.\n";
    return 0;
}
