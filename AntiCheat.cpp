// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity verification (CRC32 + SHA-256)

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <limits.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static const char* kTag = "[Javelin AntiCheat] ";

// Exit codes (kept within 0..255 so POSIX and Windows preserve non-zero status)
static constexpr int kExitOk = 0;
static constexpr int kExitDebuggerDetected = 0xDE;
static constexpr int kExitSuspiciousProcess = 0xBA;
static constexpr int kExitIntegrityFailed = 0xCF;

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
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
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

// Self-contained FIPS 180-4 SHA-256 implementation
namespace javelin_sha256 {

static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

static std::string sha256Hex(const std::vector<uint8_t>& data) {
    static const uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };

    uint32_t h[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };

    uint64_t bitLen = static_cast<uint64_t>(data.size()) * 8u;
    std::vector<uint8_t> padded = data;
    padded.push_back(0x80u);
    while ((padded.size() % 64u) != 56u) {
        padded.push_back(0x00u);
    }
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xFFu));
    }

    for (size_t offset = 0; offset < padded.size(); offset += 64u) {
        uint32_t w[64]{};
        for (int i = 0; i < 16; ++i) {
            size_t idx = offset + static_cast<size_t>(i) * 4u;
            w[i] = (static_cast<uint32_t>(padded[idx]) << 24u) |
                   (static_cast<uint32_t>(padded[idx + 1]) << 16u) |
                   (static_cast<uint32_t>(padded[idx + 2]) << 8u) |
                   static_cast<uint32_t>(padded[idx + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7u) ^ rotr(w[i - 15], 18u) ^ (w[i - 15] >> 3u);
            uint32_t s1 = rotr(w[i - 2], 17u) ^ rotr(w[i - 2], 19u) ^ (w[i - 2] >> 10u);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint32_t word : h) {
        oss << std::setw(8) << word;
    }
    return oss.str();
}

} // namespace javelin_sha256

static bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

#ifdef _WIN32
static bool readExecutableBytes(std::vector<uint8_t>& out, const std::string& overridePath = "") {
    std::ifstream f;
    if (!overridePath.empty()) {
        f.open(overridePath, std::ios::binary);
    } else {
        wchar_t path[MAX_PATH]{};
        if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
        f.open(path, std::ios::binary);
    }
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), size));
}
#else
static bool readExecutableBytes(std::vector<uint8_t>& out, const std::string& overridePath = "") {
    std::string execPath = overridePath;
    if (execPath.empty()) {
#ifdef __APPLE__
        char buf[PATH_MAX]{};
        uint32_t size = sizeof(buf);
        if (_NSGetExecutablePath(buf, &size) == 0) {
            execPath = buf;
        }
#else
        char buf[PATH_MAX]{};
        ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            execPath = buf;
        }
#endif
    }
    if (execPath.empty()) return false;
    std::ifstream f(execPath, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), size));
}
#endif

// --- Checks ---
static bool checkDebugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) return true;

    // Secondary anti-debug: CheckBeingDebugged flag in PEB (best-effort)
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
#endif
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
        std::string name = toLower(pe.szExeFile);
        for (const auto& bad : kSuspiciousProcesses) {
            if (name == toLower(bad)) {
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
#endif
    return false;
}

static bool checkSelfIntegrityCrc32(uint32_t expectedCrc, const std::string& overridePath = "") {
    std::vector<uint8_t> bytes;
    if (!readExecutableBytes(bytes, overridePath)) return false;
    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

static bool checkSelfIntegritySha256(const std::string& expectedSha256Hex, const std::string& overridePath = "") {
    std::string normalizedExpected = toLower(trim(expectedSha256Hex));
    if (normalizedExpected.size() != 64u) return false;

    std::vector<uint8_t> bytes;
    if (!readExecutableBytes(bytes, overridePath)) return false;
    std::string actualHex = javelin_sha256::sha256Hex(bytes);
    return constantTimeEquals(actualHex, normalizedExpected);
}

// --- Build-time constants ---
// Embed a baseline CRC32 or SHA-256 at build time:
//   MSVC:  cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp
//   GCC:   g++ -O2 -DJAVELIN_EXPECTED_SHA256="\"<64-hex-chars>\"" AntiCheat.cpp -o anticheat
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

#ifndef JAVELIN_EXPECTED_SHA256
#define JAVELIN_EXPECTED_SHA256 ""
#endif

int main(int argc, char* argv[]) {
    std::string targetPath;
    bool printHashOnly = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--print-hash") {
            printHashOnly = true;
        } else if (arg == "--file" && i + 1 < argc) {
            targetPath = argv[++i];
        }
    }

    if (printHashOnly) {
        std::vector<uint8_t> bytes;
        if (!readExecutableBytes(bytes, targetPath)) {
            std::cerr << kTag << "Failed to read executable for hash calculation.\n";
            return kExitIntegrityFailed;
        }
        std::cout << "CRC32=0x" << std::hex << std::setw(8) << std::setfill('0') << crc32(bytes) << "\n";
        std::cout << "SHA256=" << javelin_sha256::sha256Hex(bytes) << "\n";
        return kExitOk;
    }

    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebuggerDetected;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kExitSuspiciousProcess;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrityCrc32(JAVELIN_EXPECTED_CRC32, targetPath)) {
            std::cerr << kTag << "Integrity check failed (CRC32 mismatch). Exiting.\n";
            return kExitIntegrityFailed;
        }
    }

    const std::string expectedSha256 = trim(JAVELIN_EXPECTED_SHA256);
    if (!expectedSha256.empty()) {
        if (!checkSelfIntegritySha256(expectedSha256, targetPath)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
            return kExitIntegrityFailed;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return kExitOk;
}
