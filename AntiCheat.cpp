// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, basic self-integrity (CRC32 or SHA-256)

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <array>

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

static std::string hexLower(const uint8_t* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2 * i + 0] = kHex[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = kHex[(data[i] >> 0) & 0xF];
    }
    return out;
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

// Minimal SHA-256 implementation (FIPS 180-4 compliant)
// Public-domain style, compact single-file routine for hashing buffers
namespace mini_sha256 {
    static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    static void hash(const uint8_t* data, size_t len, uint8_t out[32]) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

        uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
                 h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

        // Process in 64-byte blocks with padding
        uint64_t bit_len = static_cast<uint64_t>(len) * 8ull;
        size_t full = len & ~static_cast<size_t>(63);

        auto process_block = [&](const uint8_t* p){
            uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                w[i] = (uint32_t(p[4*i+0]) << 24) | (uint32_t(p[4*i+1]) << 16) |
                       (uint32_t(p[4*i+2]) << 8)  | (uint32_t(p[4*i+3]) << 0);
            }
            for (int i = 16; i < 64; ++i) {
                uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
                uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }

            uint32_t a=h0, b=h1, c=h2, d=h3, e=h4, f=h5, g=h6, h=h7;
            for (int i = 0; i < 64; ++i) {
                uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = h + S1 + ch + K[i] + w[i];
                uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;
                h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
        };

        // Process complete blocks
        for (size_t i = 0; i < full; i += 64) process_block(data + i);

        // Tail + padding
        uint8_t tail[128]{}; // enough for padding
        size_t tail_len = len - full;
        for (size_t i = 0; i < tail_len; ++i) tail[i] = data[full + i];
        tail[tail_len++] = 0x80; // append 1 bit

        if (tail_len > 56) {
            // not enough room for length, pad with zeros and process
            for (size_t i = tail_len; i < 64; ++i) tail[i] = 0;
            process_block(tail);
            // start a new block with zeros up to length
            for (size_t i = 0; i < 56; ++i) tail[i] = 0;
        } else {
            for (size_t i = tail_len; i < 56; ++i) tail[i] = 0;
        }

        // append big-endian 64-bit length
        tail[56] = uint8_t((bit_len >> 56) & 0xFF);
        tail[57] = uint8_t((bit_len >> 48) & 0xFF);
        tail[58] = uint8_t((bit_len >> 40) & 0xFF);
        tail[59] = uint8_t((bit_len >> 32) & 0xFF);
        tail[60] = uint8_t((bit_len >> 24) & 0xFF);
        tail[61] = uint8_t((bit_len >> 16) & 0xFF);
        tail[62] = uint8_t((bit_len >> 8) & 0xFF);
        tail[63] = uint8_t((bit_len >> 0) & 0xFF);

        process_block(tail);

        auto be32 = [](uint32_t x, uint8_t* o){
            o[0] = uint8_t((x >> 24) & 0xFF);
            o[1] = uint8_t((x >> 16) & 0xFF);
            o[2] = uint8_t((x >> 8) & 0xFF);
            o[3] = uint8_t((x >> 0) & 0xFF);
        };
        be32(h0, out + 0*4); be32(h1, out + 1*4); be32(h2, out + 2*4); be32(h3, out + 3*4);
        be32(h4, out + 4*4); be32(h5, out + 5*4); be32(h6, out + 6*4); be32(h7, out + 7*4);
    }
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

static bool checkSelfIntegrityCRC32(uint32_t expectedCrc) {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

static bool checkSelfIntegritySHA256(const char* expectedHex) {
    if (!expectedHex || !expectedHex[0]) return true; // nothing to enforce

    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    uint8_t digest[32];
    mini_sha256::hash(bytes.data(), bytes.size(), digest);
    std::string hex = hexLower(digest, 32);

    std::string want = toLower(std::string(expectedHex));
    // allow optional 0x prefix
    if (want.size() >= 2 && want[0] == '0' && (want[1] == 'x' || want[1] == 'X')) want = want.substr(2);

    return hex == want;
}

// --- Entry helper (embed a baseline CRC/SHA once you ship a build) ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set this at build time (e.g., -DJAVELIN_EXPECTED_CRC32=0x12345678)
#endif

#ifndef JAVELIN_EXPECTED_SHA256
#define JAVELIN_EXPECTED_SHA256 ""  // Set this at build time (e.g., -DJAVELIN_EXPECTED_SHA256=\"abcdef...\")
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return 0xDEB; // code for debugger
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return 0xBAD; // code for bad process
    }

    // Prefer SHA-256 if configured, otherwise CRC32 if configured
    if (JAVELIN_EXPECTED_SHA256[0] != '\0') {
        if (!checkSelfIntegritySHA256(JAVELIN_EXPECTED_SHA256)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
            return 0x1C7; // integrity failure
        }
    } else if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrityCRC32(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC32 mismatch). Exiting.\n";
            return 0x1C7; // integrity failure
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
