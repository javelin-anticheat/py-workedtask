// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32 + SHA-256)

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

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include <unistd.h>
#else
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#endif

static const char* kTag = "[Javelin AntiCheat] ";
static constexpr int kExitDebugger = 10;
static constexpr int kExitSuspiciousProcess = 11;
static constexpr int kExitIntegrityMismatch = 12;

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

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

// IEEE 802.3 CRC32 (polynomial 0xEDB88320)
static uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            uint32_t mask = static_cast<uint32_t>(-static_cast<int32_t>(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

// Self-contained RFC 6234 SHA-256 implementation (zero external library dependencies)
static std::string sha256Hex(const std::vector<uint8_t>& data) {
    static constexpr std::array<uint32_t, 64> kRoundConstants = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };

    auto rotr = [](uint32_t x, uint32_t n) -> uint32_t {
        return (x >> n) | (x << (32u - n));
    };

    std::array<uint32_t, 8> h = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };

    uint64_t bitLen = static_cast<uint64_t>(data.size()) * 8u;
    std::vector<uint8_t> msg(data);
    msg.push_back(0x80u);
    while ((msg.size() % 64u) != 56u) {
        msg.push_back(0x00u);
    }
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xFFu));
    }

    for (size_t offset = 0; offset < msg.size(); offset += 64u) {
        std::array<uint32_t, 64> w{};
        for (size_t i = 0; i < 16u; ++i) {
            size_t j = offset + i * 4u;
            w[i] = (static_cast<uint32_t>(msg[j]) << 24u) |
                   (static_cast<uint32_t>(msg[j + 1]) << 16u) |
                   (static_cast<uint32_t>(msg[j + 2]) << 8u) |
                   static_cast<uint32_t>(msg[j + 3]);
        }
        for (size_t i = 16u; i < 64u; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7u) ^ rotr(w[i - 15], 18u) ^ (w[i - 15] >> 3u);
            uint32_t s1 = rotr(w[i - 2], 17u) ^ rotr(w[i - 2], 19u) ^ (w[i - 2] >> 10u);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (size_t i = 0; i < 64u; ++i) {
            uint32_t S1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + kRoundConstants[i] + w[i];
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

static bool isValidSha256Hex(const std::string& hex) {
    if (hex.size() != 64u) return false;
    return std::all_of(hex.begin(), hex.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

static bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

static bool readExecutableBytes(const char* argv0, std::vector<uint8_t>& out) {
#ifdef _WIN32
    wchar_t wpath[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, wpath, MAX_PATH)) {
        std::ifstream wf(wpath, std::ios::binary);
        if (wf) {
            wf.seekg(0, std::ios::end);
            std::streamsize sz = wf.tellg();
            if (sz > 0) {
                wf.seekg(0, std::ios::beg);
                out.resize(static_cast<size_t>(sz));
                if (wf.read(reinterpret_cast<char*>(out.data()), sz)) return true;
            }
        }
    }
#elif defined(__APPLE__)
    uint32_t bufSize = 0;
    _NSGetExecutablePath(nullptr, &bufSize);
    if (bufSize > 0) {
        std::vector<char> pathBuf(bufSize, '\0');
        if (_NSGetExecutablePath(pathBuf.data(), &bufSize) == 0) {
            std::ifstream f(pathBuf.data(), std::ios::binary);
            if (f) {
                out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
                if (!out.empty()) return true;
            }
        }
    }
#else
    char linkBuf[PATH_MAX]{};
    ssize_t len = readlink("/proc/self/exe", linkBuf, sizeof(linkBuf) - 1);
    if (len > 0) {
        linkBuf[len] = '\0';
        std::ifstream f(linkBuf, std::ios::binary);
        if (f) {
            out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
            if (!out.empty()) return true;
        }
    }
#endif
    if (argv0 && argv0[0] != '\0') {
        std::ifstream f(argv0, std::ios::binary);
        if (f) {
            out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
            return !out.empty();
        }
    }
    return false;
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
#elif defined(__APPLE__)
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info{};
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, nullptr, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
    return false;
#else
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            std::string val = line.substr(10);
            return std::stoi(val) != 0;
        }
    }
    return false;
#endif
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
    return false;
#else
    (void)kSuspiciousProcesses;
    return false;
#endif
}

static bool checkSelfIntegrityCrc32(const std::vector<uint8_t>& bytes, uint32_t expectedCrc) {
    if (bytes.empty()) return false;
    return crc32(bytes) == expectedCrc;
}

static bool checkSelfIntegritySha256(const std::vector<uint8_t>& bytes, const std::string& expectedHex) {
    if (bytes.empty()) return false;
    std::string normalized = toLower(expectedHex);
    if (!isValidSha256Hex(normalized)) return false;
    std::string actual = sha256Hex(bytes);
    return constantTimeEquals(actual, normalized);
}

// --- Build-time integrity configuration ---
// Pass -DJAVELIN_EXPECTED_CRC32=0x12345678u and/or
// -DJAVELIN_EXPECTED_SHA256="64-hex-digest" at compile time.
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

#ifndef JAVELIN_EXPECTED_SHA256
#define JAVELIN_EXPECTED_SHA256 ""
#endif

int main(int argc, char* argv[]) {
    const char* argv0 = (argc > 0) ? argv[0] : nullptr;

    if (argc > 1 && std::string(argv[1]) == "--print-hashes") {
        std::vector<uint8_t> exeBytes;
        if (!readExecutableBytes(argv0, exeBytes)) {
            std::cerr << kTag << "Unable to read executable image.\n";
            return kExitIntegrityMismatch;
        }
        std::cout << "CRC32=0x" << std::hex << std::uppercase << std::setw(8)
                  << std::setfill('0') << crc32(exeBytes) << std::dec << "\n";
        std::cout << "SHA256=" << sha256Hex(exeBytes) << "\n";
        return 0;
    }

    std::cout << kTag << "starting checks...\n";

    bool skipRuntimeScan = false;
#ifdef JAVELIN_SKIP_RUNTIME_SCAN
    skipRuntimeScan = true;
#endif
    if (!skipRuntimeScan) {
        if (checkDebugger()) {
            std::cerr << kTag << "Debugger detected. Exiting.\n";
            return kExitDebugger;
        }

        if (checkSuspiciousProcesses()) {
            std::cerr << kTag << "Suspicious process detected. Exiting.\n";
            return kExitSuspiciousProcess;
        }
    }

    const std::string expectedSha256(JAVELIN_EXPECTED_SHA256);
    if (JAVELIN_EXPECTED_CRC32 != 0u || !expectedSha256.empty()) {
        std::vector<uint8_t> exeBytes;
        if (!readExecutableBytes(argv0, exeBytes)) {
            std::cerr << kTag << "Integrity check failed (unable to read executable). Exiting.\n";
            return kExitIntegrityMismatch;
        }

        if (JAVELIN_EXPECTED_CRC32 != 0u) {
            if (!checkSelfIntegrityCrc32(exeBytes, JAVELIN_EXPECTED_CRC32)) {
                std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
                return kExitIntegrityMismatch;
            }
        }

        if (!expectedSha256.empty()) {
            if (!checkSelfIntegritySha256(exeBytes, expectedSha256)) {
                std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
                return kExitIntegrityMismatch;
            }
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
