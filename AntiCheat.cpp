// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32 & SHA-256)

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#else
#include <limits.h>
#include <unistd.h>
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

namespace {

const char* kTag = "[Javelin AntiCheat] ";

constexpr int kExitDebuggerDetected = 0xDEB;
constexpr int kExitSuspiciousProcess = 0xBAD;
constexpr int kExitIntegrityFailed = 3;

// --- Configurable lists ---
const std::vector<std::string> kSuspiciousProcesses = {
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
std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string trimAndUnquote(std::string s) {
    auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && isSpace(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    while (!s.empty() && isSpace(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') ||
         (s.front() == '\'' && s.back() == '\''))) {
        s = s.substr(1, s.size() - 2);
    }
    return s;
}

bool isHexString(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

// Constant-time string comparison for fixed/equal-length digests
bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

// Simple CRC32 (polynomial 0xEDB88320)
uint32_t computeCrc32(const std::vector<uint8_t>& data) {
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

std::string formatCrc32Hex(uint32_t crc) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << crc;
    return oss.str();
}

// Portable SHA-256 (FIPS 180-4) with zero external dependencies
class Sha256 {
public:
    Sha256() { reset(); }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer_[bufferLen_++] = data[i];
            if (bufferLen_ == 64) {
                transform(buffer_.data());
                bitLen_ += 512;
                bufferLen_ = 0;
            }
        }
    }

    std::string finalHex() {
        uint64_t totalBits = bitLen_ + static_cast<uint64_t>(bufferLen_) * 8u;

        buffer_[bufferLen_++] = 0x80;
        if (bufferLen_ > 56) {
            while (bufferLen_ < 64) {
                buffer_[bufferLen_++] = 0x00;
            }
            transform(buffer_.data());
            bufferLen_ = 0;
        }
        while (bufferLen_ < 56) {
            buffer_[bufferLen_++] = 0x00;
        }
        for (int i = 7; i >= 0; --i) {
            buffer_[bufferLen_++] = static_cast<uint8_t>((totalBits >> (i * 8)) & 0xFFu);
        }
        transform(buffer_.data());

        std::ostringstream oss;
        oss << std::hex << std::nouppercase << std::setfill('0');
        for (uint32_t h : state_) {
            oss << std::setw(8) << h;
        }
        return oss.str();
    }

private:
    static inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    void reset() {
        state_ = {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
        };
        bitLen_ = 0;
        bufferLen_ = 0;
    }

    void transform(const uint8_t block[64]) {
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

        uint32_t w[64]{};
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = state_[0];
        uint32_t b = state_[1];
        uint32_t c = state_[2];
        uint32_t d = state_[3];
        uint32_t e = state_[4];
        uint32_t f = state_[5];
        uint32_t g = state_[6];
        uint32_t h = state_[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<uint32_t, 8> state_{};
    uint64_t bitLen_ = 0;
    std::array<uint8_t, 64> buffer_{};
    size_t bufferLen_ = 0;
};

std::string computeSha256(const std::vector<uint8_t>& data) {
    Sha256 hasher;
    if (!data.empty()) {
        hasher.update(data.data(), data.size());
    }
    return hasher.finalHex();
}

std::string getExecutablePath(const char* argv0) {
#ifdef _WIN32
    std::vector<char> buf(MAX_PATH, '\0');
    while (true) {
        DWORD len = GetModuleFileNameA(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (len == 0) {
            break;
        }
        if (len < buf.size() - 1) {
            return std::string(buf.data(), len);
        }
        if (buf.size() >= 32768) {
            break;
        }
        buf.resize(buf.size() * 2, '\0');
    }
#else
    std::vector<char> buf(4096, '\0');
    ssize_t len = readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (len > 0) {
        return std::string(buf.data(), static_cast<size_t>(len));
    }
#endif
    return argv0 ? std::string(argv0) : std::string();
}

bool readFile(const std::string& path, std::vector<uint8_t>& out) {
    if (path.empty()) {
        return false;
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) {
        return false;
    }
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), size));
}

// --- Checks ---
bool checkDebugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        return true;
    }

#ifdef _MSC_VER
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
#endif
    return false;
}

bool checkSuspiciousProcesses() {
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }

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
#endif
    return false;
}

bool checkSelfIntegrityCrc32(const std::vector<uint8_t>& bytes, uint32_t expectedCrc) {
    uint32_t current = computeCrc32(bytes);
    if (current != expectedCrc) {
        std::cerr << kTag << "Integrity check failed (CRC32 mismatch: expected "
                  << formatCrc32Hex(expectedCrc) << ", got "
                  << formatCrc32Hex(current) << "). Exiting.\n";
        return false;
    }
    return true;
}

bool checkSelfIntegritySha256(const std::vector<uint8_t>& bytes, const std::string& expectedRaw) {
    std::string expected = toLower(trimAndUnquote(expectedRaw));
    if (expected.size() != 64 || !isHexString(expected)) {
        std::cerr << kTag << "Integrity check failed (invalid build-time SHA-256 hash format). Exiting.\n";
        return false;
    }
    std::string current = computeSha256(bytes);
    if (!constantTimeEquals(current, expected)) {
        std::cerr << kTag << "Integrity check failed (SHA-256 mismatch: expected "
                  << expected << ", got " << current << "). Exiting.\n";
        return false;
    }
    return true;
}

} // namespace

// --- Build-time integrity configuration ---
// Set CRC32 at build time, e.g.:
//   -DJAVELIN_EXPECTED_CRC32=0x12345678u
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

#define JAVELIN_STR_HELPER(x) #x
#define JAVELIN_STR(x) JAVELIN_STR_HELPER(x)

// Optional build-time hash macro (supports 64-char SHA-256 or 0x... CRC32), e.g.:
//   -DEXPECTED_EXE_HASH=\"<64-char-sha256>\"
//   -DEXPECTED_EXE_HASH=0x12345678
#ifdef EXPECTED_EXE_HASH
static const char* kExpectedExeHash = JAVELIN_STR(EXPECTED_EXE_HASH);
#elif defined(JAVELIN_EXPECTED_SHA256)
static const char* kExpectedExeHash = JAVELIN_STR(JAVELIN_EXPECTED_SHA256);
#else
static const char* kExpectedExeHash = "";
#endif

static bool verifyBuildTimeIntegrity(const char* argv0) {
    const std::string expectedHash = trimAndUnquote(kExpectedExeHash);
    const bool hasCrc32Macro = (JAVELIN_EXPECTED_CRC32 != 0u);
    const bool hasHashMacro = !expectedHash.empty();

    if (!hasCrc32Macro && !hasHashMacro) {
        return true; // Optional integrity verification not configured for this build
    }

    std::string exePath = getExecutablePath(argv0);
    std::vector<uint8_t> bytes;
    if (!readFile(exePath, bytes)) {
        std::cerr << kTag << "Integrity check failed (unable to read running executable: "
                  << (exePath.empty() ? "<unknown>" : exePath) << "). Exiting.\n";
        return false;
    }

    if (hasCrc32Macro && !checkSelfIntegrityCrc32(bytes, static_cast<uint32_t>(JAVELIN_EXPECTED_CRC32))) {
        return false;
    }

    if (hasHashMacro) {
        std::string lower = toLower(expectedHash);
        if (lower.rfind("0x", 0) == 0 && lower.size() > 2 && lower.size() <= 10 && isHexString(lower.substr(2))) {
            uint32_t expectedCrc = static_cast<uint32_t>(std::stoul(lower, nullptr, 16));
            if (expectedCrc != 0u && !checkSelfIntegrityCrc32(bytes, expectedCrc)) {
                return false;
            }
        } else if (!checkSelfIntegritySha256(bytes, expectedHash)) {
            return false;
        }
    }

    return true;
}

int main(int argc, char* argv[]) {
    const char* argv0 = (argc > 0 && argv != nullptr) ? argv[0] : nullptr;

    if (argc > 1 && argv != nullptr && std::string(argv[1]) == "--print-hash") {
        std::string exePath = getExecutablePath(argv0);
        std::vector<uint8_t> bytes;
        if (!readFile(exePath, bytes)) {
            std::cerr << kTag << "Unable to read executable: " << exePath << "\n";
            return 1;
        }
        std::cout << "Executable: " << exePath << "\n"
                  << "CRC32:      " << formatCrc32Hex(computeCrc32(bytes)) << "\n"
                  << "SHA-256:    " << computeSha256(bytes) << "\n";
        return 0;
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

    if (!verifyBuildTimeIntegrity(argv0)) {
        return kExitIntegrityFailed;
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
