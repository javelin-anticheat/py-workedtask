// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32 or SHA-256)

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>

// Detect availability of bcrypt.h
#if defined(_WIN32)
#  if defined(__has_include)
#    if __has_include(<bcrypt.h>)
#      define JAVELIN_HAVE_BCRYPT 1
#      include <bcrypt.h>    // For SHA-256 (CNG)
#    endif
#  endif
#endif
#ifndef JAVELIN_HAVE_BCRYPT
#  define JAVELIN_HAVE_BCRYPT 0
#endif

#if defined(_MSC_VER) && JAVELIN_HAVE_BCRYPT
#  pragma comment(lib, "Bcrypt.lib")
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

// Read entire file using Win32 (supports wide paths reliably)
static bool readFile(const std::wstring& path, std::vector<uint8_t>& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER li{};
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0) {
        CloseHandle(h);
        return false;
    }

    out.resize(static_cast<size_t>(li.QuadPart));
    DWORD total = 0;
    while (total < out.size()) {
        DWORD read = 0;
        if (!ReadFile(h, out.data() + total, static_cast<DWORD>(out.size() - total), &read, nullptr)) {
            CloseHandle(h);
            return false;
        }
        if (read == 0) break;
        total += read;
    }
    CloseHandle(h);
    return total == out.size();
}

#if JAVELIN_HAVE_BCRYPT
// SHA-256 via CNG (Bcrypt)
static bool sha256(const std::vector<uint8_t>& data, std::vector<uint8_t>& digestOut) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD objLen = 0, cbData = 0, hashLen = 0;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st < 0) goto Cleanup;

    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cbData, 0);
    if (st < 0) goto Cleanup;
    st = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cbData, 0);
    if (st < 0) goto Cleanup;

    std::vector<uint8_t> obj(objLen);
    digestOut.resize(hashLen);

    st = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, nullptr, 0, 0);
    if (st < 0) goto Cleanup;
    st = BCryptHashData(hHash, const_cast<PUCHAR>(reinterpret_cast<const PUCHAR>(data.data())), static_cast<ULONG>(data.size()), 0);
    if (st < 0) goto Cleanup;
    st = BCryptFinishHash(hHash, reinterpret_cast<PUCHAR>(digestOut.data()), static_cast<ULONG>(digestOut.size()), 0);
    if (st < 0) goto Cleanup;

Cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return st >= 0;
}
#endif

static std::string toHex(const uint8_t* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2 * i + 0] = kHex[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = kHex[data[i] & 0xF];
    }
    return out;
}

// --- Checks ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;

    // Secondary anti-debug without compiler-specific intrinsics
    typedef BOOL (WINAPI *PFN_CheckRemoteDebuggerPresent)(HANDLE, PBOOL);
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (hKernel) {
        auto pCheck = reinterpret_cast<PFN_CheckRemoteDebuggerPresent>(GetProcAddress(hKernel, "CheckRemoteDebuggerPresent"));
        if (pCheck) {
            BOOL remote = FALSE;
            if (pCheck(GetCurrentProcess(), &remote) && remote) return true;
        }
    }
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
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

#if JAVELIN_HAVE_BCRYPT
static bool checkSelfIntegritySHA256(const char* expectedHex) {
    if (!expectedHex || !*expectedHex) return true;
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    std::vector<uint8_t> digest;
    if (!sha256(bytes, digest)) return false;

    std::string got = toHex(digest.data(), digest.size());
    std::string exp = expectedHex;
    got = toLower(got);
    exp = toLower(exp);
    return got == exp;
}
#else
static bool checkSelfIntegritySHA256(const char* /*expectedHex*/) {
    // SHA-256 unavailable on this toolchain; skip check
    return true;
}
#endif

// --- Entry helper (embed a baseline CRC once you ship a build) ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set at build time (e.g., /DJAVELIN_EXPECTED_CRC32=0x12345678)
#endif
#ifndef JAVELIN_EXPECTED_SHA256_STR
#define JAVELIN_EXPECTED_SHA256_STR ""  // 64 hex chars; set at build time (e.g., /DJAVELIN_EXPECTED_SHA256_STR=\"<hex>\")
#endif

#define EXIT_DEBUGGER       0x0DEB
#define EXIT_BADPROC        0x0BAD
#define EXIT_INTEGRITY_CRC  0x0C1C
#define EXIT_INTEGRITY_SHA  0x05A6

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return EXIT_DEBUGGER; // code for debugger
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return EXIT_BADPROC; // code for bad process
    }

    // Prefer SHA-256 if provided; else CRC32 if non-zero
    if (std::char_traits<char>::length(JAVELIN_EXPECTED_SHA256_STR) > 0) {
#if JAVELIN_HAVE_BCRYPT
        if (!checkSelfIntegritySHA256(JAVELIN_EXPECTED_SHA256_STR)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
            return EXIT_INTEGRITY_SHA;
        }
#else
        // Auto-fallback to CRC32 if provided
        if (JAVELIN_EXPECTED_CRC32 != 0u) {
            std::cerr << kTag << "SHA-256 requested but bcrypt is unavailable; falling back to CRC32.\n";
            if (!checkSelfIntegrity(JAVELIN_EXPECTED_CRC32)) {
                std::cerr << kTag << "Integrity check failed (CRC32 mismatch). Exiting.\n";
                return EXIT_INTEGRITY_CRC;
            }
        } else {
            std::cerr << kTag << "SHA-256 requested but bcrypt is unavailable and no CRC32 provided; skipping integrity check.\n";
        }
#endif
    } else if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrity(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC32 mismatch). Exiting.\n";
            return EXIT_INTEGRITY_CRC;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
