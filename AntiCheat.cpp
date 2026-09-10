// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, integrity verification (SHA-256 + CRC32)

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <wincrypt.h>
#include <iomanip>

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

static bool readFile(const std::wstring& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) return false;
    return true;
}

// SHA-256 hash using Windows CryptoAPI
static bool sha256(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    bool result = false;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    DWORD hashLen = 32; // SHA-256 = 32 bytes
    hash.resize(hashLen);
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
        result = true;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

static std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        hex += buf;
    }
    return hex;
}

// --- Checks ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;
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
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

// --- Entry helper (embed a baseline CRC once you ship a build) ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set this at build time (e.g., /DJAVELIN_EXPECTED_CRC32=0x12345678)
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
    return current == expectedCrc;
}

// SHA-256 integrity verification
static bool checkSelfIntegritySHA256(const char* expectedHash) {
    if (!expectedHash || expectedHash[0] == '\0') return true; // skip if not set

    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    std::vector<uint8_t> hash;
    if (!sha256(bytes, hash)) return false;

    std::string currentHex = bytesToHex(hash);
    return currentHex == toLower(std::string(expectedHash));
}

// --- Entry helper (embed a baseline CRC once you ship a build) ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set this at build time (e.g., /DJAVELIN_EXPECTED_CRC32=0x12345678)
#endif

#ifndef JAVELIN_EXPECTED_SHA256
#define JAVELIN_EXPECTED_SHA256 ""  // Set at build time (e.g., /DJAVELIN_EXPECTED_SHA256=\"abc123...\")
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    }

    // SHA-256 integrity check (preferred, stronger than CRC32)
    if (JAVELIN_EXPECTED_SHA256[0] != '\0') {
        if (!checkSelfIntegritySHA256(JAVELIN_EXPECTED_SHA256)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
            return 0x256; // code for SHA-256 failure
        }
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrity(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";