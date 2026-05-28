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
#include <iomanip>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")

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

static std::string toHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
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

// SHA-256 via Windows CNG (BCrypt)
static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(32, 0);
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return hash; // all zeros = failure

    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return hash; }

    status = BCryptHashData(hHash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return hash; }

    status = BCryptFinishHash(hHash, hash.data(), static_cast<ULONG>(hash.size()), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) return std::vector<uint8_t>(32, 0);
    return hash;
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
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
}

static bool checkSelfIntegrityCrc32(uint32_t expectedCrc) {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

static bool checkSelfIntegritySha256(const std::string& expectedHex) {
    if (expectedHex.empty() || expectedHex.length() != 64) return true; // skip if not configured

    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    std::vector<uint8_t> hash = sha256(bytes);

    // Check if hash is all zeros (crypto API failure)
    bool allZero = true;
    for (uint8_t b : hash) { if (b != 0) { allZero = false; break; } }
    if (allZero) return false;

    std::string currentHex = toHex(hash);
    return currentHex == expectedHex;
}

// --- Build-time constants ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

#ifndef JAVELIN_EXPECTED_SHA256
#define JAVELIN_EXPECTED_SHA256 ""
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return 0xDEB;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return 0xBAD;
    }

    // CRC32 integrity check
    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrityCrc32(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC32 mismatch). Exiting.\n";
            return 0xCRC;
        }
        std::cout << kTag << "CRC32 integrity OK.\n";
    }

    // SHA-256 integrity check (stronger; takes priority if both configured)
    if (strlen(JAVELIN_EXPECTED_SHA256) == 64) {
        if (!checkSelfIntegritySha256(JAVELIN_EXPECTED_SHA256)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
            return 0x256;
        }
        std::cout << kTag << "SHA-256 integrity OK.\n";
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
