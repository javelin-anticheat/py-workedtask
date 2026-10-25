// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32 & SHA-256)

#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>

static const char* kTag = "[Javelin AntiCheat] ";
static const int kExitDebugger = 0xDEB;
static const int kExitBadProcess = 0xBAD;
static const int kExitIntegrityFailed = 3;

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

// Compute lowercase hex SHA-256 of buffer using Windows CryptoAPI
static std::string sha256Hex(const std::vector<uint8_t>& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    if (!data.empty()) {
        if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }
    BYTE digest[32]{};
    DWORD digestLen = sizeof(digest);
    std::ostringstream oss;
    if (CryptGetHashParam(hHash, HP_HASHVAL, digest, &digestLen, 0)) {
        oss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < digestLen; ++i) {
            oss << std::setw(2) << static_cast<unsigned int>(digest[i]);
        }
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return oss.str();
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

static bool readRunningExecutable(std::vector<uint8_t>& out) {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    return readFile(path, out);
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
    std::vector<uint8_t> bytes;
    if (!readRunningExecutable(bytes)) return false;
    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

static bool checkSelfIntegritySha256(const std::string& expectedHex) {
    std::vector<uint8_t> bytes;
    if (!readRunningExecutable(bytes)) return false;
    std::string current = toLower(sha256Hex(bytes));
    return !current.empty() && current == toLower(expectedHex);
}

// --- Build-time integrity constants ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

#ifndef JAVELIN_EXPECTED_SHA256
#define JAVELIN_EXPECTED_SHA256 ""
#endif

int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--print-hash") {
        std::vector<uint8_t> bytes;
        if (!readRunningExecutable(bytes)) {
            std::cerr << kTag << "Failed to read executable.\n";
            return 1;
        }
        std::cout << "CRC32: 0x" << std::hex << std::uppercase << crc32(bytes) << "\n";
        std::cout << "SHA256: " << sha256Hex(bytes) << "\n";
        return 0;
    }

    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebugger;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kExitBadProcess;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrityCrc32(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC32 mismatch). Guarded exit.\n";
            return kExitIntegrityFailed;
        }
    }

    std::string expectedSha256(JAVELIN_EXPECTED_SHA256);
    if (!expectedSha256.empty()) {
        if (!checkSelfIntegritySha256(expectedSha256)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Guarded exit.\n";
            return kExitIntegrityFailed;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
