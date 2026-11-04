// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32 + SHA-256)

#include <windows.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>

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

// SHA-256 using Windows CryptoAPI (zero external dependencies)
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
    if (!data.empty() && !CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    BYTE hash[32]{};
    DWORD hashLen = sizeof(hash);
    std::ostringstream oss;
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        oss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < hashLen; ++i) {
            oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
        }
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return toLower(oss.str());
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

static bool readExecutableBytes(std::vector<uint8_t>& bytes) {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    return readFile(path, bytes);
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
    if (!readExecutableBytes(bytes)) return false;
    return crc32(bytes) == expectedCrc;
}

static bool checkSelfIntegritySha256(const std::string& expectedSha256) {
    std::vector<uint8_t> bytes;
    if (!readExecutableBytes(bytes)) return false;
    std::string current = sha256Hex(bytes);
    return !current.empty() && current == toLower(expectedSha256);
}

// --- Build-time constants ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // e.g. /DJAVELIN_EXPECTED_CRC32=0x12345678u
#endif

#ifndef JAVELIN_EXPECTED_SHA256
#define JAVELIN_EXPECTED_SHA256 "" // e.g. /DJAVELIN_EXPECTED_SHA256="\"e3b0c442...\""
#endif

int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--print-hash") {
        std::vector<uint8_t> bytes;
        if (readExecutableBytes(bytes)) {
            std::cout << "CRC32:  0x" << std::hex << std::uppercase << crc32(bytes) << "\n";
            std::cout << "SHA256: " << sha256Hex(bytes) << "\n";
            return 0;
        }
        return 1;
    }

    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return 0xDEB;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return 0xBAD;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrityCrc32(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC32 mismatch). Guarded exit.\n";
            return 0xC4C;
        }
    }

    std::string expectedSha = JAVELIN_EXPECTED_SHA256;
    if (!expectedSha.empty()) {
        if (!checkSelfIntegritySha256(expectedSha)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Guarded exit.\n";
            return 0x5A2;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
