// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32 + optional SHA-256)

#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "advapi32.lib")

static const char* kTag = "[Javelin AntiCheat] ";

static std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe", "ollydbg.exe", "x64dbg.exe", "httpdebuggerui.exe",
    "ida.exe", "ida64.exe", "scylla.exe", "processhacker.exe"
};

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// CRC32 (poly 0xEDB88320)
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
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), size));
}

static bool sha256Hex(const std::vector<uint8_t>& data, std::string& outHex) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;
    bool ok = false;
    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        if (CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
            DWORD len = 32;
            BYTE hash[32]{};
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &len, 0)) {
                std::ostringstream oss;
                for (DWORD i = 0; i < len; ++i)
                    oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                outHex = oss.str();
                ok = true;
            }
        }
        CryptDestroyHash(hHash);
    }
    CryptReleaseContext(hProv, 0);
    return ok;
}

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
    if (!Process32First(snap, &pe)) { CloseHandle(snap); return false; }
    do {
        std::string name = toLower(pe.szExeFile);
        for (const auto& bad : kSuspiciousProcesses) {
            if (name == toLower(bad)) { CloseHandle(snap); return true; }
        }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return false;
}

static bool getSelfPath(std::wstring& pathOut) {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    pathOut = path;
    return true;
}

static bool checkSelfIntegrityCrc(uint32_t expectedCrc) {
    std::wstring path;
    if (!getSelfPath(path)) return false;
    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;
    return crc32(bytes) == expectedCrc;
}

static bool checkSelfIntegritySha256(const std::string& expectedLowerHex) {
    if (expectedLowerHex.empty()) return true;
    std::wstring path;
    if (!getSelfPath(path)) return false;
    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;
    std::string got;
    if (!sha256Hex(bytes, got)) return false;
    std::string exp = expectedLowerHex;
    for (char& c : exp) c = (char)tolower((unsigned char)c);
    return got == exp;
}

#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

// Optional: /DJAVELIN_EXPECTED_SHA256=\"abc...\"  (64 hex chars). Empty = skip.
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
    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrityCrc(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC32 mismatch). Exiting.\n";
            return 0xC32;
        }
    }
    {
        std::string expectedSha = JAVELIN_EXPECTED_SHA256;
        if (!expectedSha.empty()) {
            if (!checkSelfIntegritySha256(expectedSha)) {
                std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
                return 0xA56;
            }
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
