// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, basic self-integrity (CRC32)

#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cwctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#ifdef _MSC_VER
#include <intrin.h>
#endif

static const char* kTag = "[Javelin AntiCheat] ";

#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

// Keep the expected value in a marked field so it can be excluded while hashing
// the executable. This avoids making the build-time CRC depend on itself.
static constexpr char kCrcBeginMarker[] = "JAVELIN_CRC32_BEGIN";
static constexpr char kCrcEndMarker[] = "JAVELIN_CRC32_END";

struct IntegrityConfig {
    char begin[sizeof(kCrcBeginMarker)];
    uint32_t expectedCrc32;
    char end[sizeof(kCrcEndMarker)];
};

static_assert(
    offsetof(IntegrityConfig, expectedCrc32) == sizeof(kCrcBeginMarker),
    "Unexpected padding before expected CRC32"
);
static_assert(
    offsetof(IntegrityConfig, end) ==
        sizeof(kCrcBeginMarker) + sizeof(uint32_t),
    "Unexpected padding after expected CRC32"
);

static volatile const IntegrityConfig kIntegrityConfig = {
    "JAVELIN_CRC32_BEGIN",
    JAVELIN_EXPECTED_CRC32,
    "JAVELIN_CRC32_END"
};

static constexpr int kIntegrityFailureExitCode = 0xC0C;

// --- Configurable lists ---
static std::vector<std::wstring> kSuspiciousProcesses = {
    L"cheatengine.exe",
    L"ollydbg.exe",
    L"x64dbg.exe",
    L"httpdebuggerui.exe",
    L"ida.exe",
    L"ida64.exe",
    L"scylla.exe",
    L"processhacker.exe"
};

// --- Utils ---
static std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
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
    FILE* file = _wfopen(path.c_str(), L"rb");
    if (!file) return false;

    uint8_t buffer[16 * 1024];
    while (true) {
        const size_t count = std::fread(buffer, 1, sizeof(buffer), file);
        out.insert(out.end(), buffer, buffer + count);

        if (count < sizeof(buffer)) {
            if (std::ferror(file)) {
                std::fclose(file);
                return false;
            }
            break;
        }
    }

    std::fclose(file);
    return !out.empty();
}

template <typename T>
static bool readValue(
    const std::vector<uint8_t>& data,
    size_t offset,
    T& value
) {
    if (offset > data.size() || sizeof(T) > data.size() - offset) return false;

    std::memcpy(&value, data.data() + offset, sizeof(T));
    return true;
}

static bool zeroRange(
    std::vector<uint8_t>& data,
    size_t offset,
    size_t count
) {
    if (offset > data.size() || count > data.size() - offset) return false;

    auto begin =
        data.begin() +
        static_cast<std::vector<uint8_t>::difference_type>(offset);
    std::fill(begin, begin + count, uint8_t{0});
    return true;
}

static bool normalizePeMetadata(std::vector<uint8_t>& data) {
    IMAGE_DOS_HEADER dosHeader{};
    if (!readValue(data, 0, dosHeader)) return false;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew < 0) {
        return false;
    }

    const size_t ntHeaderOffset = static_cast<size_t>(dosHeader.e_lfanew);
    DWORD signature = 0;
    if (!readValue(data, ntHeaderOffset, signature)) return false;
    if (signature != IMAGE_NT_SIGNATURE) return false;

    const size_t fileHeaderOffset = ntHeaderOffset + sizeof(DWORD);
    IMAGE_FILE_HEADER fileHeader{};
    if (!readValue(data, fileHeaderOffset, fileHeader)) return false;

    const size_t timestampOffset =
        fileHeaderOffset + offsetof(IMAGE_FILE_HEADER, TimeDateStamp);
    if (!zeroRange(data, timestampOffset, sizeof(DWORD))) return false;

    const size_t optionalHeaderOffset =
        fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    WORD optionalMagic = 0;
    if (!readValue(data, optionalHeaderOffset, optionalMagic)) return false;

    size_t checksumOffset = 0;
    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        checksumOffset = offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum);
    } else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        checksumOffset = offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum);
    } else {
        return false;
    }

    if (fileHeader.SizeOfOptionalHeader < checksumOffset + sizeof(DWORD)) {
        return false;
    }

    return zeroRange(
        data,
        optionalHeaderOffset + checksumOffset,
        sizeof(DWORD)
    );
}

template <size_t N>
static bool markerMatches(
    const std::vector<uint8_t>& data,
    size_t offset,
    const char (&marker)[N]
) {
    if (offset > data.size() || N > data.size() - offset) return false;

    return std::equal(
        marker,
        marker + N,
        data.begin() +
            static_cast<std::vector<uint8_t>::difference_type>(offset)
    );
}

static bool normalizeExpectedCrcField(std::vector<uint8_t>& data) {
    constexpr size_t kFieldSize = sizeof(uint32_t);
    constexpr size_t kConfigSize =
        sizeof(kCrcBeginMarker) + kFieldSize + sizeof(kCrcEndMarker);

    if (data.size() < kConfigSize) return false;

    size_t matches = 0;
    for (size_t offset = 0; offset <= data.size() - kConfigSize; ++offset) {
        if (!markerMatches(data, offset, kCrcBeginMarker)) continue;

        const size_t fieldOffset = offset + sizeof(kCrcBeginMarker);
        const size_t endOffset = fieldOffset + kFieldSize;
        if (!markerMatches(data, endOffset, kCrcEndMarker)) continue;

        auto fieldBegin =
            data.begin() +
            static_cast<std::vector<uint8_t>::difference_type>(fieldOffset);
        std::fill(fieldBegin, fieldBegin + kFieldSize, uint8_t{0});
        ++matches;
    }

    return matches == 1;
}

static bool calculateSelfCrc32(uint32_t& currentCrc) {
    wchar_t path[MAX_PATH]{};
    const DWORD pathLength = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (pathLength == 0 || pathLength >= MAX_PATH) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;
    if (!normalizePeMetadata(bytes)) return false;
    if (!normalizeExpectedCrcField(bytes)) return false;

    currentCrc = crc32(bytes);
    return true;
}

// --- Checks ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;

    // Secondary anti-debug: CheckBeingDebugged flag in PEB (best-effort)
#if defined(_MSC_VER) && defined(_M_IX86)
    // 32-bit: fs:[30h] -> PEB, offset 2 = BeingDebugged (BYTE)
    __try {
        BYTE* peb = reinterpret_cast<BYTE*>(_readfsdword(0x30));
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_MSC_VER) && defined(_M_X64)
    // 64-bit: gs:[60h] -> PEB
    __try {
        BYTE* peb = reinterpret_cast<BYTE*>(_readgsqword(0x60));
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif

    return false;
}

static bool checkSuspiciousProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
        std::wstring name = toLower(pe.szExeFile);
        for (const auto& bad : kSuspiciousProcesses) {
            if (name == toLower(bad)) {
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return false;
}

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string(argv[1]) == "--print-self-crc32") {
        uint32_t currentCrc = 0;
        if (!calculateSelfCrc32(currentCrc)) {
            std::cerr << kTag << "Unable to calculate executable CRC32.\n";
            return kIntegrityFailureExitCode;
        }

        std::cout
            << "0x"
            << std::uppercase
            << std::hex
            << std::setw(8)
            << std::setfill('0')
            << currentCrc
            << "\n";
        return 0;
    }

    if (argc != 1) {
        std::cerr << "Usage: AntiCheat.exe [--print-self-crc32]\n";
        return 2;
    }

    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return 0xDEB; // code for debugger
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return 0xBAD; // code for bad process
    }

    const uint32_t expectedCrc = kIntegrityConfig.expectedCrc32;
    if (expectedCrc != 0u) {
        uint32_t currentCrc = 0;
        if (!calculateSelfCrc32(currentCrc) || currentCrc != expectedCrc) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
            return kIntegrityFailureExitCode;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
