// AntiCheat.cpp
// Javelin Project - minimal anti-cheat guards.
//
// Features:
// - debugger detection
// - suspicious process scan
// - optional self-integrity check using CRC32 of the running executable

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <tlhelp32.h>
#include <windows.h>
#else
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

namespace {

constexpr const char* kTag = "[Javelin AntiCheat] ";
constexpr int kExitDebugger = 0xDB;
constexpr int kExitSuspiciousProcess = 0xBA;
constexpr int kExitIntegrity = 0xC0;

const std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
};

// Keep the expected CRC in a single recognizable marker. CRC computation zeros
// only the four value bytes so embedding the expected CRC does not change the
// executable hash being verified.
unsigned char gIntegrityMarker[] = {
    'J', 'V', 'L', 'N', 'C', 'R', 'C', '3', '2', 'V', '1',
    static_cast<unsigned char>(JAVELIN_EXPECTED_CRC32 & 0xFFu),
    static_cast<unsigned char>((JAVELIN_EXPECTED_CRC32 >> 8) & 0xFFu),
    static_cast<unsigned char>((JAVELIN_EXPECTED_CRC32 >> 16) & 0xFFu),
    static_cast<unsigned char>((JAVELIN_EXPECTED_CRC32 >> 24) & 0xFFu),
    'E', 'N', 'D',
};

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string basename(std::string path) {
    const std::string::size_type slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        path = path.substr(slash + 1);
    }
    return path;
}

std::string stripExeSuffix(const std::string& name) {
    if (name.size() >= 4 && name.compare(name.size() - 4, 4, ".exe") == 0) {
        return name.substr(0, name.size() - 4);
    }
    return name;
}

bool isSuspiciousProcessName(const std::string& processName) {
    const std::string normalized = stripExeSuffix(toLower(basename(processName)));
    for (const std::string& bad : kSuspiciousProcesses) {
        if (normalized == stripExeSuffix(toLower(bad))) {
            return true;
        }
    }
    return false;
}

uint32_t expectedCrc32() {
    return static_cast<uint32_t>(gIntegrityMarker[11]) |
           (static_cast<uint32_t>(gIntegrityMarker[12]) << 8) |
           (static_cast<uint32_t>(gIntegrityMarker[13]) << 16) |
           (static_cast<uint32_t>(gIntegrityMarker[14]) << 24);
}

uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; ++i) {
            const uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

void canonicalizeIntegrityMarker(std::vector<uint8_t>& bytes) {
    static constexpr std::array<uint8_t, 11> kPrefix = {
        'J', 'V', 'L', 'N', 'C', 'R', 'C', '3', '2', 'V', '1',
    };
    static constexpr std::array<uint8_t, 3> kSuffix = {'E', 'N', 'D'};
    constexpr size_t kValueOffset = kPrefix.size();
    constexpr size_t kValueSize = 4;
    constexpr size_t kMarkerSize = kPrefix.size() + kValueSize + kSuffix.size();

    if (bytes.size() < kMarkerSize) {
        return;
    }

    for (size_t i = 0; i + kMarkerSize <= bytes.size(); ++i) {
        const bool prefixMatches = std::equal(kPrefix.begin(), kPrefix.end(), bytes.begin() + i);
        const bool suffixMatches = std::equal(
            kSuffix.begin(),
            kSuffix.end(),
            bytes.begin() + i + kValueOffset + kValueSize);
        if (prefixMatches && suffixMatches) {
            std::fill(
                bytes.begin() + i + kValueOffset,
                bytes.begin() + i + kValueOffset + kValueSize,
                0);
        }
    }
}

uint32_t integrityCrc32(std::vector<uint8_t> bytes) {
    canonicalizeIntegrityMarker(bytes);
    return crc32(bytes);
}

bool readFile(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    file.seekg(0, std::ios::end);
    const std::streamsize size = file.tellg();
    if (size <= 0) {
        return false;
    }

    file.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    return static_cast<bool>(file.read(reinterpret_cast<char*>(out.data()), size));
}

bool getExecutablePath(std::string& out) {
#ifdef _WIN32
    std::array<char, MAX_PATH> path{};
    const DWORD written = GetModuleFileNameA(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (written == 0 || written >= path.size()) {
        return false;
    }
    out.assign(path.data(), written);
    return true;
#elif defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    if (size == 0) {
        return false;
    }
    std::string path(size, '\0');
    if (_NSGetExecutablePath(path.data(), &size) != 0) {
        return false;
    }
    path.resize(std::char_traits<char>::length(path.c_str()));
    out = path;
    return true;
#else
    std::array<char, 4096> path{};
    const ssize_t written = readlink("/proc/self/exe", path.data(), path.size() - 1);
    if (written <= 0) {
        return false;
    }
    out.assign(path.data(), static_cast<size_t>(written));
    return true;
#endif
}

bool readExecutableBytes(std::vector<uint8_t>& out) {
    std::string path;
    return getExecutablePath(path) && readFile(path, out);
}

bool checkDebugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        return true;
    }
    BOOL remoteDebuggerPresent = FALSE;
    return CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebuggerPresent) &&
           remoteDebuggerPresent;
#else
    return false;
#endif
}

bool checkSuspiciousProcesses() {
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32A entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstA(snap, &entry)) {
        CloseHandle(snap);
        return false;
    }

    do {
        if (isSuspiciousProcessName(entry.szExeFile)) {
            CloseHandle(snap);
            return true;
        }
    } while (Process32NextA(snap, &entry));

    CloseHandle(snap);
    return false;
#else
    FILE* pipe = popen("ps -axo comm=", "r");
    if (pipe == nullptr) {
        return false;
    }

    std::array<char, 512> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        std::string processName(buffer.data());
        processName.erase(std::remove(processName.begin(), processName.end(), '\n'), processName.end());
        if (isSuspiciousProcessName(processName)) {
            pclose(pipe);
            return true;
        }
    }

    pclose(pipe);
    return false;
#endif
}

bool checkSelfIntegrity() {
    const uint32_t expected = expectedCrc32();
    if (expected == 0u) {
        return true;
    }

    std::vector<uint8_t> bytes;
    if (!readExecutableBytes(bytes)) {
        return false;
    }

    return integrityCrc32(bytes) == expected;
}

bool printCurrentIntegrityCrc32() {
    std::vector<uint8_t> bytes;
    if (!readExecutableBytes(bytes)) {
        return false;
    }

    std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << integrityCrc32(bytes)
              << "\n";
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--print-integrity-crc32") {
        return printCurrentIntegrityCrc32() ? 0 : kExitIntegrity;
    }

    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebugger;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kExitSuspiciousProcess;
    }

    if (!checkSelfIntegrity()) {
        std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
        return kExitIntegrity;
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
