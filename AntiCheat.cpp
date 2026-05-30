// AntiCheat.cpp
// Javelin Project - baseline anti-cheat guards.
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
#include <iostream>
#include <sstream>
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
#include <sys/sysctl.h>
#endif
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

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string basename(std::string path) {
    const auto slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        path = path.substr(slash + 1);
    }
    return path;
}

std::string stripExeSuffix(const std::string& name) {
    constexpr const char* suffix = ".exe";
    if (name.size() >= 4 && name.compare(name.size() - 4, 4, suffix) == 0) {
        return name.substr(0, name.size() - 4);
    }
    return name;
}

bool isSuspiciousProcessName(const std::string& processName) {
    const std::string normalized = stripExeSuffix(toLower(basename(processName)));
    for (const std::string& bad : kSuspiciousProcesses) {
        const std::string suspicious = stripExeSuffix(toLower(bad));
        if (normalized == suspicious) {
            return true;
        }
    }
    return false;
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

bool checkDebugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        return true;
    }

    BOOL remoteDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebuggerPresent) &&
        remoteDebuggerPresent) {
        return true;
    }
    return false;
#elif defined(__linux__)
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            std::istringstream stream(line.substr(10));
            int tracerPid = 0;
            stream >> tracerPid;
            return tracerPid != 0;
        }
    }
    return false;
#elif defined(__APPLE__)
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    kinfo_proc info{};
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, nullptr, 0) != 0) {
        return false;
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
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
    FILE* pipe = popen("ps -axo comm", "r");
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

bool checkSelfIntegrity(uint32_t expectedCrc) {
    std::string path;
    if (!getExecutablePath(path)) {
        return false;
    }

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) {
        return false;
    }

    return crc32(bytes) == expectedCrc;
}

}  // namespace

#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebugger;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kExitSuspiciousProcess;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u && !checkSelfIntegrity(JAVELIN_EXPECTED_CRC32)) {
        std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
        return kExitIntegrity;
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
