// AntiCheat.cpp
// Javelin Project - baseline anti-cheat guards.
//
// The client exits when a debugger is attached or a known cheat/debugging tool
// is running. Windows uses native APIs; other platforms keep the file buildable
// and provide best-effort process/debugger checks for CI validation.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <tlhelp32.h>
#include <windows.h>
#else
#include <array>
#include <cstdio>
#include <memory>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace {

constexpr const char* kTag = "[Javelin AntiCheat] ";
constexpr int kDebuggerExitCode = 0xDEB;
constexpr int kSuspiciousProcessExitCode = 0xBAD;
constexpr int kIntegrityExitCode = 0xC0DE;

const std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "cheatengine",
    "ollydbg.exe",
    "ollydbg",
    "x64dbg.exe",
    "x64dbg",
    "x32dbg.exe",
    "x32dbg",
    "httpdebuggerui.exe",
    "httpdebuggerui",
    "ida.exe",
    "ida",
    "ida64.exe",
    "ida64",
    "scylla.exe",
    "scylla",
    "processhacker.exe",
    "processhacker",
    "frida-server",
    "frida-trace"
};

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string basename(std::string value) {
    const auto slash = value.find_last_of("/\\");
    if (slash != std::string::npos) {
        value = value.substr(slash + 1);
    }
    return toLower(value);
}

bool isSuspiciousName(const std::string& processName) {
    const std::string normalized = basename(processName);
    return std::find(kSuspiciousProcesses.begin(), kSuspiciousProcesses.end(), normalized) !=
           kSuspiciousProcesses.end();
}

uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit) {
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

#ifdef _WIN32
std::string wideToUtf8(const wchar_t* value) {
    if (!value || value[0] == L'\0') {
        return {};
    }

    const int required = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (required <= 1) {
        return {};
    }

    std::string out(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, out.data(), required, nullptr, nullptr);
    out.pop_back();
    return out;
}

bool checkDebugger() {
    if (IsDebuggerPresent()) {
        return true;
    }

    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        return true;
    }

    return false;
}

std::vector<std::string> listProcessNames() {
    std::vector<std::string> names;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return names;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return names;
    }

    do {
        names.push_back(wideToUtf8(entry.szExeFile));
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return names;
}

std::string executablePath() {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) {
        return {};
    }
    return wideToUtf8(path);
}
#else
bool checkDebugger() {
#if defined(__APPLE__)
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info {};
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, nullptr, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
    return false;
#elif defined(__linux__)
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            const int tracerPid = std::atoi(line.substr(10).c_str());
            return tracerPid != 0;
        }
    }
    return false;
#else
    return false;
#endif
}

std::vector<std::string> listProcessNames() {
    std::vector<std::string> names;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("ps -axo comm=", "r"), pclose);
    if (!pipe) {
        return names;
    }

    std::array<char, 512> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        std::string name(buffer.data());
        while (!name.empty() && (name.back() == '\n' || name.back() == '\r')) {
            name.pop_back();
        }
        if (!name.empty()) {
            names.push_back(name);
        }
    }
    return names;
}

std::string executablePath() {
#if defined(__linux__)
    std::array<char, 4096> path{};
    const ssize_t length = readlink("/proc/self/exe", path.data(), path.size() - 1);
    if (length <= 0) {
        return {};
    }
    return std::string(path.data(), static_cast<size_t>(length));
#else
    return {};
#endif
}
#endif

bool checkSuspiciousProcesses() {
    for (const auto& name : listProcessNames()) {
        if (isSuspiciousName(name)) {
            return true;
        }
    }
    return false;
}

bool checkSelfIntegrity(uint32_t expectedCrc) {
    const std::string path = executablePath();
    if (path.empty()) {
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
        return kDebuggerExitCode;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kSuspiciousProcessExitCode;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u && !checkSelfIntegrity(JAVELIN_EXPECTED_CRC32)) {
        std::cerr << kTag << "Integrity check failed. Exiting.\n";
        return kIntegrityExitCode;
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
