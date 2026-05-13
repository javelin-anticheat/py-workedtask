// AntiCheat.cpp
// Javelin Project - baseline native anti-cheat guards.
//
// Implements the issue #2 acceptance criteria for the C++ client:
//   * exit when a debugger is attached
//   * exit when a known cheat/debugger process is running
//
// The Windows path uses Win32 APIs.  POSIX fallback paths keep the source
// buildable and locally verifiable on Linux/macOS while preserving the same
// process-name policy.

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <tlhelp32.h>
#include <windows.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#else
#include <fstream>
#include <sstream>
#if defined(__APPLE__)
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <unistd.h>
#endif
#endif

namespace {

constexpr const char* kTag = "[Javelin AntiCheat] ";
constexpr int kExitOk = 0;
constexpr int kExitDebugger = 17;
constexpr int kExitSuspiciousProcess = 18;

const std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "cheatengine-x86_64.exe",
    "cheat engine.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "ollydbg.exe",
    "ida.exe",
    "ida64.exe",
    "idaq.exe",
    "idaq64.exe",
    "scylla.exe",
    "scylla_x64.exe",
    "scylla_x86.exe",
    "processhacker.exe",
    "process hacker.exe",
    "httpdebuggerui.exe",
    "wireshark.exe",
    "fiddler.exe",
    "ghidra.exe",
};

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string basename(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }

    const auto slash = value.find_last_of("/\\");
    if (slash != std::string::npos) {
        value = value.substr(slash + 1);
    }
    return toLower(value);
}

bool isSuspiciousProcessName(const std::string& processName) {
    const std::string normalized = basename(processName);
    if (normalized.empty()) {
        return false;
    }

    if (std::find(kSuspiciousProcesses.begin(), kSuspiciousProcesses.end(), normalized) != kSuspiciousProcesses.end()) {
        return true;
    }

    const std::array<const char*, 4> suspiciousPrefixes = {"cheatengine", "x64dbg", "x32dbg", "ollydbg"};
    for (const char* prefix : suspiciousPrefixes) {
        if (normalized.rfind(prefix, 0) == 0) {
            return true;
        }
    }
    return false;
}

#ifdef _WIN32
std::string wideToUtf8(const wchar_t* value) {
    if (value == nullptr || value[0] == L'\0') {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }

    std::string out(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, out.data(), size, nullptr, nullptr);
    return out;
}

bool debuggerAttached() {
    if (IsDebuggerPresent()) {
        return true;
    }

    BOOL remoteDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebuggerPresent) && remoteDebuggerPresent) {
        return true;
    }

#if defined(_MSC_VER) && defined(_M_IX86)
    __try {
        const auto* peb = reinterpret_cast<const unsigned char*>(__readfsdword(0x30));
        if (peb != nullptr && peb[2] != 0) {
            return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#elif defined(_MSC_VER) && defined(_M_X64)
    __try {
        const auto* peb = reinterpret_cast<const unsigned char*>(__readgsqword(0x60));
        if (peb != nullptr && peb[2] != 0) {
            return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#endif

    return false;
}

std::vector<std::string> processNames() {
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
#else
#if defined(__linux__)
bool debuggerAttached() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            std::istringstream parser(line.substr(std::strlen("TracerPid:")));
            int tracerPid = 0;
            parser >> tracerPid;
            return tracerPid > 0;
        }
    }
    return false;
}
#elif defined(__APPLE__)
bool debuggerAttached() {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    kinfo_proc info{};
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, nullptr, 0) != 0) {
        return false;
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
#else
bool debuggerAttached() {
    return false;
}
#endif

std::vector<std::string> processNames() {
    std::vector<std::string> names;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("ps -A -o comm=", "r"), pclose);
    if (!pipe) {
        return names;
    }

    std::array<char, 4096> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        names.emplace_back(buffer.data());
    }
    return names;
}
#endif

std::string suspiciousProcess() {
    for (const auto& name : processNames()) {
        if (isSuspiciousProcessName(name)) {
            return basename(name);
        }
    }
    return {};
}

}  // namespace

int main() {
    std::cout << kTag << "starting checks...\n";

    if (debuggerAttached()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebugger;
    }

    const std::string suspicious = suspiciousProcess();
    if (!suspicious.empty()) {
        std::cerr << kTag << "Suspicious process detected: " << suspicious << ". Exiting.\n";
        return kExitSuspiciousProcess;
    }

    std::cout << kTag << "All clear. Continue.\n";
    return kExitOk;
}
