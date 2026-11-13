// AntiCheat.cpp
// Javelin Project - Cross-platform Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32)

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#elif defined(__linux__)
#include <dirent.h>
#include <unistd.h>
#endif

static const char* kTag = "[Javelin AntiCheat] ";

static constexpr int kExitOk = 0;
static constexpr int kExitDebuggerDetected = 10;
static constexpr int kExitSuspiciousProcess = 11;
static constexpr int kExitIntegrityFailed = 12;

static const std::vector<std::string> kSuspiciousProcessStems = {
    "cheatengine",
    "ollydbg",
    "x64dbg",
    "x32dbg",
    "httpdebuggerui",
    "ida",
    "ida64",
    "scylla",
    "processhacker"
};

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static std::string normalizeProcessStem(const std::string& raw) {
    std::string s = raw;
    const auto slash = s.find_last_of("/\\");
    if (slash != std::string::npos) {
        s = s.substr(slash + 1);
    }
    s = toLower(s);
    if (s.size() > 4 && s.substr(s.size() - 4) == ".exe") {
        s = s.substr(0, s.size() - 4);
    }
    return s;
}

static bool matchesSuspiciousName(const std::string& procName) {
    const std::string stem = normalizeProcessStem(procName);
    if (stem.empty()) return false;
    for (const auto& bad : kSuspiciousProcessStems) {
        if (stem == bad) return true;
        if (stem.rfind(bad + "-", 0) == 0 || stem.rfind(bad + "_", 0) == 0) return true;
    }
    return false;
}

// Simple CRC32 (polynomial 0xEDB88320)
static uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            uint32_t mask = static_cast<uint32_t>(-(static_cast<int32_t>(crc & 1u)));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static bool readFileBytes(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), size));
}

static bool checkDebugger() {
#if defined(_WIN32)
    if (IsDebuggerPresent()) return true;
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        return true;
    }
#if defined(_M_IX86) && defined(_MSC_VER)
    __try {
        BYTE* peb = *(BYTE**)_readfsdword(0x30);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_M_X64) && defined(_MSC_VER)
    __try {
        BYTE* peb = *(BYTE**)_readgsqword(0x60);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
    return false;
#elif defined(__APPLE__)
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
            int tracerPid = std::stoi(line.substr(10));
            return tracerPid != 0;
        }
    }
    return false;
#else
    return false;
#endif
}

static bool checkSuspiciousProcesses() {
#if defined(_WIN32)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }
    do {
        if (matchesSuspiciousName(pe.szExeFile)) {
            CloseHandle(snap);
            return true;
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
#elif defined(__APPLE__)
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, nullptr, &size, nullptr, 0) != 0 || size == 0) return false;
    std::vector<struct kinfo_proc> procs(size / sizeof(struct kinfo_proc));
    if (sysctl(mib, 4, procs.data(), &size, nullptr, 0) != 0) return false;
    const size_t count = size / sizeof(struct kinfo_proc);
    for (size_t i = 0; i < count; ++i) {
        if (matchesSuspiciousName(procs[i].kp_proc.p_comm)) {
            return true;
        }
    }
    return false;
#elif defined(__linux__)
    DIR* dir = opendir("/proc");
    if (!dir) return false;
    struct dirent* ent = nullptr;
    while ((ent = readdir(dir)) != nullptr) {
        const std::string dname(ent->d_name);
        if (dname.empty() || !std::all_of(dname.begin(), dname.end(), ::isdigit)) continue;
        std::ifstream comm("/proc/" + dname + "/comm");
        std::string pname;
        if (std::getline(comm, pname) && matchesSuspiciousName(pname)) {
            closedir(dir);
            return true;
        }
    }
    closedir(dir);
    return false;
#else
    return false;
#endif
}

static bool checkSelfIntegrity(const std::string& exePath, uint32_t expectedCrc) {
    std::vector<uint8_t> bytes;
    if (!readFileBytes(exePath, bytes)) return false;
    return crc32(bytes) == expectedCrc;
}

#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

int main(int argc, char* argv[]) {
    bool simulateDebugger = false;
    bool simulateClean = false;
    std::string simulatedProcess;

    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--simulate-debugger") {
            simulateDebugger = true;
        } else if (arg == "--simulate-clean") {
            simulateClean = true;
        } else if (arg == "--simulate-process" && i + 1 < argc) {
            simulatedProcess = argv[++i];
        }
    }

    std::cout << kTag << "starting checks...\n";

    if (simulateDebugger || (!simulateClean && simulatedProcess.empty() && checkDebugger())) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebuggerDetected;
    }

    if ((!simulatedProcess.empty() && matchesSuspiciousName(simulatedProcess)) ||
        (!simulateClean && simulatedProcess.empty() && checkSuspiciousProcesses())) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kExitSuspiciousProcess;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u && argc > 0 && argv[0] != nullptr) {
        if (!checkSelfIntegrity(argv[0], JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
            return kExitIntegrityFailed;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return kExitOk;
}
