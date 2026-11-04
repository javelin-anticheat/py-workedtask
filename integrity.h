#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace javelin {
// CRC-32/ISO-HDLC: same format as Python's zlib.crc32.
inline std::uint32_t updateCrc32(std::uint32_t state,
                                 const unsigned char* bytes, std::size_t size) {
    for (std::size_t i = 0; i < size; ++i) {
        state ^= bytes[i];
        for (int bit = 0; bit < 8; ++bit)
            state = (state >> 1) ^ (0xEDB88320u & (0u - (state & 1u)));
    }
    return state;
}

inline bool fileCrc32(const std::wstring& path, std::uint32_t& result) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    unsigned char buffer[64 * 1024];
    std::uint32_t state = 0xFFFFFFFFu;
    bool success = true;
    for (;;) {
        DWORD count = 0;
        if (!ReadFile(file, buffer, sizeof(buffer), &count, nullptr)) {
            success = false;
            break;
        }
        if (count == 0) break;
        state = updateCrc32(state, buffer, count);
    }
    CloseHandle(file);
    if (success) result = ~state;
    return success;
}

inline bool selfIntegrity(std::uint32_t expected) {
    // A growing buffer avoids silently hashing a truncated MAX_PATH filename.
    std::vector<wchar_t> path(256);
    for (;;) {
        DWORD size = GetModuleFileNameW(nullptr, path.data(),
                                         static_cast<DWORD>(path.size()));
        if (!size) return false;
        if (size < path.size()) {
            std::uint32_t actual = 0;
            return fileCrc32(std::wstring(path.data(), size), actual) && actual == expected;
        }
        if (path.size() >= 32768) return false;
        path.resize(path.size() * 2);
    }
}
}  // namespace javelin
