#include "../integrity.h"
#include <iostream>

int main() {
    const unsigned char vector[] = "123456789";
    if (~javelin::updateCrc32(0xFFFFFFFFu, vector, 9) != 0xCBF43926u) return 1;
    auto state = javelin::updateCrc32(0xFFFFFFFFu, vector, 4);
    if (~javelin::updateCrc32(state, vector + 4, 5) != 0xCBF43926u) return 2;
    if (~javelin::updateCrc32(0xFFFFFFFFu, vector, 0) != 0) return 3;
    wchar_t directory[MAX_PATH], temporary[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, directory) || !GetTempFileNameW(directory, L"jvl", 0, temporary)) return 4;
    HANDLE file = CreateFileW(temporary, GENERIC_WRITE, 0, nullptr, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 5;
    DWORD written = 0;
    bool wrote = WriteFile(file, vector, 9, &written, nullptr) && written == 9;
    CloseHandle(file);
    std::uint32_t actual = 42;
    bool valid = wrote && javelin::fileCrc32(temporary, actual) && actual == 0xCBF43926u;
    DeleteFileW(temporary);
    if (!valid) return 6;
    actual = 42;
    if (javelin::fileCrc32(temporary, actual) || actual != 42) return 7;
    if (javelin::fileCrc32(directory, actual)) return 8;
    std::cout << "Native CRC vectors, streamed file, missing file, and directory checks passed.\n";
    return 0;
}
