// Compile the production implementation, but never call its anti-debug/process checks.
#define main antiCheatMainNotCalled
#include "../AntiCheat.cpp"
#undef main

int main() {
    int result = integrityExitCode();
    if (result == 0) std::cout << "Integrity-only harness: passed or disabled.\n";
    return result;
}
