#include "includes.h"
#include "utils.h"
#include "hardwareid.h"
#include "scanner.h"
#include "xorstr.h"

int main() {
    SetConsoleTitleA("AC Core");

    Utils::Log("INIT", "System analysis...");
    auto profile = HardwareID::GetProfile();
    std::cout << profile.toString() << std::endl;

    if (HardwareID::IsBanned(profile)) {
        Utils::Log("BLOCK", "ACCESS DENIED: HWID BANNED.");
        MessageBoxA(NULL, "Hardware ID Ban Active.", "ERROR", MB_OK);
        return 0;
    }

    Utils::Log("SUCCESS", "System Clean. Engine starting.");

    Scanner scanner(profile, _X("notepad.exe"));
    scanner.Start();

    return 0;
}