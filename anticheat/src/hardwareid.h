#pragma once
#include <string>
#include <vector>

class HardwareID {
public:
    struct HardwareProfile {
        std::string pcName;
        std::string cpuId;
        std::vector<std::string> diskSerials;
        std::string toString() const;
    };

    static HardwareProfile GetProfile();
    static bool IsBanned(const HardwareProfile& profile);
    static void BanUser(const HardwareProfile& profile, const std::string& reason);

private:
    static std::string GetPcName();
    static std::string GetCpuId();
    static std::string GetDriveSerial(int driveIndex);
};