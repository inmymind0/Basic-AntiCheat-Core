#include "HardwareID.h"
#include "Utils.h"
#include <windows.h>
#include <sstream>
#include <fstream>
#include <intrin.h>

// create report
std::string HardwareID::HardwareProfile::toString() const {
    std::stringstream ss;
    ss << "--- HARDWARE REPORT ---\n";
    ss << "PC Name    : " << pcName << "\n";
    ss << "CPU ID     : " << cpuId << "\n";
    for (size_t i = 0; i < diskSerials.size(); ++i) {
        ss << "Disk " << i << "     : " << diskSerials[i] << "\n";
    }
    ss << "-----------------------";
    return ss.str();
}

std::string HardwareID::GetPcName() {
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer);
    if (GetComputerNameA(buffer, &size)) return std::string(buffer);
    return "UNKNOWN";
}

std::string HardwareID::GetCpuId() {
    int cpuInfo[4] = { -1 };
    __cpuid(cpuInfo, 1);
    std::stringstream ss;
    ss << std::hex << cpuInfo[3] << "-" << cpuInfo[0];
    return Utils::CleanString(ss.str());
}

std::string HardwareID::GetDriveSerial(int driveIndex) {
    std::string path = "\\\\.\\PhysicalDrive" + std::to_string(driveIndex);
    HANDLE hDevice = CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return "";

    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    char buffer[1024] = { 0 };
    DWORD bytesReturned = 0;
    std::string result = "";

    if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &buffer, sizeof(buffer), &bytesReturned, NULL)) {
        STORAGE_DEVICE_DESCRIPTOR* desc = (STORAGE_DEVICE_DESCRIPTOR*)buffer;
        if (desc->SerialNumberOffset != 0) {
            result = Utils::CleanString(&buffer[desc->SerialNumberOffset]);
        }
    }
    CloseHandle(hDevice);
    return result;
}

HardwareID::HardwareProfile HardwareID::GetProfile() {
    HardwareProfile profile;
    profile.pcName = GetPcName();
    profile.cpuId = GetCpuId();
    for (int i = 0; i < 4; ++i) { // scan first 4 disk
        std::string s = GetDriveSerial(i);
        if (!s.empty()) profile.diskSerials.push_back(s);
    }
    return profile;
}

bool HardwareID::IsBanned(const HardwareProfile& profile) {
    std::ifstream file("hwidbanlist.txt");
    if (!file.is_open()) return false;
    std::string line;
    while (std::getline(file, line)) {
        if (line.find(profile.cpuId) != std::string::npos && profile.cpuId.length() > 5) return true;
        for (const auto& disk : profile.diskSerials) {
            if (disk.length() > 4 && line.find(disk) != std::string::npos) return true;
        }
    }
    return false;
}

void HardwareID::BanUser(const HardwareProfile& profile, const std::string& reason) {
    std::ofstream file("hwidbanlist.txt", std::ios::app);
    if (file.is_open()) {
        file << "REASON: " << reason << " | " << profile.toString() << "\n";
    }
}