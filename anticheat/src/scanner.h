#pragma once
#include "hardwareid.h"
#include <vector>
#include <string>
#include <windows.h>

class Scanner {
private:
    bool running;
    HardwareID::HardwareProfile currentProfile;
    std::vector<std::string> threats;
    std::vector<std::string> allowedDLLs;

    std::string targetProcessName;
    DWORD targetPID;

public:
    Scanner(HardwareID::HardwareProfile profile, std::string processName);
    void Start();

private:
    void ScanProcesses();
    void ScanWindows();
    void ScanModules();
    void HandleDetection(const std::string& detectionName, const std::string& type, int pid = 0);

    DWORD GetPIDByName(const std::string& name);

    static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
};