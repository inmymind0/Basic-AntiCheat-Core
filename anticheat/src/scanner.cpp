#include "scanner.h"
#include "utils.h"
#include "xorstr.h"
#include <windows.h>
#include <tlhelp32.h>
#include <thread>
#include <vector>

Scanner::Scanner(HardwareID::HardwareProfile profile, std::string processName)
    : currentProfile(profile), targetProcessName(processName) {

    running = true;
    targetPID = 0;

    threats = {
        _X("cheatengine"), _X("ollydbg"), _X("wireshark"),
        _X("ida64"), _X("httpdebugger"), _X("processhacker"),
        _X("ksdumper"), _X("x64dbg")
    };

    allowedDLLs = {
        _X("discord_game_sdk.dll"),
        _X("steam_api64.dll"),
        _X("opengl32.dll"),
        _X("d3d11.dll"),
        _X("d3d9.dll"),
        _X("dxgi.dll")
    };
}

DWORD Scanner::GetPIDByName(const std::string& name) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (Utils::CleanString(pe32.szExeFile) == Utils::CleanString(name)) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return pid;
}

void Scanner::HandleDetection(const std::string& detectionName, const std::string& type, int pid) {
    Utils::Log("CRITICAL", "Threat detected (" + type + "): " + detectionName);

    HardwareID::BanUser(currentProfile, "Detected [" + type + "]: " + detectionName);

    if (targetPID != 0) {
        HANDLE hGame = OpenProcess(PROCESS_TERMINATE, FALSE, targetPID);
        if (hGame) {
            TerminateProcess(hGame, 0);
            CloseHandle(hGame);
        }
    }

    if (pid != 0 && pid != targetPID) {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProc) {
            TerminateProcess(hProc, 0);
            CloseHandle(hProc);
        }
    }

    MessageBoxA(NULL, _X("Prohibited activity detected. HWID ban implemented.").c_str(), _X("Security Alert").c_str(), MB_OK | MB_ICONERROR);
    exit(1);
}

void Scanner::ScanModules() {
    if (targetPID == 0) {
        targetPID = GetPIDByName(targetProcessName);
        if (targetPID == 0) return;
        Utils::Log("INFO", "Game Process Found: " + targetProcessName + " (PID: " + std::to_string(targetPID) + ")");
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPID);

    if (hSnap == INVALID_HANDLE_VALUE) {
        targetPID = 0;
        return;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnap, &me32)) {
        do {
            std::string dllName = me32.szModule;
            std::string dllPath = me32.szExePath;

            std::string dllNameLower = Utils::CleanString(dllName);
            std::string dllPathLower = Utils::CleanString(dllPath);

            if (dllPathLower.find(_X("c:\\windows\\")) != std::string::npos ||
                dllPathLower.find(_X("system32\\")) != std::string::npos ||
                dllPathLower.find(_X("syswow64\\")) != std::string::npos) {
                continue;
            }

            if (dllPathLower.find(_X("windowsapps\\")) != std::string::npos ||
                dllPathLower.find(_X("microsoft.windowsappruntime")) != std::string::npos) {
                continue;
            }

            if (dllNameLower.find(_X(".exe")) != std::string::npos) {
                continue;
            }

            bool isAllowed = false;
            for (const auto& allowed : allowedDLLs) {
                if (dllNameLower == Utils::CleanString(allowed)) {
                    isAllowed = true;
                    break;
                }
            }

            if (isAllowed) continue;

            HandleDetection(dllName + " (" + dllPath + ")", "DLL Injection", targetPID);

        } while (Module32Next(hSnap, &me32));
    }
    CloseHandle(hSnap);
}

BOOL CALLBACK Scanner::EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    char title[256];
    if (GetWindowTextA(hwnd, title, sizeof(title))) {
        Scanner* scanner = (Scanner*)lParam;
        std::string titleStr = title;
        std::string titleLower = Utils::CleanString(titleStr);

        for (const auto& threat : scanner->threats) {
            if (titleLower.find(threat) != std::string::npos) {
                if (titleLower.find(_X("anti-cheat")) != std::string::npos) continue;
                scanner->HandleDetection(titleStr, "Window");
                return FALSE;
            }
        }
    }
    return TRUE;
}

void Scanner::ScanWindows() {
    EnumWindows(EnumWindowsProc, (LPARAM)this);
}

void Scanner::ScanProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32)) {
        do {
            std::string pName = pe32.szExeFile;
            std::string pNameLower = Utils::CleanString(pName);

            if (pNameLower == "svchost.exe" || pNameLower == "explorer.exe" || pNameLower == "chrome.exe" || pNameLower == "searchui.exe") continue;

            for (const auto& threat : threats) {
                if (pNameLower.find(threat) != std::string::npos) {
                    HandleDetection(pName, "Process", pe32.th32ProcessID);
                }
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
}

void Scanner::Start() {
    Utils::Log("INFO", "Waiting for target process: " + targetProcessName);

    while (running) {
        ScanProcesses();
        ScanWindows();
        ScanModules();

        if (IsDebuggerPresent()) {
            HardwareID::BanUser(currentProfile, "Debugger (Basic)");
            exit(1);
        }

        BOOL remoteDb = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDb);
        if (remoteDb) {
            HardwareID::BanUser(currentProfile, "Debugger (Remote)");
            exit(1);
        }

        Sleep(2000);
    }
}