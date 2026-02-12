# AC-Core (User-Mode Anti-Cheat Base)

AC-Core is a modular, user-mode (Ring 3) anti-cheat framework written in C++. It is designed to demonstrate fundamental concepts of game security, including heuristic process scanning, window enumeration, module integrity checks (DLL injection detection), and hardware-based identification (HWID).

**Disclaimer:** This project is intended for **educational purposes** to understand how basic detection vectors operate within the Windows environment. It provides a foundational structure but is **not** a production-ready solution against sophisticated threats.

## ⚠️ User-Mode Limitations (Crucial Read)

This software operates entirely in **User Mode (Ring 3)**. While effective against generic tools, internal injectors, and script kiddies, it has inherent limitations:

* **Kernel Drivers:** It cannot detect or block cheats operating in Kernel Mode (Ring 0).
* **Hypervisors:** It cannot detect hypervisor-based attacks.
* **Advanced Spoofing:** Sophisticated HWID spoofers running at the kernel level can bypass the identification system.
* **Handle Stripping:** Cheats that strip handles using a driver can hide from this scanner.

**To build a robust anti-cheat solution, you must migrate critical detection logic (process stripping, callbacks, memory integrity) to a Kernel-Mode Driver.**

## 🛠 Features

* **Heuristic Process Scanning:** Monitors active processes against a signature list of known analysis tools (e.g., Cheat Engine, x64dbg, Wireshark).
* **Window Title Enumeration:** Detects tools that rename their executables but fail to mask their window titles (e.g., "Cheat Engine 7.5").
* **Module Injection Scanner:**
    * Monitors the target game process for unauthorized DLL injections.
    * **Smart Whitelist:** Automatically distinguishes between Windows system binaries (`System32`, `SysWOW64`, `WindowsApps`) and unauthorized modules.
    * Triggers HWID bans upon detecting unauthorized code injection.
* **Hardware ID (HWID) System:**
    * Generates a persistent fingerprint using **CPU ID + Physical Drive Serials** (SMART/IOCTL).
    * Includes a local ban management system (`hwidbanlist.txt`).
* **Security:**
    * **String Encryption:** Utilizes compile-time XOR encryption to hide sensitive strings (threat names, logic) from static analysis.

## 📂 Project Structure

The codebase follows a modular architecture for maintainability:

* `main.cpp`: Entry point. Initializes hardware profile and starts the security engine.
* `scanner.cpp/h`: Core logic for scanning processes, windows, and modules.
* `hardwareid.cpp/h`: Low-level hardware queries (SMBIOS/Disk IOCTL).
* `utils.h`: Helper functions for logging and string manipulation.
* `xorstr.h`: Template-based compile-time string encryption.
* `includes.h`: Precompiled header-style management.

## 🚀 Configuration & Usage

### Prerequisites
* Visual Studio 2019/2022 (C++17 or later)
* Windows SDK

### Setup
1.  **Target Process:** Open `main.cpp` and define the executable name of the game you wish to protect:
    ```cpp
    // Example: "cs2.exe" or "notepad.exe" for testing
    Scanner scanner(profile, _X("your_game_process.exe"));
    ```

2.  **Whitelist Management:** Open `scanner.cpp` and update the `allowedDLLs` vector with your game's legitimate dependencies (e.g., `discord_game_sdk.dll`, `steam_api64.dll`).

3.  **Build:**
    * Configuration: **Release / x64**
    * **Run as Administrator**: Essential for querying physical drive serials and accessing external process memory.

## 📜 License

MIT License. You are free to fork, modify, and extend this project. If you plan to use this in a live environment, **heavy modification and kernel-level integration are strongly recommended.**
