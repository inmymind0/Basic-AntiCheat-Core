#pragma once
#include <iostream>
#include <string>
#include <ctime>
#include <iomanip>
#include <algorithm>

namespace Utils {
    inline void Log(const std::string& type, const std::string& msg) {
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        std::cout << "[" << std::put_time(&tm, "%H:%M:%S") << "] "
            << "[" << type << "] " << msg << std::endl;
    }

    inline std::string CleanString(std::string str) {
        str.erase(std::remove_if(str.begin(), str.end(),
            [](unsigned char c) { return std::isspace(c) || !std::isprint(c); }), str.end());
        std::transform(str.begin(), str.end(), str.begin(), ::tolower);
        return str;
    }
}