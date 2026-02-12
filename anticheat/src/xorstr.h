#pragma once
#include <string>
#include <array>

template <size_t N>
class XorStr {
private:
    std::array<char, N> encrypted;

public:
    constexpr XorStr(const char(&str)[N]) : encrypted() {
        for (size_t i = 0; i < N; ++i) {
            encrypted[i] = str[i] ^ 0x55;
        }
    }

    std::string decrypt() const {
        std::string decrypted;
        decrypted.reserve(N);
        for (size_t i = 0; i < N; ++i) {
            decrypted.push_back(encrypted[i] ^ 0x55);
        }

        if (!decrypted.empty() && decrypted.back() == '\0') {
            decrypted.pop_back();
        }
        return decrypted;
    }
};

#define _X(s) XorStr<sizeof(s)>(s).decrypt()