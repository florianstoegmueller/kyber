#include "../include/helpers.h"

#include <fstream>
#include <iostream>

#include "../include/base64.h"

std::string encode(const uint8_t* in, const int size) {
    std::string out("");
    if (in) {
        for (int i = 0; i < size; i++) {
            out = out + (char)in[i];
        }
        out = base64_encode(out);
    }
    return out;
}

void decode(std::string in, uint8_t* out, const int size) {
    if (out && !in.empty()) {
        in = base64_decode(in);
        for (int i = 0; i < size; i++) {
            out[i] = in[i];
        }
    }
}

int write(const std::string path, const std::string line, const bool append) {
    if (!path.empty()) {
        std::ofstream file(path, append ? std::ios::app : std::ios::out);
        if (file.is_open()) {
            file << line.c_str() << std::endl;
            file.close();
            return 1;
        }
    }
    return 0;
}

int read(const std::string path, std::string* text) {
    if (text && !path.empty()) {
        std::ifstream file(path);
        std::string line;
        if (file.is_open()) {
            int i = 0;
            while (getline(file, line)) {
                text[i++] = line;
            }
            file.close();
            return 1;
        }
    }
    return 0;
}
