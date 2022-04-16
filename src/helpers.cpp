#include <fstream>
#include <iostream>

#include "../include/helpers.h"
#include "../include/base64.h"

// TODO null checks

std::string encode(const uint8_t* in, const int size) {
    std::string out;
    for (int i = 0; i < size; i++) {
        out = out + (char)in[i];
    }
    return base64_encode(out);
}

void decode(std::string in, uint8_t* out, const int size) {
    in = base64_decode(in);
    for (int i = 0; i < size; i++) {
        out[i] = in[i];
    }
}

int write(const std::string path, const std::string text, const bool append) {
    std::ofstream file(path, append ?  std::ios::app : std::ios::out);
    if (file.is_open()) {
        file << text.c_str() << "\n";
        file.close();
        return 0;
    }
    return -1;
}

int read(const std::string path, std::string* text) {
    int i = 0;
    std::string line;
    std::ifstream file(path);
    if (file.is_open()) {
        while (getline(file, line)) {
            text[i++] = line;
        }
        file.close();
        return 0;
    }

    return -1;
}
