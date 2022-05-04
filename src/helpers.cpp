#include <fstream>
#include <iostream>

#include "../include/base64.h"
#include "../include/helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/kem.h"

#ifdef __cplusplus
}
#endif

std::string encode(const uint8_t in[], const int size) {
    std::string out("");
    if (in) {
        for (int i = 0; i < size; i++) {
            out = out + (char)in[i];
        }
        out = base64_encode(out);
    }
    return out;
}

int decode(std::string in, uint8_t out[], const int size) {
    if (out && !in.empty()) {
        in = base64_decode(in);
        for (int i = 0; i < size; i++) {
            out[i] = in[i];
        }
        return 1;
    }
    return 0;
}

int write(const std::string path, const std::string line, const bool append) {
    if (path.empty()) return 0;

    std::ofstream file(path, append ? std::ios::app : std::ios::out);
    if (file.is_open()) {
        file << line.c_str() << std::endl;
        file.close();
        return 1;
    }
    return 0;
}

int read(const std::string path, std::string text[]) {
    if (!text || path.empty()) return 0;

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
    return 0;
}

int parsePKFile(const std::string pk_file, uint8_t pk_out[], std::string &uid) {
    if (pk_file.empty() || !pk_out) return 0;

    std::string buf[2];
    if (!read(pk_file, buf)) return 0;
    if (!decode(buf[1], pk_out, CRYPTO_PUBLICKEYBYTES)) return 0;
    uid = buf[0];
    return 1;
}

int parseSKFile(const std::string sk_file, uint8_t sk_out[], std::string &uid) {
    if (sk_file.empty() || !sk_out) return 0;

    std::string buf[2];
    if (!read(sk_file, buf)) return 0;
    if (!decode(buf[1], sk_out, CRYPTO_SECRETKEYBYTES)) return 0;
    uid = buf[0];
    return 1;
}

int parseCTFile(const std::string ct_file, uint8_t ct_out[]) {
    if (ct_file.empty() || !ct_out) return 0;

    std::string buf[2];
    if (!read(ct_file, buf)) return 0;
    if (!decode(buf[0], ct_out, CRYPTO_CIPHERTEXTBYTES)) return 0;
    return 1;
}

int parseKeyFile(const std::string key_file, uint8_t key_out[]) {
    if (key_file.empty() || !key_out) return 0;

    std::string buf[2];
    if (!read(key_file, buf)) return 0;
    if (!decode(buf[0], key_out, CRYPTO_BYTES)) return 0;
    return 1;
}
