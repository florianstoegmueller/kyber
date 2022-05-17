#include "../include/helpers.h"

#include <fstream>
#include <iostream>

#include "../include/aes.h"
#include "../include/base64.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/kem.h"

#ifdef __cplusplus
}
#endif

secure::string encode(const uint8_t in[], const int size) {
    secure::string out("");
    secure::string tmp("");
    if (in) {
        for (int i = 0; i < size; i++) {
            tmp += (char)in[i];
        }
        out += base64_encode(tmp);
    }
    return out;
}

int decode(secure::string in, uint8_t out[], const int size) {
    if (out && !in.empty()) {
        secure::string tmp(base64_decode(in));
        for (int i = 0; i < size; i++) {
            out[i] = tmp[i];
        }
        return 1;
    }
    return 0;
}

secure::string encode(secure::string in) { return base64_encode(in); }

secure::string decode(secure::string in) { return base64_decode(in); }

int write(const std::string path, const secure::string line,
          const bool append) {
    if (path.empty()) return 0;

    std::ofstream file(path, append ? std::ios::app : std::ios::out);
    if (file.is_open()) {
        file << line.c_str() << std::endl;
        file.close();
        return 1;
    }
    return 0;
}

int read(const std::string path, secure::string text[]) {
    if (!text || path.empty()) return 0;

    std::ifstream file(path);
    secure::string line;
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

    secure::string buf[2];
    if (!read(pk_file, buf)) return 0;
    if (!decode(buf[1], pk_out, CRYPTO_PUBLICKEYBYTES)) return 0;
    uid = buf[0];
    return 1;
}

int parseSKFile(const std::string sk_file, uint8_t sk_out[], std::string &uid) {
    if (sk_file.empty() || !sk_out) return 0;

    secure::string buf[2];
    if (!read(sk_file, buf)) return 0;
    if (!decode(buf[1], sk_out, CRYPTO_SECRETKEYBYTES)) return 0;
    uid = buf[0];
    return 1;
}

int parseSKFileAES(const std::string sk_file, uint8_t sk_out[],
                   std::string &uid, const secure::string pass) {
    if (sk_file.empty() || !sk_out) return 0;

    secure::string buf[1];
    if (!read(sk_file, buf)) return 0;
    secure::string decoded(decode(buf[0]));
    if (strncmp(decoded.c_str(), k_salted.c_str(), k_salted.length()) != 0)
        return 0;

    AES aes;
    secure::string ptext;
    aes.decryptSalted(decoded, ptext, pass);

    std::string linebreak = "\n";
    int pos = ptext.find(linebreak);
    uid = ptext.substr(0, pos);
    secure::string sk(ptext.substr(pos + linebreak.length(), ptext.length()));
    memcpy(sk_out, sk.c_str(), CRYPTO_SECRETKEYBYTES);

    return 1;
}

int parseCTFile(const std::string ct_file, uint8_t ct_out[]) {
    if (ct_file.empty() || !ct_out) return 0;

    secure::string buf[2];
    if (!read(ct_file, buf)) return 0;
    if (!decode(buf[0], ct_out, CRYPTO_CIPHERTEXTBYTES)) return 0;
    return 1;
}

int parseKeyFile(const std::string key_file, uint8_t key_out[]) {
    if (key_file.empty() || !key_out) return 0;

    secure::string buf[2];
    if (!read(key_file, buf)) return 0;
    if (!decode(buf[0], key_out, CRYPTO_BYTES)) return 0;
    return 1;
}
