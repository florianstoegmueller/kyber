#include "../include/filehandler.h"

#include <fstream>
#include <iostream>

#include "../include/aes.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/kem.h"

#ifdef __cplusplus
}
#endif

std::string FileHandler::default_uid = "";

int FileHandler::write(const std::string path, const secure::string line,
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

int FileHandler::write(const std::string path, const std::string line,
                       const bool append) {
    return write(path, secure::string(line), append);
}

int FileHandler::read(const std::string path, secure::string text[]) {
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

int FileHandler::parseFile(FileType type, const std::string file, uint8_t out[],
                           std::string &uid) {
    if (file.empty() || !out) return 0;

    secure::string buf[2];
    if (!read(file, buf)) return 0;
    switch (type) {
        case FileType::pk:
            if (!coder.decode(buf[1], out, CRYPTO_PUBLICKEYBYTES)) return 0;
            uid = buf[0];
            break;
        case FileType::sk:
            if (!coder.decode(buf[1], out, CRYPTO_SECRETKEYBYTES)) return 0;
            uid = buf[0];
            break;
        case FileType::ct:
            if (!coder.decode(buf[0], out, CRYPTO_CIPHERTEXTBYTES)) return 0;
            break;
        case FileType::ss:
            if (!coder.decode(buf[0], out, CRYPTO_BYTES)) return 0;
            break;
        default:
            return 0;
    }

    return 1;
}

int FileHandler::parseSKFileAES(const std::string sk_file, uint8_t sk_out[],
                                const secure::string pass, std::string &uid) {
    if (sk_file.empty() || !sk_out) return 0;

    secure::string buf[1];
    if (!read(sk_file, buf)) return 0;
    secure::string decoded(coder.decode(buf[0]));
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
