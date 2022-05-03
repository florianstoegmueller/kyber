#include <stdio.h>

#include <fstream>
#include <iostream>
#include <string>

#include "../include/helpers.h"
#include "../include/inputparser.h"
#include "../include/keypair.h"
#include "../include/kyber.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/rng.h"

#ifdef __cplusplus
}
#endif

enum FileType { pk, sk, ct, ss };

#define NOT_EQUAL 0
#define EQUAL 1
#define ERROR 2

std::string getValue(std::ifstream* file, const std::string marker) {
    std::string line;
    while (getline(*file, line)) {
        std::size_t pos = line.find(marker);
        if (pos != std::string::npos) return line.substr(pos + marker.length());
    }
    return "";
}

void readHex(const std::string in, unsigned char* out, int len) {
    memset(out, 0x00, len);

    for (int i = 0; i < in.length(); i++) {
        char ch = in[i];
        if ((ch >= '0') && (ch <= '9'))
            ch = ch - '0';
        else if ((ch >= 'A') && (ch <= 'F'))
            ch = ch - 'A' + 10;
        else if ((ch >= 'a') && (ch <= 'f'))
            ch = ch - 'a' + 10;
        else
            ch = 0;

        for (int j = 0; j < len - 1; j++)
            out[j] = (out[j] << 4) | (out[j + 1] >> 4);
        out[len - 1] = (out[len - 1] << 4) | ch;
    }
}

int test(std::ifstream* file, const std::string marker, FileType type,
         int buf_size) {
    std::string value = getValue(file, marker);
    if (value.empty()) return ERROR;

    unsigned char kat_buf[buf_size];
    readHex(value, kat_buf, buf_size);

    std::string uid;
    uint8_t parsed_buf[buf_size];

    switch (type) {
        case pk:
            if (!parsePKFile(PK_FILE_DEFAULT, parsed_buf, uid)) return ERROR;
            break;
        case sk:
            if (!parseSKFile(SK_FILE_DEFAULT, parsed_buf, uid)) return ERROR;
            break;
        case ct:
            if (!parseCTFile(CT_FILE_DEFAULT, parsed_buf)) return ERROR;
            break;
        case ss:
            if (!parseKeyFile(KEY_FILE_DEFAULT, parsed_buf)) return ERROR;
            break;
        default:
            return ERROR;
    }

    if (memcmp(kat_buf, parsed_buf, buf_size)) return NOT_EQUAL;
    return EQUAL;
}

int main(int argc, char* argv[]) {
    InputParser input(argc, argv);
    Keypair pair;
    Kyber kyber;

    const std::string kat_arg = input.getCmdOption("-kat");
    if (kat_arg.empty()) return -1;

    std::ifstream kat_file(kat_arg);
    if (!kat_file.is_open()) return -1;

    while (!getValue(&kat_file, "count = ").empty()) {
        std::string line = getValue(&kat_file, "seed = ");
        int len = (line.length() / 2);
        unsigned char seed[len];
        readHex(line, seed, len);

        std::cout << "testing with seed " << line << std::endl;

        randombytes_init(seed, NULL, 256);
        kyber.generate(&pair, "test");
        kyber.encrypt(&pair, PK_FILE_DEFAULT);
        kyber.decrypt(&pair, SK_FILE_DEFAULT, CT_FILE_DEFAULT);

        if (!test(&kat_file, "pk = ", FileType(pk), CRYPTO_PUBLICKEYBYTES) ||
            !test(&kat_file, "sk = ", FileType(sk), CRYPTO_SECRETKEYBYTES) ||
            !test(&kat_file, "ct = ", FileType(ct), CRYPTO_CIPHERTEXTBYTES) ||
            !test(&kat_file, "ss = ", FileType(ss), CRYPTO_BYTES)) {
            std::cout << "error: test was not successful" << std::endl;
        }

        std::cout << "success" << std::endl << std::endl;
    }

    kat_file.close();
    return 0;
}
