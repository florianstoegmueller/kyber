#include <stdio.h>

#include <fstream>
#include <iostream>
#include <string>

#include "../include/filehandler.h"
#include "../include/inputparser.h"
#include "../include/kyber.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/rng.h"

#ifdef __cplusplus
}
#endif

static const unsigned int k_failure = 0;
static const unsigned int k_success = 1;
static const unsigned int k_error = 2;
static const unsigned int k_seed_bytes = 48;

std::string getValue(std::ifstream* const file, const std::string marker) {
    if (!file) return "";

    std::string line;
    while (getline(*file, line)) {
        std::size_t pos = line.find(marker);
        if (pos != std::string::npos) return line.substr(pos + marker.length());
    }
    return "";
}

/*
    Converts a hex string into a byte array.
*/
void readHex(const std::string in, uint8_t* const out, const int len) {
    if (!out) return;

    memset(out, 0x00, len);
    for (auto ch : in) {
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

/*
    Read the value for a specific marker from the kat file and compare it to
    the value from the file generated by the kyber programm.
    Returns 1 if the values are equal.
*/
int test(std::ifstream* const file, const std::string marker, const FileType type,
         const int buf_size) {
    std::string value = getValue(file, marker);
    if (value.empty()) return k_error;

    uint8_t kat_buf[buf_size];
    readHex(value, kat_buf, buf_size);

    FileHandler file_handler;
    uint8_t parsed_buf[buf_size];

    switch (type) {
        case pk:
            if (!file_handler.parseFile(FileType::pk, k_pk_file_default, parsed_buf)) return k_error;
            break;
        case sk:
            if (!file_handler.parseFile(FileType::sk, k_sk_file_default, parsed_buf)) return k_error;
            break;
        case ct:
            if (!file_handler.parseFile(FileType::ct, k_ct_file_default, parsed_buf)) return k_error;
            break;
        case ss:
            if (!file_handler.parseFile(FileType::ss, k_key_file_default, parsed_buf)) return k_error;
            break;
        default:
            return k_error;
    }

    if (memcmp(kat_buf, parsed_buf, buf_size)) return k_failure;
    return k_success;
}

int main(int argc, char* argv[]) {
    InputParser input(argc, argv);

    const std::string kat_arg = input.getCmdOption("-kat");
    if (kat_arg.empty()) {
        std::cout << "No kat file specified. Please use -kat option to specify "
                     "a kat file."
                  << std::endl;
        return -1;
    }

    std::ifstream kat_file(kat_arg);
    if (!kat_file) {
        std::cout << "Unable to open kat file." << std::endl;
        return -1;
    }

    while (!getValue(&kat_file, "count = ").empty()) {
        // retrive the seed from the kat file and use it for initialization
        std::string value = getValue(&kat_file, "seed = ");
        if (value.empty()) {
            std::cout << "error: couldn't retrive seed" << std::endl;
            continue;
        }

        unsigned char seed[k_seed_bytes];
        readHex(value, seed, k_seed_bytes);
        randombytes_init(seed, NULL, 256);

        std::cout << "testing with seed " << value << std::endl;

        // generate the four kyber files
        Kyber kyber;
        kyber.generate("test");
        kyber.encrypt(k_pk_file_default);
        kyber.decrypt(k_sk_file_default, k_ct_file_default);

        // compare the generated kyber files with the kat file
        if (test(&kat_file, "pk = ", FileType(pk), CRYPTO_PUBLICKEYBYTES) !=
                k_success ||
            test(&kat_file, "sk = ", FileType(sk), CRYPTO_SECRETKEYBYTES) !=
                k_success ||
            test(&kat_file, "ct = ", FileType(ct), CRYPTO_CIPHERTEXTBYTES) !=
                k_success ||
            test(&kat_file, "ss = ", FileType(ss), CRYPTO_BYTES) != k_success) {
            std::cout << "error: test was not successful" << std::endl
                      << std::endl;
        } else {
            std::cout << "success" << std::endl << std::endl;
        }
    }

    kat_file.close();
    return 0;
}
