#include <stdio.h>

#include <fstream>
#include <iostream>
#include <string>

#include "../include/base64.h"
#include "../include/helpers.h"
#include "../include/inputparser.h"
#include "../include/keypair.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/kem.h"
#include "../kyber/ref/params.h"

#ifdef __cplusplus
}
#endif

#define PK_FILE_DEFAULT "pk"
#define SK_FILE_DEFAULT "sk"
#define CT_FILE_DEFAULT "ct"
#define KEY_FILE_DEFAULT "key"

void generate(Keypair pair, const std::string uid) {
    pair.generate_pair();
    std::string pk = encode(pair.get_pk(), CRYPTO_PUBLICKEYBYTES);
    std::string sk = encode(pair.get_sk(), CRYPTO_SECRETKEYBYTES);

    if (!write(PK_FILE_DEFAULT, uid))
        std::cout << "Error writing uid to pk file!" << std::endl;
    if (!write(PK_FILE_DEFAULT, pk, true))
        std::cout << "Error writing pk to pk file!" << std::endl;
    if (!write(SK_FILE_DEFAULT, uid))
        std::cout << "Error writing uid to sk file!" << std::endl;
    if (!write(SK_FILE_DEFAULT, sk, true))
        std::cout << "Error writing sk to sk file!" << std::endl;
}

void encrypt(Keypair pair, const std::string pk_file) {
    std::string uid;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];

    if (!parsePKFile(pk_file, pk, uid)) {
        std::cout << "Error parsing pk file! Aborting!" << std::endl;
        return;
    }

    pair.set_pk(pk);
    uint8_t* ct = pair.encrypt();
    uint8_t* key = pair.get_key();
    std::string ct_encoded = encode(ct, CRYPTO_CIPHERTEXTBYTES);
    std::string key_encoded = encode(key, CRYPTO_BYTES);

    if (!write(CT_FILE_DEFAULT, ct_encoded))
        std::cout << "Error writing ct to ct file!" << std::endl;
    if (!write(KEY_FILE_DEFAULT, key_encoded))
        std::cout << "Error writing key to key file!" << std::endl;
}

void decrypt(Keypair pair, const std::string sk_file,
             const std::string ct_file) {
    std::string uid, key_encoded;
    uint8_t* key;
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

    if (!parseSKFile(sk_file, sk, uid)) {
        std::cout << "Error parsing sk file! Aborting!" << std::endl;
        return;
    }
    if (!parseCTFile(ct_file, ct)) {
        std::cout << "Error parsing ct file! Aborting!" << std::endl;
        return;
    }

    pair.set_sk(sk);
    key = pair.decrypt(ct);
    key_encoded = encode(key, CRYPTO_BYTES);

    std::cout << key_encoded << std::endl;
}

int main(int argc, char* argv[]) {
    InputParser input(argc, argv);
    Keypair pair;

    if (input.cmdOptionExists("-h") || input.cmdOptionExists("--help")) {
        std::cout << "Usage: " << std::endl;
        std::cout << "\t" << argv[0] << " -g -uid <email>" << std::endl;
        std::cout << "\t" << argv[0] << " -e -pk <pk-file>" << std::endl;
        std::cout << "\t" << argv[0] << " -d -sk <sk-file> -ct <ct-file>"
                  << std::endl;
        std::cout << std::endl << "Options:" << std::endl;
        std::cout << "\t-h, --help\t prints this help text" << std::endl;
        std::cout << "\t-g\t\t generate a key pair" << std::endl;
        std::cout << "\t-e\t\t encryption mode" << std::endl;
        std::cout << "\t-d\t\t decryption mode" << std::endl;
        std::cout << "\t-pk\t\t specify the private key file" << std::endl;
        std::cout << "\t-sk\t\t specify the secret key file" << std::endl;
        std::cout << "\t-ct\t\t specify the ciphertext file" << std::endl;
        return 0;
    }

    const std::string uid = input.getCmdOption("-uid");
    const std::string pk_file = input.getCmdOption("-pk");
    const std::string sk_file = input.getCmdOption("-sk");
    const std::string ct_file = input.getCmdOption("-ct");

    if (input.cmdOptionExists("-g") && !uid.empty()) generate(pair, uid);

    if (input.cmdOptionExists("-e") && !pk_file.empty()) encrypt(pair, pk_file);

    if (input.cmdOptionExists("-d") && !sk_file.empty() && !ct_file.empty())
        decrypt(pair, sk_file, ct_file);

    return 0;
}
