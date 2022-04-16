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

// TODO check retrun values of functions

void generate(Keypair pair, const std::string uid) {
    pair.generate_pair();
    std::string pk = encode(pair.get_pk(), CRYPTO_PUBLICKEYBYTES);
    std::string sk = encode(pair.get_sk(), CRYPTO_SECRETKEYBYTES);

    // TODO remove hard coded file names
    write("pk", uid);
    write("pk", pk, true);
    write("sk", uid);
    write("sk", sk, true);
}

void encrypt(Keypair pair, const std::string pk_file) {
    std::string* pk_encoded;
    uint8_t* pk;
    read(pk_file, pk_encoded);
    decode(pk_encoded[1], pk, CRYPTO_PUBLICKEYBYTES);
    pair.set_pk(pk);

    uint8_t* ct = pair.encrypt();
    uint8_t* key = pair.get_key();
    std::string ct_encoded = encode(ct, CRYPTO_CIPHERTEXTBYTES);
    std::string key_encoded = encode(key, CRYPTO_BYTES);

    write("ct", ct_encoded);
    write("key", key_encoded);
}

void decrypt(Keypair pair, const std::string sk_file,
             const std::string ct_file) {
    std::string sk_encoded[2], ct_encoded[2], key_encoded;
    uint8_t* key;
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    read(sk_file, sk_encoded);
    read(ct_file, ct_encoded);

    decode(sk_encoded[1], sk, CRYPTO_SECRETKEYBYTES);
    decode(ct_encoded[0], ct, CRYPTO_CIPHERTEXTBYTES);

    pair.set_sk(sk);
    key = pair.decrypt(ct);
    key_encoded = encode(key, CRYPTO_BYTES);

    printf("%s\n", key_encoded.c_str());
}


int main(int argc, char* argv[]) {
    InputParser input(argc, argv);
    Keypair pair;

    // TODO better options
    const std::string uid = input.getCmdOption("-g");
    const std::string pk_file = input.getCmdOption("-pk");
    const std::string sk_file = input.getCmdOption("-sk");
    const std::string ct_file = input.getCmdOption("-ct");

    if (!uid.empty()) generate(pair, uid);

    if (!pk_file.empty()) encrypt(pair, pk_file);

    if (!sk_file.empty() && !ct_file.empty()) decrypt(pair, sk_file, ct_file);

    return 0;
}
