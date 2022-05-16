#include <stdio.h>

#include <iostream>
#include <string>

#include "../include/kyber.h"
#include "../include/helpers.h"
#include "../include/keypair.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/kem.h"
#include "../kyber/ref/params.h"

#ifdef __cplusplus
}
#endif

void Kyber::generate(Keypair* const pair, const std::string uid) {
    if (!pair) return;

    (*pair).generate_pair();
    std::string pk = encode((*pair).get_pk(), CRYPTO_PUBLICKEYBYTES);
    std::string sk = encode((*pair).get_sk(), CRYPTO_SECRETKEYBYTES);

    if (!write(k_pk_file_default, uid))
        std::cout << "Error writing uid to pk file!" << std::endl;
    if (!write(k_pk_file_default, pk, true))
        std::cout << "Error writing pk to pk file!" << std::endl;
    if (!write(k_sk_file_default, uid))
        std::cout << "Error writing uid to sk file!" << std::endl;
    if (!write(k_sk_file_default, sk, true))
        std::cout << "Error writing sk to sk file!" << std::endl;
}

void Kyber::encrypt(Keypair* const pair, const std::string pk_file) {
    if (!pair) return;

    std::string uid;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];

    if (!parsePKFile(pk_file, pk, uid)) {
        std::cout << "Error parsing pk file! Aborting!" << std::endl;
        return;
    }

    (*pair).set_pk(pk);
    uint8_t* ct = (*pair).encrypt();
    uint8_t* key = (*pair).get_key();
    std::string ct_encoded = encode(ct, CRYPTO_CIPHERTEXTBYTES);
    std::string key_encoded = encode(key, CRYPTO_BYTES);

    if (!write(k_ct_file_default, ct_encoded))
        std::cout << "Error writing ct to ct file!" << std::endl;
    if (!write(k_key_file_default, key_encoded))
        std::cout << "Error writing key to key file!" << std::endl;
}

void Kyber::decrypt(Keypair* const pair, const std::string sk_file,
                    const std::string ct_file) {
    if (!pair)
        return;

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

    (*pair).set_sk(sk);
    key = (*pair).decrypt(ct);
    key_encoded = encode(key, CRYPTO_BYTES);

    std::cout << key_encoded << std::endl;
}
