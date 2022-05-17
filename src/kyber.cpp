#include "../include/kyber.h"

#include <stdio.h>

#include <iostream>
#include <string>

#include "../include/aes.h"
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

void Kyber::generate(Keypair* const pair, const std::string uid,
                     const secure::string pass) {
    if (!pair) return;

    (*pair).generate_pair();
    secure::string sk("");
    std::string sk_file = k_sk_file_default;

    if (pass.empty()) {
        sk += uid;
        sk += "\n";
        sk += encode((*pair).get_sk(), CRYPTO_SECRETKEYBYTES);
    } else {
        AES aes;
        secure::string ctext("");

        uint8_t* sk_bytes = (*pair).get_sk();
        secure::string ptext("");
        ptext += uid;
        ptext += "\n";
        for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
            ptext += sk_bytes[i];
        }

        aes.encryptSalted(ptext, ctext, pass);
        sk += encode(ctext);
        sk_file += ".enc";
    }

    secure::string pk(encode((*pair).get_pk(), CRYPTO_PUBLICKEYBYTES));
    if (!write(k_pk_file_default, secure::string(uid)))
        std::cout << "Error writing uid to pk file!" << std::endl;
    if (!write(k_pk_file_default, pk, true))
        std::cout << "Error writing pk to pk file!" << std::endl;
    if (!write(sk_file, sk))
        std::cout << "Error writing to sk file!" << std::endl;
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
    secure::string ct_encoded(encode(ct, CRYPTO_CIPHERTEXTBYTES));
    secure::string key_encoded(encode(key, CRYPTO_BYTES));

    if (!write(k_ct_file_default, ct_encoded))
        std::cout << "Error writing ct to ct file!" << std::endl;
    if (!write(k_key_file_default, key_encoded))
        std::cout << "Error writing key to key file!" << std::endl;
}

void Kyber::decrypt(Keypair* const pair, const std::string sk_file,
                    const std::string ct_file, const secure::string pass) {
    if (!pair) return;

    std::string uid;
    uint8_t* key;
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

    if (pass.empty()) {
        if (!parseSKFile(sk_file, sk, uid)) {
            std::cout << "Error parsing sk file! Aborting!" << std::endl;
            return;
        }
    } else {
        if (!parseSKFileAES(sk_file, sk, uid, pass)) {
            std::cout << "Error parsing sk file! Aborting!" << std::endl;
            return;
        }
    }

    if (!parseCTFile(ct_file, ct)) {
        std::cout << "Error parsing ct file! Aborting!" << std::endl;
        return;
    }

    (*pair).set_sk(sk);
    key = (*pair).decrypt(ct);

    std::cout << encode(key, CRYPTO_BYTES) << std::endl;
}
