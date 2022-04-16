#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>

#include "../include/base64.h"
#include "../include/helpers.h"
#include "../include/keypair.h"
#include "../include/inputparser.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/kem.h"
#include "../kyber/ref/params.h"

#ifdef __cplusplus
}
#endif

int main(int argc, char *argv[]) {
    //uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    //uint8_t sk[CRYPTO_SECRETKEYBYTES];
    //uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    std::ofstream keyfile;
    std::ifstream keyfile2;
    std::string buf;
    uint8_t sk2[CRYPTO_SECRETKEYBYTES];

    uint8_t * pk;
    uint8_t * sk;
    uint8_t * ct;
    Keypair pair;
    pair.generate_pair();
    pk = pair.get_pk();
    sk = pair.get_sk();

    printf("%d\n", pair.get_key());
    pair.encrypt();
    printf("%d\n", pair.get_key());

/*
    // generate keypair
    //crypto_kem_keypair(pk, sk);

    // write secrete key to file
    keyfile.open("key.txt");
    keyfile << encode(sk, CRYPTO_SECRETKEYBYTES) << "\n";
    keyfile.close();

    // encrypt
    //crypto_kem_enc(ct, key_b, pk);
    ct = pair.encrypt();

    // retrive key from file
    keyfile2.open("key.txt");
    std::getline(keyfile2, buf);
    keyfile2.close();
    decode(buf, sk2, CRYPTO_SECRETKEYBYTES);

    // decrypt with key from file
    crypto_kem_dec(key_a, ct, sk2);

    if (memcmp(key_a, key_b, CRYPTO_BYTES)) {
        printf("ERROR: keys do not match\n");
        return 1;
    } else {
        printf("success\n");
    }
*/
    return 0;
}
