#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>

#include "../include/base64.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/kem.h"
#include "../kyber/ref/params.h"

#ifdef __cplusplus
}
#endif

std::string encode(uint8_t* in, int size){
    std::string out;
    for (int i = 0; i < size; i++) {
        out = out + (char)in[i];
    }
    return base64_encode(out);
}

void decode(std::string in, uint8_t* out, int size){
    in = base64_decode(in);
    for (int i = 0; i < size; i++) {
        out[i] = in[i];
    }
}

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    std::ofstream keyfile;
    std::ifstream keyfile2;
    std::string buf;
    uint8_t sk2[CRYPTO_SECRETKEYBYTES];
    
    // generate keypair
    crypto_kem_keypair(pk, sk);

    // write secrete key to file
    keyfile.open("key.txt");
    keyfile << encode(sk, CRYPTO_SECRETKEYBYTES) << "\n";
    keyfile.close();

    // encrypt
    crypto_kem_enc(ct, key_b, pk);

    // retrive key from file
    keyfile2.open("key.txt");
    std::getline(keyfile2, buf);
    keyfile2.close();
    decode(buf, sk2, CRYPTO_SECRETKEYBYTES);

    // decrypt with key from file
    crypto_kem_dec(key_a, ct, sk2);

    if (memcmp(key_a, key_b, CRYPTO_BYTES)) {
        printf("ERROR keys\n");
        return 1;
    } else {
        printf("success\n");
    }
}
