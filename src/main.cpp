#include <stdio.h>
#include <string>
#include <iostream>

#include "../include/base64.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/kem.h"
#include "../kyber/ref/params.h"

#ifdef __cplusplus
}
#endif

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];
    
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, key_b, pk);
    crypto_kem_dec(key_a, ct, sk);

    if (memcmp(key_a, key_b, CRYPTO_BYTES)) {
        printf("ERROR keys\n");
        return 1;
    } else {
        printf("success\n");
    }

    std::string encode = base64_encode("Test");
    std::cout << "\nencode:\n" << encode << "\n";
    std::string decode = base64_decode(encode);
    std::cout << "\ndecode:\n" << decode << "\n";

}
