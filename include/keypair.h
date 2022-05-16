#ifndef KEYPAIR_H
#define KEYPAIR_H

#include <stdint.h>

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/kem.h"
#include "../kyber/ref/params.h"

#ifdef __cplusplus
}
#endif

class Keypair {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key[CRYPTO_BYTES];
    bool pk_is_set = false;
    bool sk_is_set = false;

   public:
    uint8_t* encrypt();
    uint8_t* decrypt(const uint8_t ct[]);
    void generate_pair();
    uint8_t* get_key();
    uint8_t* get_pk();
    void set_pk(const uint8_t pk[]);
    uint8_t* get_sk();
    void set_sk(const uint8_t sk[]);
    ~Keypair();
};

#endif
