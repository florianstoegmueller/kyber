#include "../include/keypair.h"

#include <string>

#include "../include/instrumentor.h"

uint8_t* Keypair::encrypt() {
    if (pk_is_set) {
        {
            PROFILE_SCOPE("kyber encrypt");
            crypto_kem_enc(ct, key, pk);
        }
        return ct;
    }
    return nullptr;
}

uint8_t* Keypair::decrypt(const uint8_t ct[]) {
    if (sk_is_set && ct) {
        {
            PROFILE_SCOPE("kyber decrypt");
            crypto_kem_dec(key, ct, sk);
        }
        return key;
    }
    return nullptr;
}

void Keypair::generate_pair() {
    {
        PROFILE_SCOPE("kyber generate");
        crypto_kem_keypair(pk, sk);
    }
    pk_is_set = true;
    sk_is_set = true;
}

uint8_t* Keypair::get_key() { return key; }

uint8_t* Keypair::get_pk() { return pk; }

void Keypair::set_pk(const uint8_t pk_in[]) {
    if (pk_in) {
        for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
            pk[i] = pk_in[i];
        }
        pk_is_set = true;
    }
}

uint8_t* Keypair::get_sk() { return sk; }

void Keypair::set_sk(const uint8_t sk_in[]) {
    if (sk_in) {
        for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
            sk[i] = sk_in[i];
        }
        sk_is_set = true;
    }
}

Keypair::~Keypair() {
    memset(pk, 0x00, CRYPTO_PUBLICKEYBYTES);
    memset(sk, 0x00, CRYPTO_SECRETKEYBYTES);
    memset(ct, 0x00, CRYPTO_CIPHERTEXTBYTES);
    memset(key, 0x00, CRYPTO_BYTES);
}
