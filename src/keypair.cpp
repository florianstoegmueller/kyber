#include "../include/keypair.h"

// TODO null checks

uint8_t* Keypair::encrypt() {
    crypto_kem_enc(ct, key, pk);
    return ct;
}

uint8_t* Keypair::decrypt(uint8_t* ct) {
    crypto_kem_dec(key, ct, sk);
    return key;
}

void Keypair::generate_pair() { crypto_kem_keypair(pk, sk); }

uint8_t* Keypair::get_key() {
    return key;
}

uint8_t* Keypair::get_pk() { return pk; }
void Keypair::set_pk(uint8_t* pk_in) {
    for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        pk[i] = pk_in[i];
    }
}

uint8_t* Keypair::get_sk() { return sk; }
void Keypair::set_sk(uint8_t * sk_in) {
    for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
        sk[i] = sk_in[i];
    }
}
