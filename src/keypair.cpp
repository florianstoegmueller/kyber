#include "../include/keypair.h"

uint8_t* Keypair::encrypt() {
    crypto_kem_enc(ct, key, pk);
    return ct;
}

void Keypair::decrypt(uint8_t* ct) { crypto_kem_dec(key, ct, sk); }

void Keypair::generate_pair() { crypto_kem_keypair(pk, sk); }

uint8_t Keypair::get_key() {
    if (key[0] != 0) {
        return 1;
    } else {
        return 0;
    }
}

uint8_t* Keypair::get_pk() { return pk; }
void Keypair::set_pk(uint8_t* pk_in) {
    // pk = pk_in;
}

uint8_t* Keypair::get_sk() { return sk; }
void Keypair::set_sk(uint8_t* sk_in) {
    // sk = sk_in;
}
