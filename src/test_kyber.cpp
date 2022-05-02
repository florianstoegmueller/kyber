#include <stdio.h>

#include <iostream>
#include <string>

#include "../include/keypair.h"
#include "../include/kyber.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/rng.h"

#ifdef __cplusplus
}
#endif

unsigned char seed[48] = {6,21,80,35,77,21,140,94,201,85,149,254,4,239,122,37,118,127,46,36,204,43,196,121,208,157,134,220,154,188,253,231,5,106,140,38,111,158,249,126,208,133,65,219,210,225,255,161};

int main(int argc, char* argv[]) {
    Keypair pair;
    Kyber kyber;

    randombytes_init(seed, NULL, 256);

    kyber.generate(&pair, "test");
    kyber.encrypt(&pair, PK_FILE_DEFAULT);
    kyber.decrypt(&pair, SK_FILE_DEFAULT, CT_FILE_DEFAULT);
    return 0;
}
