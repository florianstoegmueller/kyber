#ifndef KYBER_H
#define KYBER_H

#include <string>

#include "keypair.h"

#define PK_FILE_DEFAULT "pk"
#define SK_FILE_DEFAULT "sk"
#define CT_FILE_DEFAULT "ct"
#define KEY_FILE_DEFAULT "key"

class Kyber {
   public:
    void generate(Keypair* pair, const std::string uid);
    void encrypt(Keypair* pair, const std::string pk_file);
    void decrypt(Keypair* pair, const std::string sk_file,
                 const std::string ct_file);
};

#endif
