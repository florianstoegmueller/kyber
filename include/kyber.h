#ifndef KYBER_H
#define KYBER_H

#include "coder.h"
#include "filehandler.h"
#include "keypair.h"
#include "securestring.h"

static const std::string k_pk_file_default = "pk";
static const std::string k_sk_file_default = "sk";
static const std::string k_ct_file_default = "ct";
static const std::string k_key_file_default = "key";

class Kyber {
    FileHandler file;
    Coder coder;

   public:
    void generate(Keypair* const pair, const std::string uid,
                  const secure::string pass = "");
    void encrypt(Keypair* const pair, const std::string pk_file);
    void decrypt(Keypair* const pair, const std::string sk_file,
                 const std::string ct_file, const secure::string pass = "");
};

#endif
