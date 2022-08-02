#ifndef AES_H
#define AES_H

#include <openssl/evp.h>

#include <string>

#include "securestring.h"

typedef unsigned char byte;
static const unsigned int k_salt_size = 8;
static const std::string k_salted = "Salted__";

class AES {
    EVP_CIPHER_CTX* e_ctx;
    EVP_CIPHER_CTX* d_ctx;
    int init(const secure::string key_data_in, const byte salt[k_salt_size]);
    void encrypt(const secure::string& ptext, secure::string& ctext);
    void decrypt(const secure::string& ctext, secure::string& rtext);
    void genSalt(byte salt[k_salt_size]);

   public:
    AES();
    void encryptSalted(const secure::string& ptext, secure::string& ctext,
                       const secure::string key_data_in);
    void decryptSalted(const secure::string& ctext, secure::string& rtext,
                       const secure::string key_data_in);
    ~AES();
};

#endif
