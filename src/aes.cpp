#include "../include/aes.h"

#include <openssl/rand.h>

#include <string>

// number of rounds for key derivation
// set to 1 for compatibility with OpenSSL CLI
static const unsigned int k_nrounds = 1;

static const unsigned int k_block_size = 16;
static const unsigned int k_key_size = 32;

AES::AES() {
    e_ctx = EVP_CIPHER_CTX_new();
    d_ctx = EVP_CIPHER_CTX_new();
}

int AES::init(const secure::string key_data_in, const byte salt[k_salt_size]) {
    byte key[k_key_size], iv[k_key_size], key_data[key_data_in.length()];
    memcpy(key_data, &key_data_in, key_data_in.length());

    int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, key_data,
                           key_data_in.length(), k_nrounds, key, iv);
    if (i != 32) {
        printf("Key size is %d bits - should be 256 bits\n", i);
        return -1;
    }

    EVP_CIPHER_CTX_init(e_ctx);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

    OPENSSL_cleanse(key, k_key_size);
    OPENSSL_cleanse(iv, k_key_size);

    return 0;
}

void AES::encrypt(const secure::string &ptext, secure::string &ctext) {
    ctext.resize(ptext.size() + k_block_size);
    int out_len1 = (int)ctext.size();

    EVP_EncryptInit_ex(e_ctx, NULL, NULL, NULL, NULL);

    int rc = EVP_EncryptUpdate(e_ctx, (byte *)&ctext[0], &out_len1,
                               (const byte *)&ptext[0], (int)ptext.size());
    if (rc != 1) throw std::runtime_error("EVP_EncryptUpdate failed");

    int out_len2 = (int)ctext.size() - out_len1;
    rc = EVP_EncryptFinal_ex(e_ctx, (byte *)&ctext[0] + out_len1, &out_len2);
    if (rc != 1) throw std::runtime_error("EVP_EncryptFinal_ex failed");

    ctext.resize(out_len1 + out_len2);
}

void AES::decrypt(const secure::string &ctext, secure::string &rtext) {
    rtext.resize(ctext.size());
    int out_len1 = (int)rtext.size();

    EVP_DecryptInit_ex(d_ctx, NULL, NULL, NULL, NULL);

    int rc = EVP_DecryptUpdate(d_ctx, (byte *)&rtext[0], &out_len1,
                               (const byte *)&ctext[0], (int)ctext.size());
    if (rc != 1) throw std::runtime_error("EVP_DecryptUpdate failed");

    int out_len2 = (int)rtext.size() - out_len1;
    rc = EVP_DecryptFinal_ex(d_ctx, (byte *)&rtext[0] + out_len1, &out_len2);
    if (rc != 1) throw std::runtime_error("EVP_DecryptFinal_ex failed");

    rtext.resize(out_len1 + out_len2);
}

void AES::genSalt(byte salt[k_salt_size]) {
    int rc = RAND_bytes(salt, k_salt_size);
    if (rc != 1) throw std::runtime_error("RAND_bytes salt failed");
}

void AES::encryptSalted(const secure::string &ptext, secure::string &ctext,
                        const secure::string key_data_in) {
    byte salt[k_salt_size];
    genSalt(salt);

    ctext += k_salted;
    for (int i = 0; i < k_salt_size; i++) {
        ctext += salt[i];
    }

    secure::string ctext_wo_salt;
    init(key_data_in, salt);
    encrypt(ptext, ctext_wo_salt);
    ctext += ctext_wo_salt;
}

void AES::decryptSalted(const secure::string &ctext, secure::string &rtext,
                        const secure::string key_data_in) {
    byte rsalt[k_salt_size];
    secure::string ctext_tmp("");
    if (strncmp(ctext.c_str(), k_salted.c_str(), k_salted.length()) == 0) {
        memcpy(rsalt, &ctext[k_salted.length()], k_salt_size);
        ctext_tmp +=
            (ctext.substr(k_salted.length() + k_salt_size, ctext.length()));
    }

    init(key_data_in, rsalt);
    decrypt(ctext_tmp, rtext);
}

AES::~AES() {
    EVP_CIPHER_CTX_free(e_ctx);
    EVP_CIPHER_CTX_free(d_ctx);
}
