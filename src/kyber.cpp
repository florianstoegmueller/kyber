#include "../include/kyber.h"

#include <iostream>
#include <string>

#include "../include/aes.h"
#include "../include/keypair.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "../kyber/ref/kem.h"

#ifdef __cplusplus
}
#endif

void Kyber::generate(const std::string uid, const secure::string pass) {
    pair.generate_pair();
    secure::string sk("");
    std::string sk_file = k_sk_file_default;

    if (pass.empty()) {
        sk += uid + "\n";
        sk += coder.encode(pair.get_sk(), CRYPTO_SECRETKEYBYTES);
    } else {
        AES aes;
        secure::string ctext("");

        uint8_t* sk_bytes = pair.get_sk();
        secure::string ptext(uid + "\n");
        for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
            ptext += sk_bytes[i];
        }

        aes.encryptSalted(ptext, ctext, pass);
        sk += coder.encode(ctext);
        sk_file += ".enc";
    }

    secure::string pk(coder.encode(pair.get_pk(), CRYPTO_PUBLICKEYBYTES));
    if (!file.write(k_pk_file_default, secure::string(uid)))
        std::cout << "Error writing uid to pk file!" << std::endl;
    if (!file.write(k_pk_file_default, pk, true))
        std::cout << "Error writing pk to pk file!" << std::endl;
    if (!file.write(sk_file, sk))
        std::cout << "Error writing to sk file!" << std::endl;
}

void Kyber::encrypt(const std::string pk_file) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];

    if (!file.parseFile(FileType::pk, pk_file, pk)) {
        std::cout << "Error parsing pk file! Aborting!" << std::endl;
        return;
    }

    pair.set_pk(pk);
    uint8_t* ct = pair.encrypt();
    uint8_t* key = pair.get_key();
    secure::string ct_encoded(coder.encode(ct, CRYPTO_CIPHERTEXTBYTES));
    secure::string key_encoded(coder.encode(key, CRYPTO_BYTES));

    if (!file.write(k_ct_file_default, ct_encoded))
        std::cout << "Error writing ct to ct file!" << std::endl;
    if (!file.write(k_key_file_default, key_encoded))
        std::cout << "Error writing key to key file!" << std::endl;

    // Clean up
    memset(pk, 0x00, CRYPTO_PUBLICKEYBYTES);
    memset(ct, 0x00, CRYPTO_CIPHERTEXTBYTES);
    memset(key, 0x00, CRYPTO_BYTES);
}

void Kyber::decrypt(const std::string sk_file, const std::string ct_file,
                    const secure::string pass) {
    uint8_t* key;
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

    if ((pass.empty() && !file.parseFile(FileType::sk, sk_file, sk)) ||
        (!pass.empty() && !file.parseSKFileAES(sk_file, sk, pass))) {
        std::cout << "Error parsing sk file! Aborting!" << std::endl;
        return;
    }

    if (!file.parseFile(FileType::ct, ct_file, ct)) {
        std::cout << "Error parsing ct file! Aborting!" << std::endl;
        return;
    }

    pair.set_sk(sk);
    key = pair.decrypt(ct);

    std::cout << coder.encode(key, CRYPTO_BYTES) << std::endl;

    // Clean up
    memset(sk, 0x00, CRYPTO_SECRETKEYBYTES);
    memset(ct, 0x00, CRYPTO_CIPHERTEXTBYTES);
    memset(key, 0x00, CRYPTO_BYTES);
}
