#include <stdio.h>

#include <iostream>
#include <string>

#include "../include/inputparser.h"
#include "../include/kyber.h"

void usage(const std::string name) {
    std::cout << "Usage: " << std::endl;
    std::cout << "\t" << name << " -g -uid <email> [-pass <aes-key>]" << std::endl;
    std::cout << "\t" << name << " -e -pk <pk-file>" << std::endl;
    std::cout << "\t" << name << " -d -sk <sk-file> -ct <ct-file> [-pass <aes-key>]" << std::endl;
    std::cout << std::endl << "Options:" << std::endl;
    std::cout << "\t-h, --help\t prints this help text" << std::endl;
    std::cout << "\t-g\t\t generate a key pair" << std::endl;
    std::cout << "\t-e\t\t encryption mode" << std::endl;
    std::cout << "\t-d\t\t decryption mode" << std::endl;
    std::cout << "\t-pk\t\t specify the private key file" << std::endl;
    std::cout << "\t-sk\t\t specify the secret key file" << std::endl;
    std::cout << "\t-ct\t\t specify the ciphertext file" << std::endl;
    std::cout << "\t-pass\t\t specify the AES key for en- & decryption of the secret key file" << std::endl;
}

int main(int argc, char* argv[]) {
    InputParser input(argc, argv);
    Kyber kyber;

    if (input.cmdOptionExists("-h") || input.cmdOptionExists("--help")) {
        usage(argv[0]);
        return 0;
    }

    const std::string uid = input.getCmdOption("-uid");
    const std::string pk_file = input.getCmdOption("-pk");
    const std::string sk_file = input.getCmdOption("-sk");
    const std::string ct_file = input.getCmdOption("-ct");
    const secure::string key(input.getCmdOption("-pass"));

    if (input.cmdOptionExists("-g") && !uid.empty())
        kyber.generate(uid, key);
    else if (input.cmdOptionExists("-e") && !pk_file.empty())
        kyber.encrypt(pk_file);
    else if (input.cmdOptionExists("-d") && !sk_file.empty() &&
             !ct_file.empty())
        kyber.decrypt(sk_file, ct_file, key);
    else
        std::cout << "No or wrong command line arguments given. For help type: "
                  << argv[0] << " -h" << std::endl;

    return 0;
}
