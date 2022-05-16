#ifndef HELPERS_H
#define HELPERS_H

#include <string>
#include "securestring.h"

secure::string encode(const uint8_t in[], const int size);
int decode(secure::string in, uint8_t out[], const int size);
int write(const std::string path, const secure::string line, const bool append = false);
int read(const std::string path, secure::string text[]);
int parsePKFile(const std::string pk_file, uint8_t pk_out[], std::string &uid);
int parseSKFile(const std::string sk_file, uint8_t sk_out[], std::string &uid);
int parseCTFile(const std::string ct_file, uint8_t ct_out[]);
int parseKeyFile(const std::string key_file, uint8_t key_out[]);

#endif
