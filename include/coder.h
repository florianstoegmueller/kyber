#ifndef CODER_H
#define CODER_H

#include <string>

#include "securestring.h"

class Coder {
   public:
    secure::string encode(const uint8_t in[], const int size);
    int decode(secure::string in, uint8_t out[], const int size);
    secure::string encode(secure::string in);
    secure::string decode(secure::string in);
};

#endif
