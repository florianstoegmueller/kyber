#include "../include/helpers.h"
#include "../include/base64.h"

std::string encode(uint8_t* in, int size){
    std::string out;
    for (int i = 0; i < size; i++) {
        out = out + (char)in[i];
    }
    return base64_encode(out);
}

void decode(std::string in, uint8_t* out, int size){
    in = base64_decode(in);
    for (int i = 0; i < size; i++) {
        out[i] = in[i];
    }
}
