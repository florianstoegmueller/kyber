#include "../include/coder.h"

#include "../include/base64.h"

secure::string Base64Coder::encode(const uint8_t in[], const int size) {
    secure::string out("");
    secure::string tmp("");
    if (in) {
        for (int i = 0; i < size; i++) {
            tmp += (char)in[i];
        }
        out += base64_encode(tmp);
    }
    return out;
}

int Base64Coder::decode(secure::string in, uint8_t out[], const int size) {
    if (out && !in.empty()) {
        secure::string tmp(base64_decode(in));
        for (int i = 0; i < size; i++) {
            out[i] = tmp[i];
        }
        return 1;
    }
    return 0;
}

secure::string Base64Coder::encode(secure::string in) {
    return base64_encode(in);
}

secure::string Base64Coder::decode(secure::string in) {
    return base64_decode(in);
}
