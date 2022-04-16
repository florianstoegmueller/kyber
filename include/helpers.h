#ifndef HELPERS_H
#define HELPERS_H

#include <string>

std::string encode(uint8_t* in, int size);
void decode(std::string in, uint8_t* out, int size);

#endif
