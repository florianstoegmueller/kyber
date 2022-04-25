#ifndef HELPERS_H
#define HELPERS_H

#include <string>

std::string encode(const uint8_t* in, const int size);
void decode(std::string in, uint8_t* out, const int size);
int write(const std::string path, const std::string line, const bool append = false);
int read(const std::string path, std::string* text);

#endif
