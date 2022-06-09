#ifndef FILEHANDLER_H
#define FILEHANDLER_H

#include <string>

#include "coder.h"
#include "securestring.h"

enum FileType { pk, sk, ct, ss };

class FileHandler {
    Coder coder;
    static std::string default_uid;

   public:
    int write(const std::string path, const secure::string line,
              const bool append = false);
    int write(const std::string path, const std::string line,
              const bool append = false);
    int read(const std::string path, secure::string text[]);
    int parseFile(FileType type, const std::string pk_file, uint8_t pk_out[],
                  std::string &uid = default_uid);
    int parseSKFileAES(const std::string sk_file, uint8_t sk_out[],
                       const secure::string pass,
                       std::string &uid = default_uid);
};

#endif
