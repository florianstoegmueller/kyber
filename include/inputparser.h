#ifndef INPUTPARSER_H
#define INPUTPARSER_H

#include <string>
#include <vector>

class InputParser {
    std::vector<std::string> tokens;

   public:
    InputParser(int argc, char *argv[]);
    bool cmdOptionExists(const std::string &option);
    std::string getCmdOption(const std::string &option);
};

#endif
