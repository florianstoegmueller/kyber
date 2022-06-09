#include <cstdio>
#include <iostream>
#include <map>
#include <vector>

#include "../include/filehandler.h"
#include "../include/instrumentor.h"
#include "../include/keypair.h"
#include "../include/kyber.h"

static const unsigned int k_warmup = 1000;
static const unsigned int k_rounds = 1000;

typedef std::vector<std::vector<long long>> vec2d;

void writeResults(std::string file_name, vec2d results) {
    FileHandler file;
    std::string header =
        "mode;kyber core(wall);kyber core(cpu);app w/o AES(wall);app w/o "
        "AES(cpu);app w/ AES(wall);app w/ AES(cpu)";
    std::vector<std::string> mode{"generate", "encrypt", "decrypt"};
    file.write(file_name, header);

    for (int i = 0; i < 3; i++) {
        std::string line = mode[i];
        for (int j = 0; j < 6; j++) line += ";" + std::to_string(results[i][j]);

        file.write(file_name, line, true);
    }
}

std::map<std::string, ProfileResult>& profile() {
    for (int i = 0; i < (k_warmup + k_rounds); i++) {
        Keypair pair;
        Kyber kyber;
        std::string uid = "PROFILER";
        secure::string key = "Password";

        if (i > k_warmup) Instrumentor::Get().BeginSession("Profile");

        {
            PROFILE_SCOPE("prototyp generate w/o AES");
            kyber.generate(&pair, uid);
        }
        {
            PROFILE_SCOPE("prototyp generate w/ AES");
            kyber.generate(&pair, uid, key);
        }
        {
            PROFILE_SCOPE("prototyp encrypt");
            kyber.encrypt(&pair, k_pk_file_default);
        }
        {
            PROFILE_SCOPE("prototyp decrypt w/ AES");
            kyber.decrypt(&pair, k_sk_file_default + ".enc", k_ct_file_default,
                          key);
        }
        {
            PROFILE_SCOPE("prototyp decrypt w/o AES");
            kyber.decrypt(&pair, k_sk_file_default, k_ct_file_default);
        }
    }

    static auto results = Instrumentor::Get().GetResults();
    Instrumentor::Get().EndSession();
    return results;
}

void calculateAvg(std::map<std::string, ProfileResult> results,
                  vec2d* avg_times) {
    for (auto& elem : results) {
        long long acc_wall = 0;
        long long acc_cpu = 0;

        for (auto& x : elem.second.WallTime) acc_wall += x;

        for (auto& x : elem.second.CpuTime) acc_cpu += x;

        acc_wall = acc_wall / elem.second.WallTime.size();
        acc_cpu = acc_cpu / elem.second.CpuTime.size();

        if (!elem.first.compare("kyber generate")) {
            (*avg_times)[0][0] = acc_wall;
            (*avg_times)[0][1] = acc_cpu;
        } else if (!elem.first.compare("kyber encrypt")) {
            (*avg_times)[1][0] = acc_wall;
            (*avg_times)[1][1] = acc_cpu;
        } else if (!elem.first.compare("kyber decrypt")) {
            (*avg_times)[2][0] = acc_wall;
            (*avg_times)[2][1] = acc_cpu;
        } else if (!elem.first.compare("prototyp generate w/o AES")) {
            (*avg_times)[0][2] = acc_wall;
            (*avg_times)[0][3] = acc_cpu;
        } else if (!elem.first.compare("prototyp generate w/ AES")) {
            (*avg_times)[0][4] = acc_wall;
            (*avg_times)[0][5] = acc_cpu;
        } else if (!elem.first.compare("prototyp encrypt")) {
            (*avg_times)[1][2] = acc_wall;
            (*avg_times)[1][3] = acc_cpu;
        } else if (!elem.first.compare("prototyp decrypt w/o AES")) {
            (*avg_times)[2][2] = acc_wall;
            (*avg_times)[2][3] = acc_cpu;
        } else if (!elem.first.compare("prototyp decrypt w/ AES")) {
            (*avg_times)[2][4] = acc_wall;
            (*avg_times)[2][5] = acc_cpu;
        }
    }
}

int main() {
    vec2d avg_times(3, std::vector<long long>(6, 0));

    auto results = profile();

    calculateAvg(results, &avg_times);
    writeResults("results_kyberk" + std::to_string(KYBER_K) + ".csv",
                 avg_times);

    return 0;
}
