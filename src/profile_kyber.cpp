#include <cstdio>
#include <iostream>
#include <map>
#include <numeric>
#include <vector>

#include "../include/filehandler.h"
#include "../include/instrumentor.h"
#include "../include/keypair.h"
#include "../include/kyber.h"

static const unsigned int k_warmup = 100;
static const unsigned int k_rounds = 100;

typedef std::vector<std::vector<long long>> vec2d;

void writeResults(std::string file_name, vec2d avg, vec2d sd) {
    FileHandler file;
    std::string header =
        "mode;kyber core(wall) - avg;kyber core(wall) - sd;kyber core(cpu) - "
        "avg;kyber core(cpu) - sd;app w/o AES(wall) - avg;app w/o AES(wall) - "
        "sd;app w/o AES(cpu) - avg;app w/o AES(cpu) - sd;app w/ AES(wall) - "
        "avg;app w/ AES(wall) - sd;app w/ AES(cpu) - avg;app w/ AES(cpu) -sd";
    std::vector<std::string> mode{"generate", "encrypt", "decrypt"};
    file.write(file_name, header);

    for (int i = 0; i < 3; i++) {
        std::string line = mode[i];
        for (int j = 0; j < 6; j++)
            line += ";" + std::to_string(avg[i][j]) + ";" +
                    std::to_string(sd[i][j]);

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

double calcAvg(std::vector<long long> vec) {
    return std::accumulate(vec.begin(), vec.end(), 0.0) / vec.size();
}

double calcSD(std::vector<long long> vec, double avg) {
    double acc = 0.0;
    for (auto& x : vec) acc += std::pow((x - avg), 2.0);
    return std::sqrt(acc / vec.size());
}

void calculateAvgSD(std::map<std::string, ProfileResult> results, vec2d* avg,
                    vec2d* sd) {
    for (auto& elem : results) {
        const double avg_wall = calcAvg(elem.second.WallTime);
        const double avg_cpu = calcAvg(elem.second.CpuTime);
        const double sd_wall = calcSD(elem.second.WallTime, avg_wall);
        const double sd_cpu = calcSD(elem.second.CpuTime, avg_cpu);

        if (!elem.first.compare("kyber generate")) {
            (*avg)[0][0] = avg_wall;
            (*avg)[0][1] = avg_cpu;
            (*sd)[0][0] = sd_wall;
            (*sd)[0][1] = sd_cpu;
        } else if (!elem.first.compare("kyber encrypt")) {
            (*avg)[1][0] = avg_wall;
            (*avg)[1][1] = avg_cpu;
            (*sd)[1][0] = sd_wall;
            (*sd)[1][1] = sd_cpu;
        } else if (!elem.first.compare("kyber decrypt")) {
            (*avg)[2][0] = avg_wall;
            (*avg)[2][1] = avg_cpu;
            (*sd)[2][0] = sd_wall;
            (*sd)[2][1] = sd_cpu;
        } else if (!elem.first.compare("prototyp generate w/o AES")) {
            (*avg)[0][2] = avg_wall;
            (*avg)[0][3] = avg_cpu;
            (*sd)[0][2] = sd_wall;
            (*sd)[0][3] = sd_cpu;
        } else if (!elem.first.compare("prototyp generate w/ AES")) {
            (*avg)[0][4] = avg_wall;
            (*avg)[0][5] = avg_cpu;
            (*sd)[0][4] = sd_wall;
            (*sd)[0][5] = sd_cpu;
        } else if (!elem.first.compare("prototyp encrypt")) {
            (*avg)[1][2] = avg_wall;
            (*avg)[1][3] = avg_cpu;
            (*sd)[1][2] = sd_wall;
            (*sd)[1][3] = sd_cpu;
        } else if (!elem.first.compare("prototyp decrypt w/o AES")) {
            (*avg)[2][2] = avg_wall;
            (*avg)[2][3] = avg_cpu;
            (*sd)[2][2] = sd_wall;
            (*sd)[2][3] = sd_cpu;
        } else if (!elem.first.compare("prototyp decrypt w/ AES")) {
            (*avg)[2][4] = avg_wall;
            (*avg)[2][5] = avg_cpu;
            (*sd)[2][4] = sd_wall;
            (*sd)[2][5] = sd_cpu;
        }
    }
}

int main() {
    vec2d avg(3, std::vector<long long>(6, 0));
    vec2d sd(3, std::vector<long long>(6, 0));

    auto results = profile();

    calculateAvgSD(results, &avg, &sd);
    writeResults("results_kyberk" + std::to_string(KYBER_K) + "_n" +
                     std::to_string(k_rounds) + ".csv",
                 avg, sd);

    return 0;
}
