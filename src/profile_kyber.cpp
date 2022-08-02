#include <cstdio>
#include <iostream>
#include <map>
#include <numeric>
#include <vector>

#include "../include/filehandler.h"
#include "../include/instrumentor.h"
#include "../include/kyber.h"

static const unsigned int k_warmup = 1000;
static const unsigned int k_rounds = 1000;

typedef std::tuple<double, double, double> triplet;
typedef std::vector<std::vector<triplet>> vec2d;

void writeResults(std::string file_name, vec2d* metrics) {
    FileHandler file;
    std::string header =
        "mode;kyber core(wall) - median;kyber core(wall) - avg;kyber "
        "core(wall) - sd;kyber core(cpu) - median;kyber core(cpu) - avg;kyber "
        "core(cpu) - sd;app w/o AES(wall) - median;app w/o AES(wall) - avg;app "
        "w/o AES(wall) - sd;app w/o AES(cpu) - median;app w/o AES(cpu) - "
        "avg;app w/o AES(cpu) - sd;app w/ AES(wall) - median;app w/ AES(wall) "
        "- avg;app w/ AES(wall) - sd;app w/ AES(cpu) - median;app w/ AES(cpu) "
        "- avg;app w/ AES(cpu) -sd";
    std::vector<std::string> mode{"generate", "encrypt", "decrypt"};
    file.write(file_name, header);

    for (int i = 0; i < 3; i++) {
        std::string line = mode[i];
        for (int j = 0; j < 6; j++)
            line += ";" + std::to_string((long)std::get<0>((*metrics)[i][j])) +
                    ";" + std::to_string((long)std::get<1>((*metrics)[i][j])) +
                    ";" + std::to_string((long)std::get<2>((*metrics)[i][j]));

        file.write(file_name, line, true);
    }
}

std::map<std::string, ProfileResult>& profile() {
    for (int i = 0; i < (k_warmup + k_rounds); i++) {
        Kyber kyber;
        std::string uid = "PROFILER";
        secure::string key = "Password";

        if (i > k_warmup) Instrumentor::Get().BeginSession("Profile");

        {
            PROFILE_SCOPE("prototyp generate w/o AES");
            kyber.generate(uid);
        }
        {
            PROFILE_SCOPE("prototyp generate w/ AES");
            kyber.generate(uid, key);
        }
        {
            PROFILE_SCOPE("prototyp encrypt");
            kyber.encrypt(k_pk_file_default);
        }
        {
            PROFILE_SCOPE("prototyp decrypt w/ AES");
            kyber.decrypt(k_sk_file_default + ".enc", k_ct_file_default, key);
        }
        {
            PROFILE_SCOPE("prototyp decrypt w/o AES");
            kyber.decrypt(k_sk_file_default, k_ct_file_default);
        }
    }

    static auto results = Instrumentor::Get().GetResults();
    Instrumentor::Get().EndSession();
    return results;
}

double calcMedian(std::vector<long long>& vec) {
    size_t n = vec.size() / 2;
    nth_element(vec.begin(), vec.begin() + n, vec.end());

    if (vec.size() % 2 == 1) {
        return vec[n];
    } else {
        auto max = std::max_element(vec.begin(), vec.begin() + n);
        return (vec[n] + *max) / 2;
    }
}

double calcAvg(const std::vector<long long>& vec) {
    return std::accumulate(vec.begin(), vec.end(), 0.0) / vec.size();
}

double calcSD(const std::vector<long long>& vec, double avg) {
    double acc = 0.0;
    for (auto& x : vec) acc += std::pow((x - avg), 2.0);
    return std::sqrt(acc / vec.size());
}

void calculateMetrics(std::map<std::string, ProfileResult> results,
                      vec2d* metric) {
    for (auto& elem : results) {
        const double avg_wall = calcAvg(elem.second.WallTime);
        const double avg_cpu = calcAvg(elem.second.CpuTime);
        const double sd_wall = calcSD(elem.second.WallTime, avg_wall);
        const double sd_cpu = calcSD(elem.second.CpuTime, avg_cpu);
        const double median_cpu = calcMedian(elem.second.CpuTime);
        const double median_wall = calcMedian(elem.second.WallTime);

        if (!elem.first.compare("kyber generate")) {
            (*metric)[0][0] = std::make_tuple(median_wall, avg_wall, sd_wall);
            (*metric)[0][1] = std::make_tuple(median_cpu, avg_cpu, sd_cpu);
        } else if (!elem.first.compare("kyber encrypt")) {
            (*metric)[1][0] = std::make_tuple(median_wall, avg_wall, sd_wall);
            (*metric)[1][1] = std::make_tuple(median_cpu, avg_cpu, sd_cpu);
        } else if (!elem.first.compare("kyber decrypt")) {
            (*metric)[2][0] = std::make_tuple(median_wall, avg_wall, sd_wall);
            (*metric)[2][1] = std::make_tuple(median_cpu, avg_cpu, sd_cpu);
        } else if (!elem.first.compare("prototyp generate w/o AES")) {
            (*metric)[0][2] = std::make_tuple(median_wall, avg_wall, sd_wall);
            (*metric)[0][3] = std::make_tuple(median_cpu, avg_cpu, sd_cpu);
        } else if (!elem.first.compare("prototyp generate w/ AES")) {
            (*metric)[0][4] = std::make_tuple(median_wall, avg_wall, sd_wall);
            (*metric)[0][5] = std::make_tuple(median_cpu, avg_cpu, sd_cpu);
        } else if (!elem.first.compare("prototyp encrypt")) {
            (*metric)[1][2] = std::make_tuple(median_wall, avg_wall, sd_wall);
            (*metric)[1][3] = std::make_tuple(median_cpu, avg_cpu, sd_cpu);
        } else if (!elem.first.compare("prototyp decrypt w/o AES")) {
            (*metric)[2][2] = std::make_tuple(median_wall, avg_wall, sd_wall);
            (*metric)[2][3] = std::make_tuple(median_cpu, avg_cpu, sd_cpu);
        } else if (!elem.first.compare("prototyp decrypt w/ AES")) {
            (*metric)[2][4] = std::make_tuple(median_wall, avg_wall, sd_wall);
            (*metric)[2][5] = std::make_tuple(median_cpu, avg_cpu, sd_cpu);
        }
    }
}

int main() {
    vec2d metrics(3, std::vector<triplet>(6, std::make_tuple(0.0, 0.0, 0.0)));

    auto results = profile();

    calculateMetrics(results, &metrics);
    writeResults("results_kyberk" + std::to_string(KYBER_K) + "_n" +
                     std::to_string(k_rounds) + ".csv",
                 &metrics);

    return 0;
}
