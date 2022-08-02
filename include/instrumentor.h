/*
    Basic instrumentation profiler
    Adapted from
   https://gist.github.com/TheCherno/31f135eea6ee729ab5f26a6908eb3a5e
*/

#ifndef INSTRUMENTOR_H
#define INSTRUMENTOR_H

#include <algorithm>
#include <chrono>
#include <map>
#include <string>
#include <vector>

#ifndef PROFILING
#define PROFILING 0
#endif

#if PROFILING
#define PROFILE_SCOPE(name) InstrumentationTimer timer##__LINE__(name)
#define PROFILE_FUNCTION() PROFILE_SCOPE(__FUNCTION__)
#else
#define PROFILE_SCOPE(name)
#endif

struct ProfileResult {
    std::vector<long long> WallTime;
    std::vector<long long> CpuTime;
};

struct InstrumentationSession {
    std::string Name;
};

class Instrumentor {
   private:
    InstrumentationSession* m_CurrentSession;
    std::map<std::string, ProfileResult> m_Results;

   public:
    Instrumentor() : m_CurrentSession(nullptr) {}

    void BeginSession(const std::string& name) {
        m_CurrentSession = new InstrumentationSession{name};
    }

    void EndSession() {
        delete m_CurrentSession;
        m_CurrentSession = nullptr;
    }

    void AddResult(std::string name, long long walltime, long long cputime) {
        ProfileResult result;
        result.WallTime.push_back(walltime);
        result.CpuTime.push_back(cputime);

        auto ret = m_Results.insert(
            std::pair<std::string, ProfileResult>(name, result));
        if (!ret.second) {
            auto& tmp = ret.first->second;
            tmp.WallTime.push_back(walltime);
            tmp.CpuTime.push_back(cputime);
        }
    }

    std::map<std::string, ProfileResult> GetResults() { return m_Results; }

    static Instrumentor& Get() {
        static Instrumentor instance;
        return instance;
    }
};

class InstrumentationTimer {
   public:
    InstrumentationTimer(const char* name) : m_Name(name), m_Stopped(false) {
        m_StartTimeWall = std::chrono::high_resolution_clock::now();
        m_StartTimeCpu = GetCpuTimeMicro();
    }

    ~InstrumentationTimer() {
        if (!m_Stopped) Stop();
    }

    void Stop() {
        auto endTimeWall = std::chrono::high_resolution_clock::now();
        auto endTimeCpu = GetCpuTimeMicro();

        long long start =
            std::chrono::time_point_cast<std::chrono::microseconds>(
                m_StartTimeWall)
                .time_since_epoch()
                .count();
        long long end =
            std::chrono::time_point_cast<std::chrono::microseconds>(endTimeWall)
                .time_since_epoch()
                .count();

        Instrumentor::Get().AddResult(m_Name, (end - start),
                                      (long long)(endTimeCpu - m_StartTimeCpu));

        m_Stopped = true;
    }

   private:
    const char* m_Name;
    std::chrono::time_point<std::chrono::high_resolution_clock> m_StartTimeWall;
    double m_StartTimeCpu;
    bool m_Stopped;

    double GetCpuTimeMicro() {
        return (double)clock() / CLOCKS_PER_SEC * 1000000;
    }
};

#endif
