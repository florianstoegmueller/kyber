project(kyber)

set(CMAKE_CXX_STANDARD 17)

cmake_minimum_required(VERSION 3.1.0)

set(COMMONSOURCES
    kyber/ref/kex.c
    kyber/ref/kem.c
    kyber/ref/indcpa.c
    kyber/ref/polyvec.c
    kyber/ref/poly.c
    kyber/ref/ntt.c
    kyber/ref/cbd.c
    kyber/ref/reduce.c
    kyber/ref/verify.c
    kyber/ref/fips202.c
    kyber/ref/symmetric-shake.c
    src/base64.cpp
    src/coder.cpp
    src/filehandler.cpp
    src/inputparser.cpp
    src/keypair.cpp
    src/kyber.cpp
    src/aes.cpp
)

set(SOURCES
    kyber/ref/randombytes.c
    src/main.cpp
    ${COMMONSOURCES}
)

set(TESTSOURCES
    kyber/ref/rng.c
    src/test_kyber.cpp
    ${COMMONSOURCES}
)

set(PROFILESOURCES
    kyber/ref/randombytes.c
    src/profile_kyber.cpp
    ${COMMONSOURCES}
)

add_executable(kyber ${SOURCES})
add_executable(test_kyber ${TESTSOURCES})
add_executable(profile_kyber2 ${PROFILESOURCES})
add_executable(profile_kyber3 ${PROFILESOURCES})
add_executable(profile_kyber4 ${PROFILESOURCES})

target_compile_definitions(kyber PRIVATE KYBER_K=4)
target_compile_definitions(test_kyber PRIVATE KYBER_K=4)
target_compile_definitions(profile_kyber2 PRIVATE KYBER_K=2)
target_compile_definitions(profile_kyber2 PRIVATE PROFILING=1)
target_compile_definitions(profile_kyber3 PRIVATE KYBER_K=3)
target_compile_definitions(profile_kyber3 PRIVATE PROFILING=1)
target_compile_definitions(profile_kyber4 PRIVATE KYBER_K=4)
target_compile_definitions(profile_kyber4 PRIVATE PROFILING=1)

find_package(OpenSSL REQUIRED)
target_link_libraries(kyber OpenSSL::Crypto)
target_link_libraries(test_kyber OpenSSL::Crypto)
target_link_libraries(profile_kyber2 OpenSSL::Crypto)
target_link_libraries(profile_kyber3 OpenSSL::Crypto)
target_link_libraries(profile_kyber4 OpenSSL::Crypto)
