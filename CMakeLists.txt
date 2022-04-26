project(kyber)

set(CMAKE_CXX_STANDARD 17)

cmake_minimum_required(VERSION 3.1.0)

AUX_SOURCE_DIRECTORY(src SRCDIR) 

set(SOURCES
    kyber/ref/kex.c
    kyber/ref/kem.c
    kyber/ref/indcpa.c
    kyber/ref/polyvec.c
    kyber/ref/poly.c
    kyber/ref/ntt.c
    kyber/ref/cbd.c
    kyber/ref/reduce.c
    kyber/ref/verify.c
    kyber/ref/randombytes.c
    kyber/ref/fips202.c
    kyber/ref/symmetric-shake.c
    ${SRCDIR}
)

add_executable(kyber ${SOURCES})
target_compile_definitions(kyber PRIVATE KYBER_K=2)