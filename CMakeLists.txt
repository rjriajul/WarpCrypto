cmake_minimum_required(VERSION 3.15)
project(${SKBUILD_PROJECT_NAME} LANGUAGES C)

find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)

Python_add_library(tgcrypto MODULE
    tgcrypto/tgcrypto.c
    tgcrypto/aes256.c
    tgcrypto/ige256.c
    tgcrypto/ctr256.c
    tgcrypto/cbc256.c
)

target_include_directories(tgcrypto PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tgcrypto)
install(TARGETS tgcrypto LIBRARY DESTINATION .)
