cmake_minimum_required(VERSION 2.6)

project(“aes_enc”)
set(libs
mbedtls
mbedcrypto
mbedx509
)

set(targets
aes_enc
)

link_libraries("-static")
add_executable(aes_enc aes_enc.c randombytes.c)

target_link_libraries(aes_enc ${libs})
