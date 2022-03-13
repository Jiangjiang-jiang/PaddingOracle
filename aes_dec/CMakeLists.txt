cmake_minimum_required(VERSION 2.6)

project(“aes_dec”)
set(libs
mbedtls
mbedcrypto
mbedx509
)

set(targets
aes_dec
)

link_libraries("-static")
add_executable(aes_dec aes_dec.c)

target_link_libraries(aes_dec ${libs})
