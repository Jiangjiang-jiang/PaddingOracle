#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#define AES_128_BLOCK_BYTES_SIZE 16
#define HTTP_ERROR 500
#define HTTP_SUCCESS 200

#define SUCCESS 1
#define ERROR 0

/* keep secret */
static uint8_t* key = "^Qnk&gUV(NBTkc*=";


int aes_dec(uint8_t* input, size_t ilen);