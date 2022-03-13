#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes_dec.h"
#include "mbedtls/aes.h"

void print_log(uint8_t* data, size_t len, uint8_t* slog) {
    printf("%s = ", slog);

    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// input: iv || c
int aes_dec(uint8_t* input, size_t ilen) {
    /* set iv */
    uint8_t piv[AES_128_BLOCK_BYTES_SIZE];
    memcpy(piv, input, AES_128_BLOCK_BYTES_SIZE);
    ilen -= AES_128_BLOCK_BYTES_SIZE;

    /* set key */
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, key, strlen(key) << 3);

    /* decrypt */
    uint8_t* output = (uint8_t*)calloc(ilen, sizeof(uint8_t));
    int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, ilen, piv, input + AES_128_BLOCK_BYTES_SIZE, output);
    mbedtls_aes_free(&ctx);

    /* check padding */
    uint8_t p = output[ilen - 1];
    if (!ret) {

        if (!((p >= 0x01) & (p <= 0x10))) {
            free(output);
            return HTTP_ERROR;
        }

        for (uint8_t i = ilen - p; i < ilen; i++) {
            if (output[i] != p) {
                free(output);
                return HTTP_ERROR;
            }
        }
        free(output);
        return HTTP_SUCCESS;
    }
    else {
        free(output);
        return ERROR;
    }
}

int from_hex(uint8_t* s, size_t l, uint8_t* d) {
    while (l--) {
        uint8_t* m = s + l;
        uint8_t* n = m - 1;

        if (!((*m >= '0') & (*m <= 'f') || (*m == 0)) || !((*n >= '0') & (*n <= 'f') || (*n == 0))) {
            return ERROR;
        }
        *(d + l / 2) =
            ((*m > '9' ? *m + 9 : *m) & 0x0f) |
            ((*n > '9' ? *n + 9 : *n) << 4);
        l--;
    }
    return SUCCESS;
}

int is_valid_c(size_t len) {

    /* overflow */
    if ((len + 1) < len) {
        printf("input too long.\n");
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    /* check key */
    size_t klen = strlen(key);
    if (klen != AES_128_BLOCK_BYTES_SIZE) {
        printf("key must be 16 bytes.\n");
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    /* even */
    if (len % 2) {
        printf("input length is %d bits. it must be a multiple of the block size(%d bits).\n", len << 2, AES_128_BLOCK_BYTES_SIZE << 3);
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    /* check form iv||c */
    size_t byte_len = len >> 1;
    if (byte_len <= AES_128_BLOCK_BYTES_SIZE) {
        printf("input length is %d bytes. the input form is iv||c, %d bytes at least.\n", byte_len, AES_128_BLOCK_BYTES_SIZE << 1);
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    /* check length for valid block size */
    if ((byte_len % AES_128_BLOCK_BYTES_SIZE) != 0) {
        printf("input length is %d bytes. it must be a multiple of the block size(%d bytes).\n", byte_len, AES_128_BLOCK_BYTES_SIZE);
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    return SUCCESS;
}

int main(int argc, const char** argv) {

    if (argc != 2) {
        printf("Error.\n");
        return;
    }

    int ret;
    size_t len = strlen(argv[1]);

    /* check input length and key */
    if (is_valid_c(len) != SUCCESS) {
        printf("Error.\n");
        return;
    }

    /* tranform input to int array */
    size_t ilen = len >> 1;
    uint8_t* input = malloc(ilen * sizeof(uint8_t));
    ret = from_hex(argv[1], len, input);
    if (!ret) {
        printf("msg must be hex encode.\n");
        return;
    }
    // print_log(input, ilen, "iv||c");

    /* decrypt */
    ret = aes_dec(input, ilen);
    free(input);
    input = NULL;

    if (ret == HTTP_SUCCESS) {
        printf("HTTP 200.\n");
        return HTTP_SUCCESS;
    }
    else if (ret == HTTP_ERROR) {
        printf("HTTP 500 server error.\n");
        return HTTP_ERROR;
    }
    else {
        printf("decrypt error.\n");
        return;
    }
    return;
}