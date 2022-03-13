#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "randombytes.h"
#include "aes_enc.h"
#include "mbedtls/aes.h"

void print_log(uint8_t* data, size_t len, uint8_t* slog) {
    printf("%s = ", slog);
    
    for (size_t i = 0; i < len; i++) {
        /*
        if (i % 16 == 0) {
            printf(" ");
        }
        */
        printf("%02x", data[i]);
    }
    printf("\n");
}

// output: iv || c
uint8_t* aes_enc(const uint8_t* input, size_t ilen, size_t* olen, uint8_t* iv, uint8_t vlen) {

    /* iv padding */
    uint8_t piv[AES_128_BLOCK_BYTES_SIZE];
    memcpy(piv, iv, vlen);
    while (vlen < AES_128_BLOCK_BYTES_SIZE) {
        piv[vlen] = 0x00;
        vlen++;
    }

    /* PKCS5 padding */
    uint8_t p = AES_128_BLOCK_BYTES_SIZE - (ilen) % AES_128_BLOCK_BYTES_SIZE;
    size_t plen = ((ilen >> 4) + 1) << 4;
    uint8_t* pad_input = (uint8_t*)calloc(plen, sizeof(uint8_t));
    memcpy(pad_input, input, ilen);
    for (uint8_t i = 0; i < p; i++) {
        pad_input[ilen + i] = p;
    }
    (*olen) = AES_128_BLOCK_BYTES_SIZE + plen;

    /* copy iv */
    uint8_t* output = (uint8_t*)calloc(plen + AES_128_BLOCK_BYTES_SIZE, sizeof(uint8_t));
    memcpy(output, piv, AES_128_BLOCK_BYTES_SIZE * sizeof(uint8_t));

    /* copy cipher */
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, strlen(key) << 3);
    int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, plen, piv, pad_input, output + vlen);
    mbedtls_aes_free(&ctx);

    if (pad_input != NULL) {
        free(pad_input);
        pad_input = NULL;
    }

    if (ret) {
        free(output);
        return NULL;
    }
    else {
        return output;
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

int is_valid_m(size_t len) {

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
    return SUCCESS;
}

int main(int argc, char** argv) {

    if (argc != 2) {
        printf("Error.\n");
        return;
    }

    int ret;
    size_t len = strlen(argv[1]);

    /* check input length and key */
    if (is_valid_m(len) != SUCCESS) {
        printf("Error.\n");
        return;
    }

    /* tranform input to int array */
    uint8_t* input;
    size_t ilen;
    
    if (!(len % 2)) {
        ilen = len >> 1;
        input = (uint8_t*)malloc(ilen * sizeof(uint8_t));
        ret = from_hex(argv[1], len, input);
    }
    else {
        len += 1;
        ilen = len >> 1;
        input = (uint8_t*)malloc(ilen * sizeof(uint8_t));
        uint8_t* buf = (uint8_t*)malloc(len * sizeof(uint8_t));
        memcpy(buf + 1, argv[1], strlen(argv[1]));
        ret = from_hex(buf, len, input);
        free(buf);
    }
    if (!ret) {
        printf("msg must be hex encode.\n");
        return;
    }

    /* set random iv */
    uint8_t iv[AES_128_BLOCK_BYTES_SIZE];
    ret = randombytes(iv, AES_128_BLOCK_BYTES_SIZE);
    if (ret != 0) {
        printf("Error in `randombytes`");
        return;
    }

    /* encrypt */
    size_t olen = 0;
    uint8_t* output = aes_enc(input, ilen, &olen, iv, AES_128_BLOCK_BYTES_SIZE);
    if (output == NULL) {
        printf("encrypt error.\n");
        return;
    }

    print_log(output, olen, "iv||c");
    free(input);
    free(output);
    return 0;
}