#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define BLOCK_SIZE 16
#define HTTP_SUCCESS 200

#define SUCCESS 1
#define ERROR 0

void print_log(uint8_t* data, size_t len, uint8_t* slog) {
    printf("%s = ", slog);

    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


void to_hex(uint8_t* in, size_t ilen, uint8_t* out, size_t olen)
{
    uint8_t* pin = in;
    const char* hex = "0123456789abcdef";
    uint8_t* pout = out;
    for (; pin < in + ilen; pout += 2, pin++) {
        pout[0] = hex[(*pin >> 4) & 0xF];
        pout[1] = hex[*pin & 0xF];
        if (pout + 2 - out > olen) {
            break;
        }
    }
}

int access(uint8_t* iv, uint8_t* cur) {
    memcpy(cur, iv, BLOCK_SIZE);

    uint8_t out[BLOCK_SIZE << 2];
    to_hex(cur, BLOCK_SIZE << 1, out, BLOCK_SIZE << 2);
    uint8_t cmd[1024] = { 0 };
    uint8_t* path = "E:\\eshigoto\\dec_oracle\\Release\\dec_oracle.exe ";
    memcpy(cmd, path, strlen(path));
    memcpy(cmd + strlen(path), out, BLOCK_SIZE << 2);

    return system(cmd);
}

void attack(uint8_t* c, size_t len) {

    uint8_t* old_iv = (uint8_t*)calloc(BLOCK_SIZE, sizeof(uint8_t));
    memcpy(old_iv, c, BLOCK_SIZE);

    uint8_t* cur = (uint8_t*)calloc(BLOCK_SIZE << 1, sizeof(uint8_t));

    size_t block_num = (len >> 4);
    size_t olen = (block_num - 1) * BLOCK_SIZE;
    uint8_t* out = (uint8_t*)calloc(olen, sizeof(uint8_t));

    for (size_t t = 1; t < block_num; t++) {
        printf("block %d:\n", t);
        memcpy(cur + BLOCK_SIZE, c + t * BLOCK_SIZE, BLOCK_SIZE);

        uint8_t iv[BLOCK_SIZE] = { 0 };
        uint8_t mid[BLOCK_SIZE] = { 0 };
        uint8_t* last = mid;
        for (uint8_t i = 0; i < BLOCK_SIZE; i++) {
            for (int j = 0x00; j <= 0xFF; j++) {
                iv[BLOCK_SIZE - i - 1] = j;
                if (access(&iv, cur) == HTTP_SUCCESS) {
                    *last = iv[BLOCK_SIZE - i - 1] ^ (i + 1);

                    print_log(mid, BLOCK_SIZE, "mid");

                    last++;
                    for (uint8_t k = 0; k < (last - mid); k++) {
                        iv[BLOCK_SIZE - k - 1] = mid[k] ^ (i + 2);
                    }
                    break;
                }
            }
        }

        for (uint8_t i = 0; i < BLOCK_SIZE; i++) {
            out[i + (t - 1) * BLOCK_SIZE] = mid[BLOCK_SIZE - i - 1] ^ old_iv[i];
            printf("%02x", out[i + (t - 1) * BLOCK_SIZE]);
        }
        printf("\n");
        memcpy(old_iv, c + t * BLOCK_SIZE, BLOCK_SIZE);
    }

    print_log(out, olen, "pad_msg");
    uint8_t p = out[olen - 1];
    print_log(out, olen - p, "unpad_msg");

    free(cur);
    free(out);
    free(old_iv);
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

int main() {
    uint8_t* c = "3eab37cb5de9eba525c9e04217d940b613a599bfc1e1b85dd2fecdef647b59a960e2cb16884d4e78777e6fa2d7cf482b55e9269b25f01d70df4b56ce08c1e060";
    uint8_t* buf = (uint8_t*)calloc(strlen(c) >> 1, sizeof(uint8_t));
    int ret = from_hex(c, strlen(c), buf);
    attack(buf, strlen(c) >> 1);
    free(buf);
    return 0;
}
