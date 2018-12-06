#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"
#include "block.h"

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

void PRG(AES_KEY *key, block input, block* output1, block* output2, int* bit1, int* bit2);

//belongs in another header file?
//void PRG_SINGLE(AES_KEY *key, block input, block* output);

void GEN(AES_KEY *key, uint128_t alpha, int n, unsigned char** k0, unsigned char **k1);

block EVAL(AES_KEY *key, unsigned char* k, uint128_t x);

uint8_t interpret_result(block val);

