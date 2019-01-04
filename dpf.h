#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include <gmp.h>

//use prime 2^128-159
//so wrapping around involves a gap of size 159
//from https://primes.utm.edu/lists/2small/100bit.html
#define MODP (uint128_t) 159
#define LOTSAMODP (uint128_t) 25281

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

//arithmetic mod P
uint128_t addModP(uint128_t in1, uint128_t in2);
uint128_t subModP(uint128_t in1, uint128_t in2);
uint128_t multModP(uint128_t in1, uint128_t in2);

uint128_t getRandomBlock();

//DPF functions

void dpfPRG(EVP_CIPHER_CTX *ctx, uint128_t input, uint128_t* output1, uint128_t* output2, int* bit1, int* bit2);

void genDPF(EVP_CIPHER_CTX *ctx, int domainSize, uint128_t index, int dataSize, uint8_t* data, unsigned char** k0, unsigned char **k1);

uint128_t evalDPF(EVP_CIPHER_CTX *ctx, unsigned char* k, uint128_t x, int dataSize, uint8_t* dataShare);

//DPF checking functions

void PRF(EVP_CIPHER_CTX *ctx, uint128_t seed, int layer, int count, uint128_t* output);

//client check inputs
void clientVerify(EVP_CIPHER_CTX *ctx, uint128_t seed, int index, uint128_t aShare, uint128_t bShare, int dbLayers, uint8_t* bits, uint128_t* nonZeroVectors);

//server check inputs
void serverVerify(EVP_CIPHER_CTX *ctx, uint128_t seed, int dbLayers, int dbSize, uint128_t* vectors, uint128_t* outVectors);

//auditor functionality
int auditorVerify(int dbLayers, uint8_t* bits, uint128_t* nonZeroVectors, uint128_t* outVectorsA, uint128_t* outVectorsB);
