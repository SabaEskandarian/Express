#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

/*
 * Not clear we need this
//code from
//https://locklessinc.com/articles/256bit_arithmetic/
typedef unsigned long long u64b;
typedef unsigned __int128 u128b;
typedef struct u256b u256b;
struct u256b
{
	u64b lo;
	u64b mid;
	u128b hi;
};

u256b add256b(u256b *x, u256b *y);

u256b mul256b(u256b *x, u256b *y);
*/

uint128_t getRandomBlock();

//DPF functions, PRG, GEN, and EVAL from libdpf

void dpfPRG(EVP_CIPHER_CTX *ctx, uint128_t input, uint128_t* output1, uint128_t* output2, int* bit1, int* bit2);

void genDPF(EVP_CIPHER_CTX *ctx, int domainSize, uint128_t index, int dataSize, uint8_t* data, unsigned char** k0, unsigned char **k1);

uint128_t evalDPF(EVP_CIPHER_CTX *ctx, unsigned char* k, uint128_t x, int dataSize, uint8_t* dataShare);

//DPF checking functions
//written assuming 128 bit dpf domain

void PRF(EVP_CIPHER_CTX *ctx, uint128_t seed, int layer, int count, uint128_t* output);

//client check inputs
void clientVerify(EVP_CIPHER_CTX *ctx, uint128_t seed, int index, uint128_t aShare, uint128_t bShare, int dbLayers, uint8_t* bits, uint128_t* nonZeroVectors);

//server check inputs
void serverVerify(EVP_CIPHER_CTX *ctx, uint128_t seed, int dbLayers, int dbSize, uint128_t* vectors, uint128_t* outVectors);

//auditor functionality
int auditorVerify(int dbLayers, uint8_t* bits, uint128_t* nonZeroVectors, uint128_t* outVectorsA, uint128_t* outVectorsB);
