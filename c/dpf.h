#ifndef _DPF
#define _DPF

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

//defining these here
//so they don't have to be repeated across okv and okvClient
#define MAX_LAYERS 21
#define MAX_DB_SIZE 1000010
#define MAX_DATA_SIZE 10000000
#define MAX_THREADS 1024

//use prime 2^128-159
//so wrapping around involves a gap of size 159
//from https://primes.utm.edu/lists/2small/100bit.html
#define MODP (uint128_t) 159

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

void print_block(uint128_t input);

//arithmetic mod P
uint128_t addModP(uint128_t in1, uint128_t in2);
uint128_t subModP(uint128_t in1, uint128_t in2);
uint128_t multModP(uint128_t in1, uint128_t in2);

uint128_t getRandomBlock(void);

//DPF functions

void dpfPRG(EVP_CIPHER_CTX *ctx, uint128_t input, uint128_t* output1, uint128_t* output2, int* bit1, int* bit2);

void genDPF(EVP_CIPHER_CTX *ctx, int domainSize, uint128_t index, int dataSize, uint8_t* data, unsigned char** k0, unsigned char **k1);

uint128_t evalDPF(EVP_CIPHER_CTX *ctx, unsigned char* k, uint128_t x, int dataSize, uint8_t* dataShare);

//DPF checking functions

void PRF(EVP_CIPHER_CTX *ctx, uint128_t seed, int layer, int count, uint128_t* output);
void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len);

//new auditing functions
void clientGenProof(EVP_CIPHER_CTX *ctx, uint128_t seed, int index, uint128_t aShare, uint128_t bShare, uint8_t* outputsAIn, uint8_t* outputsBIn);
void serverSetupProof(EVP_CIPHER_CTX *ctx, uint8_t *seedIn, int dbSize, uint8_t* vectorsIn, uint8_t* mIn, uint8_t* cIn);
void serverComputeQuery(EVP_CIPHER_CTX *ctx, uint8_t *seedIn, uint8_t* mIn, uint8_t* cIn, uint8_t* proofIn, uint8_t* ansIn);
int serverVerifyProof(uint8_t* ans1In, uint8_t* ans2In);
uint128_t evalLinearR(uint128_t r, uint128_t p0, uint128_t p1);
uint128_t evalQuadraticR(uint128_t r, uint128_t h0, uint128_t h1, uint128_t h2);


//old auditing functions

//client check inputs
void clientVerify(EVP_CIPHER_CTX *ctx, uint128_t seed, int index, uint128_t aShare, uint128_t bShare, int dbLayers, uint8_t* bits, uint8_t* nonZeroVectorsIn);
void riposteClientVerify(EVP_CIPHER_CTX *ctx, uint128_t seed, int dbSize, uint128_t *va, uint128_t *vb, uint8_t **digestA, uint8_t **digestB);

//server check inputs
void serverVerify(EVP_CIPHER_CTX *ctx, uint8_t *seedIn, int dbLayers, int dbSize, uint8_t* vectorsIn, uint8_t* outVectorsIn);
void riposteServerVerify(EVP_CIPHER_CTX *ctx, uint128_t seed, int dbSize, uint128_t *vector, uint128_t *mVector, uint128_t *cValue);

//auditor functionality
int auditorVerify(int dbLayers, uint8_t* bits, uint8_t* nonZeroVectorsIn, uint8_t* outVectorsAIn, uint8_t* outVectorsBIn);
int riposteAuditorVerify(uint8_t *digestA, uint8_t *digestB, uint8_t *ma, uint8_t *mb, uint128_t ca, uint128_t cb, int dbSize);

#endif
