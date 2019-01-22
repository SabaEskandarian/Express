#ifndef _OKVCLIENT
#define _OKVCLIENT

#include "dpf.h"

typedef struct{
    int index;
    int dataSize; //size of the data stored here
    uint128_t rowID; //128 bit virtual address
    EVP_CIPHER_CTX *keyA; //key used to encrypt for rerandomizing
    EVP_CIPHER_CTX *keyB; //key used to encrypt for rerandomizing
} rowData;


int initializeClient();

//prepare data to add an entry
void prepNewRow(int dataSize, uint8_t *rowId, uint8_t *keyA, uint8_t *keyB);

//add index to most recent row
void addIndex(int index);

//get the virtual address corresponding to a given index
void getVirtualAddress(int index, uint8_t *virtualAddress);

//prepare a query
void prepQuery(int localIndex, uint8_t *dataToWrite, int dataSize, int *querySize);

//prepare an audit response for most recent query
void prepAudit(int index, int layers, uint8_t *seed);

//decrypt and recover a row
void decryptRow(int localIndex, uint8_t *dataA, uint8_t *dataB, uint8_t *seedA, uint8_t *seedB);

#endif