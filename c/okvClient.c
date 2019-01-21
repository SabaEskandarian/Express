#include "okv.h"
#include <openssl/rand.h>
#include <omp.h>

#include <math.h>

rowData db[MAX_DB_SIZE];
rowData *pendingRow;
EVP_CIPHER_CTX *ctx;


//using globals for these is a hack
//doing it to avoid dealing with cgo pointer passing stuff
uint8_t *dpfQueryA;
uint8_t *dpfQueryB;
int queriesSet;
uint8_t *outData;
int dbSize;

int initializeClient(){
        //set fixed key
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    unsigned char *aeskey = (unsigned char*) "0123456789123456";
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aeskey, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    queriesSet = 0;
    dbSize = 0;
    
    return 0;
}


void prepNewRow(int dataSize, uint8_t *rowId, uint8_t *keyA, uint8_t *keyB){
    rowData newRow;
    *pendingRow = newRow;    
    newRow.dataSize = dataSize;
    
    newRow.rowID = getRandomBlock();
    uint128_t newKeyA = getRandomBlock();
    uint128_t newKeyB = getRandomBlock();

    if(!(newRow.keyA = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    if(1 != EVP_EncryptInit_ex(newRow.keyA, EVP_aes_128_ecb(), NULL, &newKeyA, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(newRow.keyA, 0);
    
    if(!(newRow.keyB = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    if(1 != EVP_EncryptInit_ex(newRow.keyB, EVP_aes_128_ecb(), NULL, &newKeyB, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(newRow.keyB, 0);
    
    rowId = &newRow.rowID;
    keyA = &newKeyA;
    keyB = &newKeyB;
    
    db[dbSize] = newRow;
    dbSize += 1;
}

void prepQuery(int localIndex, uint8_t *dataToWrite, int dataSize, int *querySize){
    
    if(queriesSet){
        free(dpfQueryA);
        free(dpfQueryB);
        queriesSet = 0;
    }
    
    if(dataSize > db[localIndex].dataSize) {
        printf("dataSize too big for this entry\n");
    }
    
    *querySize = 1 + 16 + 1 + 18 * 128 + dataSize;
    
    genDPF(ctx, 128, db[localIndex].rowID, dataSize, dataToWrite, &dpfQueryA, &dpfQueryB);
    
    queriesSet = 1;
}


void addIndex(int index){
    pendingRow.index = index;
}

void getVirtualAddress(int index, uint8_t *virtualAddress){
    virtualAddress = (uint8_t*)&(db[index].rowID);
}


void decryptRow(int localIndex, uint8_t *dataA, uint8_t *dataB, uint8_t *seedA, uint8_t *seedB){
    EVP_CIPHER_CTX *ctxA;
    EVP_CIPHER_CTX *ctxB;
    
    uint8_t *maskA = (uint8_t*) malloc(db[localIndex].dataSize+16);
    uint8_t *maskB = (uint8_t*) malloc(db[localIndex].dataSize+16);
    uint8_t *seedTempA = (uint8_t*) malloc(db[localIndex].dataSize+16);
    uint8_t *seedTempB = (uint8_t*) malloc(db[localIndex].dataSize+16);
    
    //get the masks
    for(int j = 0; j < (db[localIndex].dataSize+16)/16; j++){
            memcpy(&seedTempA[16*j], &seedA, 16);
        }
        if(1 != EVP_EncryptUpdate(db[i].rowKey, maskA, &len, seedTempA, db[localIndex].dataSize))
            printf("errors occured in rerandomization of entry %d\n", i);
    for(int j = 0; j < (db[localIndex].dataSize+16)/16; j++){
            memcpy(&seedTempB[16*j], &seedB, 16);
        }
        if(1 != EVP_EncryptUpdate(db[i].rowKey, maskB, &len, seedTempB, db[localIndex].dataSize))
            printf("errors occured in rerandomization of entry %d\n", i);
        
    //this will have to be freed in the calling code
    outData = (uint8_t*) malloc(db[localIndex].dataSize);
    for(int i = 0; i < db[localIndex].dataSize; i++){
        outData[i] = dataA[i] ^ dataB[i] ^ maskA[i] ^ maskB[i];
    }
    
    free(maskA);
    free(maskB);
    free(seedTempA);
    free(seedTempB);
}
