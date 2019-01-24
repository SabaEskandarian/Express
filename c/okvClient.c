#include "okv.h"
#include "okvClient.h"
#include <openssl/rand.h>
#include <omp.h>

#include <math.h>

rowData db[MAX_DB_SIZE];
rowData *pendingRow;
uint8_t userBits[MAX_LAYERS];
uint8_t nonZeroVectors[2*MAX_LAYERS];
uint128_t shareA;
uint128_t shareB;
EVP_CIPHER_CTX *ctx;


//using globals for these is a hack
//doing it to avoid dealing with cgo pointer passing stuff
uint8_t *dpfQueryA;
uint8_t *dpfQueryB;
int queriesSet;
uint8_t *outData;
int outDataSet;
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
    outDataSet = 0;
    dbSize = 0;
    
    return 0;
}


void prepNewRow(int dataSize, uint8_t *keyA, uint8_t *keyB){

    rowData newRow;
    newRow.dataSize = dataSize;

    uint128_t newKeyA = getRandomBlock();
    uint128_t newKeyB = getRandomBlock();
    //print_block(newKeyA);
    //print_block(newKeyB);
    //printf("\n");

    if(!(newRow.keyA = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    if(1 != EVP_EncryptInit_ex(newRow.keyA, EVP_aes_128_ecb(), NULL, (uint8_t*)&newKeyA, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(newRow.keyA, 0);
    
    if(!(newRow.keyB = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    if(1 != EVP_EncryptInit_ex(newRow.keyB, EVP_aes_128_ecb(), NULL, (uint8_t*)&newKeyB, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(newRow.keyB, 0);
    
    memcpy(keyA, &newKeyA, 16);
    memcpy(keyB, &newKeyB, 16);
    
    db[dbSize] = newRow;
    pendingRow = &db[dbSize];
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

void prepAudit(int index, int layers, uint8_t *seed){
    
    //eval the dpf query at A and B and put results in shareA, shareB
    uint8_t temp[16];
    shareA = evalDPF(ctx, dpfQueryA, db[index].rowID, 16, temp);
    shareB = evalDPF(ctx, dpfQueryB, db[index].rowID, 16, temp);
    
    //call the auditing function
    clientVerify(ctx, *(uint128_t*)seed, index, shareA, shareB, layers, userBits, nonZeroVectors);
}


void addAddr(int index, uint8_t *rowId){
    pendingRow->index = index;
    memcpy(&(pendingRow->rowID), rowId, 16);
}

void getVirtualAddress(int index, uint8_t *virtualAddress){
    memcpy(virtualAddress, &db[index].rowID, 16);
}


void decryptRow(int localIndex, uint8_t *dataA, uint8_t *dataB, uint8_t *seedA, uint8_t *seedB){
    int len;
    if(outDataSet){
        free(outData);
        outDataSet = 0;
    }
    
    uint8_t *maskA = (uint8_t*) malloc(db[localIndex].dataSize+16);
    uint8_t *maskB = (uint8_t*) malloc(db[localIndex].dataSize+16);
    uint8_t *seedTempA = (uint8_t*) malloc(db[localIndex].dataSize+16);
    uint8_t *seedTempB = (uint8_t*) malloc(db[localIndex].dataSize+16);
    
    //get the masks
    for(int j = 0; j < (db[localIndex].dataSize+16)/16; j++){
            memcpy(&seedTempA[16*j], seedA, 16);
            seedTempA[16*j] = seedTempA[16*j] ^ j;
    }
    if(1 != EVP_EncryptUpdate(db[localIndex].keyA, maskA, &len, seedTempA, ((db[localIndex].dataSize-1)|15)+1))
        printf("errors occured in rerandomization of entry %d\n", localIndex);
    for(int j = 0; j < (db[localIndex].dataSize+16)/16; j++){
            memcpy(&seedTempB[16*j], seedB, 16);
            seedTempB[16*j] = seedTempB[16*j] ^ j;
    }
    if(1 != EVP_EncryptUpdate(db[localIndex].keyB, maskB, &len, seedTempB, ((db[localIndex].dataSize-1)|15)+1))
        printf("errors occured in rerandomization of entry %d\n", localIndex);
        
    outData = (uint8_t*) malloc(db[localIndex].dataSize);
    
    for(int i = 0; i < db[localIndex].dataSize; i++){
        outData[i] = dataA[i] ^ dataB[i] ^ maskA[i] ^ maskB[i];
    }
    
    //printf("some numbers %d %d %d\n", len, localIndex, db[localIndex].dataSize);
    //printf("\n");
    
    free(maskA);
    free(maskB);
    free(seedTempA);
    free(seedTempB);
    outDataSet = 1;
}

int testing(){
    
    initializeClient();

}
