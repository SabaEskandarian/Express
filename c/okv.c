#include "okv.h"
#include <openssl/rand.h>
#include <omp.h>

#include <math.h>


vatRow db[MAX_DB_SIZE];
int dbSize;
int layers;

uint128_t rerandCounter;
uint128_t rerandSeed;
EVP_CIPHER_CTX *rerandCtx;
EVP_CIPHER_CTX *newRowCtx;

EVP_CIPHER_CTX *ctx[MAX_THREADS];

uint8_t *tempRowId;

int initializeServer(int numThreads){
    
    for(int i = 0; i < numThreads; i++){
        //set fixed key
        if(!(ctx[i] = EVP_CIPHER_CTX_new())) 
            printf("errors occured in creating context\n");
        unsigned char *aeskey = (unsigned char*) "0123456789123456";
        if(1 != EVP_EncryptInit_ex(ctx[i], EVP_aes_128_ecb(), NULL, aeskey, NULL))
            printf("errors occured in init\n");
        EVP_CIPHER_CTX_set_padding(ctx[i], 0);
    }
    
    
    if(!(rerandCtx = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    //uint128_t aeskey2 = getRandomBlock();
    //next line just for testing. Servers would generate and share a secret key here in production
    unsigned char *aeskey2 = (unsigned char*) "2123456789123456";
    if(1 != EVP_EncryptInit_ex(rerandCtx, EVP_aes_128_ecb(), NULL, aeskey2, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(rerandCtx, 0);
    
    if(!(newRowCtx = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    //uint128_t aeskey2 = getRandomBlock();
    //next line just for testing. Servers would generate and share a secret key here in production
    unsigned char *aeskey3 = (unsigned char*) "3123456789123456";
    if(1 != EVP_EncryptInit_ex(newRowCtx, EVP_aes_128_ecb(), NULL, aeskey3, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(newRowCtx, 0);
    
    memset(&rerandSeed, 0, 16);
    
    tempRowId = (uint8_t*) malloc(16);
        
    dbSize = 0;
    layers = 1;
    rerandCounter = 0;
    return 0;
}

//register a new entry on a server
int processnewEntry(int dataSize, uint8_t *rowKey){
    
    int len;
    //generate a new rowId
    uint128_t bigCounter = (uint128_t)dbSize;
    if(1 != EVP_EncryptUpdate(newRowCtx, (uint8_t*)tempRowId, &len, (uint8_t*)&bigCounter, 16))
        printf("errors occured in generating row ID\n");
    
    //print_block(tempRowId);

    uint128_t realRowId;
    memcpy(&realRowId, (uint8_t*)tempRowId, 16);
    uint128_t realRowKey;
    memcpy(&realRowKey, rowKey, 16);
    
    //print_block(realRowId);
    //printf("\n");
    //printf("data size: %d\n", dataSize);
    
    //check if rowId is taken in db and return 1 if that happens
    //we would need a second counter to handle this in reality
    //this could be made more efficient, but I don't really care about optimizing registration time atm
    //for(int i = 0; i < dbSize; i++){
    //    if(memcmp(&realRowId, &(db[i].rowID), 16) == 0){
    //        printf("row id already taken!\n");
    //        return 1;
    //    }
    //}
    
    vatRow entry;
    
    if(!(entry.rowKey = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    if(1 != EVP_EncryptInit_ex(entry.rowKey, EVP_aes_128_ecb(), NULL, (uint8_t*)&realRowKey, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(entry.rowKey, 0);
    
    entry.rowID = realRowId;
    entry.dataSize = dataSize;
    //entry.rowKey = realRowKey;
    entry.data = malloc(dataSize);
    entry.mask = malloc(dataSize);
    memset(entry.mask, 0 , dataSize);
    memset(entry.data, 0 , dataSize);
    db[dbSize] = entry;
    int i = dbSize;//to make code below work without changing stuff
    dbSize = dbSize + 1;
    layers = ceil(log2(dbSize));
    
    
    //now do the encryption/rerandomization for this entry so it can be retrieved normally
    uint8_t* maskTemp = (uint8_t*) malloc(dataSize+16);
    uint8_t* seedTemp = (uint8_t*) malloc(dataSize+16);
    //get rerandomization mask
    for(int j = 0; j < (db[i].dataSize+16)/16; j++){
        memcpy(&seedTemp[16*j], &rerandSeed, 16);
        seedTemp[16*j] = seedTemp[16*j] ^ j;
    }
    if(1 != EVP_EncryptUpdate(db[i].rowKey, maskTemp, &len, seedTemp, ((dataSize-1)|15)+1))
        printf("errors occured in rerandomization of entry %d\n", i);

    //xor data into db and rerandomize db entry
    for(int j = 0; j < dataSize; j++){
        db[i].data[j] = db[i].data[j] ^ maskTemp[j];
        db[i].mask[j] = maskTemp[j];
    }
    free(maskTemp);
    free(seedTemp);
    return dbSize-1;
}

void xorIn(int i, uint8_t *data){
    for(int j = 0; j < db[i].dataSize; j++){
        db[i].data[j] = db[i].data[j] ^ data[j];
    }
}

void rerandDB() {
    
    int len2;
    
    //get rerandomization seed
    if(1 != EVP_EncryptUpdate(rerandCtx, (uint8_t*)&rerandSeed, &len2, (uint8_t*)&rerandCounter, 16))
        printf("errors occured in getting rerandomization seed\n");
    
    #pragma omp parallel for
    for(int i = 0; i < dbSize; i++){
        
        int len;
        
        //TODO: move these out into a big buffer where each thread can use its own part?
        //allocating that buffer might take longer than it's worth
        //see what performance we get as-is and change if needed
        uint8_t* maskTemp = (uint8_t*) malloc(db[i].dataSize+16);
        uint8_t* seedTemp = (uint8_t*) malloc(db[i].dataSize+16);
        
        //get rerandomization mask
        for(int j = 0; j < (db[i].dataSize+16)/16; j++){
            memcpy(&seedTemp[16*j], &rerandSeed, 16);
            seedTemp[16*j] = seedTemp[16*j] ^ j;
        }
        if(1 != EVP_EncryptUpdate(db[i].rowKey, maskTemp, &len, seedTemp, ((db[i].dataSize-1)|15)+1))
            printf("errors occured in rerandomization of entry %d\n", i);
        
        //xor data into db and rerandomize db entry
        for(int j = 0; j < db[i].dataSize; j++){
            db[i].data[j] = db[i].data[j] ^ db[i].mask[j] ^ maskTemp[j];
            db[i].mask[j] = maskTemp[j];
            //printf("%x ", dataShare[j]);
        }
        //printf("\n");
        
        free(maskTemp);
        free(seedTemp);
    }
    
    rerandCounter++;
}

int getEntrySize(uint8_t *id, int index){
    uint128_t realId;
    memcpy(&realId, id, 16);
    
    if(db[index].rowID == realId){
        return db[index].dataSize;
    }
    else{
        return -1;
    }
}

//read an entry
int readEntry(uint8_t *id, int index, uint8_t *data, uint8_t *seed){
    uint128_t realId;
    memcpy(&realId, id, 16);
    if(db[index].rowID == realId){
        memcpy(data, db[index].data, db[index].dataSize);
        memcpy(seed, &rerandSeed, 16);
        return db[index].dataSize;
    }
    else{
        return -1;
    }
}

int okv_main(){
    initializeServer(0);
    
    //some testing of the server functionality
    
    
    return 0;
}
