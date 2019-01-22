#include "okv.h"
#include <openssl/rand.h>
#include <omp.h>

#include <math.h>


vatRow db[MAX_DB_SIZE];
int dbSize;
int layers;
uint128_t rerandCounter;
uint128_t vector[MAX_DB_SIZE];
uint128_t outVector[2*MAX_DB_SIZE];
uint8_t *pendingQuery;
uint128_t verificationSeed;
uint128_t rerandSeed;
int pqDataSize;
EVP_CIPHER_CTX *ctx;
EVP_CIPHER_CTX *rerandCtx;

int initializeServer(){
    
    //set fixed key
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    unsigned char *aeskey = (unsigned char*) "0123456789123456";
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aeskey, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    if(!(rerandCtx = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    //uint128_t aeskey2 = getRandomBlock();
    //next line just for testing. Servers would generate and share a secret key here in production
    unsigned char *aeskey2 = (unsigned char*) "2123456789123456";
    if(1 != EVP_EncryptInit_ex(rerandCtx, EVP_aes_128_ecb(), NULL, (uint8_t*) &aeskey2, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(rerandCtx, 0);
    
    dbSize = 0;
    layers = 1;
    rerandCounter = 0;
    return 0;
}

//register a new entry on a server
int processnewEntry(uint8_t *rowId, int dataSize, uint8_t *rowKey){

    uint128_t realRowId;
    memcpy(&realRowId, rowId, 16);
    uint128_t realRowKey;
    memcpy(&realRowKey, rowKey, 16);
    
    //check if rowId is taken in db and return 1 if that happens
    //this could be made more efficient, but I don't really care about optimizing registration time atm
    for(int i = 0; i < dbSize; i++){
        if(memcmp(&realRowId, &(db[i].rowID), 16) == 0){
            return 1;
        }
    }
    
    vatRow entry;
    
    if(!(entry.rowKey = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    if(1 != EVP_EncryptInit_ex(entry.rowKey, EVP_aes_128_ctr(), NULL, (uint8_t*)&realRowKey, NULL))
        printf("errors occured in init\n");
    
    entry.rowID = realRowId;
    entry.dataSize = dataSize;
    //entry.rowKey = realRowKey;
    entry.data = malloc(dataSize);
    entry.mask = malloc(dataSize);
    memset(entry.mask, 0 , dataSize);
    db[dbSize] = entry;
    dbSize = dbSize + 1;
    layers = ceil(log2(dbSize));
    return dbSize-1;
}


uint128_t registerQuery(unsigned char* dpfKey, int dataSize, int dataTransferSize){
    //change this to copy the data over instead of setting the pointer so that we're not holding a go pointer after the function returns
    //pendingQuery = dpfKey;
    pendingQuery = (uint8_t*) malloc(dataTransferSize);
    memcpy(pendingQuery, dpfKey, dataTransferSize);
    pqDataSize = dataSize;
    verificationSeed = getRandomBlock();//maybe replace this with something generated from a secret shared between the servers
    return verificationSeed;
}

//processes query on the server
void processQuery(void){
    
    uint8_t* dataShare = (uint8_t*) malloc(pqDataSize);
    uint8_t* maskTemp = (uint8_t*) malloc(pqDataSize+16);
    uint8_t* seedTemp = (uint8_t*) malloc(pqDataSize+16);
    int len;
    
    //get rerandomization seed
    if(1 != EVP_EncryptUpdate(rerandCtx, (uint8_t*)&rerandSeed, &len, (uint8_t*)&rerandCounter, 16))
        printf("errors occured in getting rerandomization seed\n");
    
    for(int i = 0; i < dbSize; i++){
        
        int ds = db[i].dataSize;
        if(pqDataSize < ds){
            ds = pqDataSize;
        }
        //run dpf on each input
        vector[i] = evalDPF(ctx, pendingQuery, i, ds, dataShare);
        
        //get rerandomization mask
        for(int j = 0; j < (db[i].dataSize+16)/16; j++){
            memcpy(&seedTemp[16*j], &rerandSeed, 16);
        }
        if(1 != EVP_EncryptUpdate(db[i].rowKey, maskTemp, &len, seedTemp, ds))
            printf("errors occured in rerandomization of entry %d\n", i);
        
        //xor data into db and rerandomize db entry
        for(int j = 0; j < ds; j++){
            db[i].data[j] = db[i].data[j] ^ dataShare[j] ^ db[i].mask[j] ^ maskTemp[j];
            db[i].mask[j] = maskTemp[j];
        }
        
    }
    //increment rerandomization counter
    rerandCounter++;
    
    //produce verification check for the data
    serverVerify(ctx, verificationSeed, layers, dbSize, vector, outVector);
    
    free(dataShare);
    free(maskTemp);
    free(seedTemp);
    free(pendingQuery);
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
        memcpy(data, db[index].data, sizeof(db[index].dataSize));
        memcpy(seed, &rerandSeed, 16);
        return db[index].dataSize;
    }
    else{
        return -1;
    }
}

int okv_main(){
    initializeServer(0);
    
    //TODO: some testing of the server functionality
    
    
    return 0;
}