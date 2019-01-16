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

int initializeServer(int expNum){
    
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
int processnewEntry(uint128_t rowId, int dataSize, uint128_t rowKey){
    
    //check if rowId is taken in db and return 1 if that happens
    //this could be made more efficient, but I don't really care about optimizing registration time atm
    for(int i = 0; i < dbSize; i++){
        if(memcmp(&rowId, &(db[i].rowID), 16) == 0){
            return 1;
        }
    }
    
    vatRow entry;
    
    entry.rowID = rowId;
    entry.dataSize = dataSize;
    entry.rowKey = rowKey;
    entry.data = malloc(dataSize);
    entry.mask = malloc(dataSize);
    memset(entry.mask, 0 , dataSize);
    db[dbSize] = entry;
    dbSize = dbSize + 1;
    layers = ceil(log2(dbSize));
    return 0;
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
    uint8_t* maskTemp = (uint8_t*) malloc(pqDataSize);
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
        
        //get rerandomizatoin mask
        if(1 != EVP_EncryptUpdate(rerandCtx, maskTemp, &len, (uint8_t*)&rerandSeed, ds))
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
    
    free(pendingQuery);
}

//read an entry
int readEntry(uint128_t id, int index, vatRow *entry){
    if(db[index].rowID == id){
        memcpy(entry, &db[index], sizeof(vatRow));
        memset(&(entry->mask), 0, db[index].dataSize);
        memset(&(entry->rowKey), 0, 16);
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
