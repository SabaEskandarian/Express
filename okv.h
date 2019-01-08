#include "dpf.h"

#define MAX_DB_SIZE 10000
#define MAX_QUERY_SIZE 20000000

typedef struct{
	uint128_t rowID; //128 bit virtual address
    uint128_t rowKey; //key used to encrypt for rerandomizing
    int dataSize; //size of the data stored here
    uint8_t* mask; //current mask resulting from rerandomization
    uint8_t* data; //the actual data
} vatRow;
