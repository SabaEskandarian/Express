#include "dpf.h"
#include <openssl/rand.h>

block dpf_reverse_lsb(block input){
	static long long b1 = 0;
	static long long b2 = 1;
	block xor = dpf_make_block(b1, b2);
	return dpf_xor(input, xor);
}

block dpf_set_lsb_zero(block input){
	int lsb = dpf_lsb(input);

	if(lsb == 1){
		return dpf_reverse_lsb(input);	
	}else{
		return input;
	}
}

/*
 * Not clear we need this
//these functions taken from
//https://locklessinc.com/articles/256bit_arithmetic/
//they saw naive multiplication was faster than karatsuba for this
//for an older version of gcc, they got a >2x improvement by writing the multiplication in assembly
//so maybe we want to switch to assembly later if that ends up being a bottleneck
u256b add256b(u256b *x, u256b *y)
{
	u128b lo = (u128b) x->lo + y->lo;
	u128b mid = (u128b) x->mid + y->mid + (lo >> 64);
	u256b result =
	{
		.lo = lo,
		.mid = mid,
		.hi = x->hi + y->hi + (mid >> 64),
	};
	
	return result;
}

u256b mul256b(u256b *x, u256b *y)
{
	u128b t1 = (u128b) x->lo * y->lo;
	u128b t2 = (u128b) x->lo * y->mid;
	u128b t3 = x->lo * y->hi;
	u128b t4 = (u128b) x->mid * y->lo;
	u128b t5 = (u128b) x->mid * y->mid;
	u64b t6 = x->mid * y->hi;
	u128b t7 = x->hi * y->lo;
	u64b t8 = x->hi * y->mid;

	u64b lo = t1;
	u128b m1 = (t1 >> 64) + (u64b)t2;
	u64b m2 = m1;
	u128b mid = (u128b) m2 + (u64b)t4;
	u128b hi = (t2 >> 64) + t3 + (t4 >> 64) + t5 + ((u128b) t6 << 64) + t7
		 + ((u128b) t8 << 64) + (m1 >> 64) + (mid >> 64);
	
	u256b result = {lo, mid, hi};
	
	return result;
}
*/

void PRG(AES_KEY *key, block input, block* output1, block* output2, int* bit1, int* bit2){
	input = dpf_set_lsb_zero(input);

	block stash[2];
	stash[0] = input;
	stash[1] = dpf_reverse_lsb(input);

	AES_ecb_encrypt_blks(stash, 2, key);

	stash[0] = dpf_xor(stash[0], input);
	stash[1] = dpf_xor(stash[1], input);
	stash[1] = dpf_reverse_lsb(stash[1]);

	*bit1 = dpf_lsb(stash[0]);
	*bit2 = dpf_lsb(stash[1]);

	*output1 = dpf_set_lsb_zero(stash[0]);
	*output2 = dpf_set_lsb_zero(stash[1]);
}

static int getbit(uint128_t x, int n, int b){
	return ((uint128_t)(x) >> (n - b)) & 1;
}

void GEN(AES_KEY *key, uint128_t alpha, int n, unsigned char** k0, unsigned char **k1){
    
    //alpha is the value where it's 1 and n is the number of bits of security
    //alpha needs to be able to take any value between 0 and 2^128-1
    //not clear why 7 is being removed to get maxlayer. Hopefully some optimization
    
	int maxlayer = n - 7;
	//int maxlayer = n;

	block s[maxlayer + 1][2];
	int t[maxlayer + 1 ][2];
	block sCW[maxlayer];
	int tCW[maxlayer][2];

	s[0][0] = dpf_random_block();
	s[0][1] = dpf_random_block();
	t[0][0] = dpf_lsb(s[0][0]);
	t[0][1] = t[0][0] ^ 1;
	s[0][0] = dpf_set_lsb_zero(s[0][0]);
	s[0][1] = dpf_set_lsb_zero(s[0][1]);

	int i;
	block s0[2], s1[2]; // 0=L,1=R
	#define LEFT 0
	#define RIGHT 1
	int t0[2], t1[2];
	for(i = 1; i<= maxlayer; i++){
		PRG(key, s[i-1][0], &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT]);
		PRG(key, s[i-1][1], &s1[LEFT], &s1[RIGHT], &t1[LEFT], &t1[RIGHT]);

		int keep, lose;
		int alphabit = getbit(alpha, n, i);
		if(alphabit == 0){
			keep = LEFT;
			lose = RIGHT;
		}else{
			keep = RIGHT;
			lose = LEFT;
		}

		sCW[i-1] = dpf_xor(s0[lose], s1[lose]);

		tCW[i-1][LEFT] = t0[LEFT] ^ t1[LEFT] ^ alphabit ^ 1;
		tCW[i-1][RIGHT] = t0[RIGHT] ^ t1[RIGHT] ^ alphabit;

		if(t[i-1][0] == 1){
			s[i][0] = dpf_xor(s0[keep], sCW[i-1]);
			t[i][0] = t0[keep] ^ tCW[i-1][keep];
		}else{
			s[i][0] = s0[keep];
			t[i][0] = t0[keep];
		}

		if(t[i-1][1] == 1){
			s[i][1] = dpf_xor(s1[keep], sCW[i-1]);
			t[i][1] = t1[keep] ^ tCW[i-1][keep];
		}else{
			s[i][1] = s1[keep];
			t[i][1] = t1[keep];
		}
	}

	block finalblock;
	finalblock = dpf_zero_block();
	finalblock = dpf_reverse_lsb(finalblock);

	char shift = (alpha) & 127;
	if(shift & 64){
		finalblock = dpf_left_shirt(finalblock, 64);
	}
	if(shift & 32){
		finalblock = dpf_left_shirt(finalblock, 32);
	}
	if(shift & 16){
		finalblock = dpf_left_shirt(finalblock, 16);
	}
	if(shift & 8){
		finalblock = dpf_left_shirt(finalblock, 8);
	}
	if(shift & 4){
		finalblock = dpf_left_shirt(finalblock, 4);
	}
	if(shift & 2){
		finalblock = dpf_left_shirt(finalblock, 2);
	}
	if(shift & 1){
		finalblock = dpf_left_shirt(finalblock, 1);
	}
	dpf_cb(finalblock);
	finalblock = dpf_reverse_lsb(finalblock);

	finalblock = dpf_xor(finalblock, s[maxlayer][0]);
	finalblock = dpf_xor(finalblock, s[maxlayer][1]);

	unsigned char *buff0;
	unsigned char *buff1;
	buff0 = (unsigned char*) malloc(1 + 16 + 1 + 18 * maxlayer + 16);
	buff1 = (unsigned char*) malloc(1 + 16 + 1 + 18 * maxlayer + 16);

	if(buff0 == NULL || buff1 == NULL){
		printf("Memory allocation failed\n");
		exit(1);
	}

	buff0[0] = n;
	memcpy(&buff0[1], &s[0][0], 16);
	buff0[17] = t[0][0];
	for(i = 1; i <= maxlayer; i++){
		memcpy(&buff0[18 * i], &sCW[i-1], 16);
		buff0[18 * i + 16] = tCW[i-1][0];
		buff0[18 * i + 17] = tCW[i-1][1]; 
	}
	memcpy(&buff0[18 * maxlayer + 18], &finalblock, 16); 

	buff1[0] = n;
	memcpy(&buff1[18], &buff0[18], 18 * (maxlayer));
	memcpy(&buff1[1], &s[0][1], 16);
	buff1[17] = t[0][1];
	memcpy(&buff1[18 * maxlayer + 18], &finalblock, 16);

	*k0 = buff0;
	*k1 = buff1;
} 

block EVAL(AES_KEY *key, unsigned char* k, uint128_t x){
	int n = k[0];
	int maxlayer = n - 7;

	block s[maxlayer + 1];
	int t[maxlayer + 1];
	block sCW[maxlayer];
	int tCW[maxlayer][2];
	block finalblock;

	memcpy(&s[0], &k[1], 16);
	t[0] = k[17];

	int i;
	for(i = 1; i <= maxlayer; i++){
		memcpy(&sCW[i-1], &k[18 * i], 16);
		tCW[i-1][0] = k[18 * i + 16];
		tCW[i-1][1] = k[18 * i + 17];
	}

	memcpy(&finalblock, &k[18 * (maxlayer + 1)], 16);

	block sL, sR;
	int tL, tR;
	for(i = 1; i <= maxlayer; i++){
		PRG(key, s[i - 1], &sL, &sR, &tL, &tR); 

		if(t[i-1] == 1){
			sL = dpf_xor(sL, sCW[i-1]);
			sR = dpf_xor(sR, sCW[i-1]);
			tL = tL ^ tCW[i-1][0];
			tR = tR ^ tCW[i-1][1];	
		}

		int xbit = getbit(x, n, i);
		if(xbit == 0){
			s[i] = sL;
			t[i] = tL;
		}else{
			s[i] = sR;
			t[i] = tR;
		}
	}

	block res;
	res = s[maxlayer];
	if(t[maxlayer] == 1){
		res = dpf_reverse_lsb(res);
	}

	if(t[maxlayer] == 1){
		res = dpf_xor(res, finalblock);
	}

	return res;
}


//helper function to get the result as a 1/0 int
uint8_t interpret_result(block val){
    return ((uint8_t*)(&val))[7] >> 7;
}

//use the correllated randomness so that servers and user pick same randomness
//untested function
//void PRF(AES_KEY *key, block input, block* output){
void PRF(AES_KEY *key, block seed, int layer, int count, block* output){

    block input = seed;
    
    //xor count with 32 bits of input and layer with next 32 bits. 
    //count = -1 is for determining whether to swap or not when shuffling halves
    // if output mod 2 == 1, then user/servers will swap
    int* temp; //= malloc(sizeof(int));
    temp = (int*)&input;
    temp[0] = temp[0] ^ count;
    temp[1] = temp[1] ^ layer;

	block stash = input;

	AES_ecb_encrypt_blks(&stash, 1, key);

	stash = dpf_xor(stash, input);

	*output = stash;
    free(temp);
}

//to generate a shared randomness to use as input to prf with counter
int getSeed(block* seed){
    return RAND_bytes(seed, 16);
}

//client check inputs
//void clientVerify(AES_KEY *key, block seed, uint128_t alpha, int dbLayers, int dbSize, uint8_t* bits, block* nonZeroVectors){
void clientVerify(AES_KEY *key, block seed, uint128_t alpha, int dbLayers, uint8_t* bits, block* nonZeroVectors){
    
    block whenToSwap;
    uint128_t newAlphaIndex = alpha;
    
    //set bits vector to all zeros
    memset(bits, 0, dbLayers);
    
    for(int i = 0; i < dbLayers; i++){
        
        //set newAlphaIndex
        //if the alpha number is bigger than than the corresponding power of 2, the alpha index will have been moved up
        if(newAlphaIndex > (1<<(dblayers - i))){
            newAlphaIndex -= 1<<(dblayers - i);
            bits[i] = 1;
        }
        
        //check if the halves will be swapped and set the entry of bits
        PRF(key, seed, i, -1, whenToSwap);
        bits[i] = bits[i] ^ ((uint128_t)whenToSwap % 2);
        
        
        //check the mask value for newAlphaIndex and set entry of nonZeroVectors
        PRF(key, seed, i, newAlphaIndex, &nonZeroVectors[i]);        
    }
    
}

//TODO: server check inputs
void serverVerify(AES_KEY *key, block seed, int dbLayers, int dbSize, block* vectors, block* outVectors){
    
    //outVectors should be of length 2*dbLayers since there are 2 sums per layer

    //don't modify vectors -- it should be treated as read-only, so make a copy
    block* vectorsWorkSpace = malloc((1 << (dbLayers-1))*sizeof(block));
    memset(vectorsWorkSpace, 0, (1 << (dbLayers-1))*sizeof(block));
    
    //will use vectors as the input the first round to avoid needing to copy it,
    //but subsequent rounds will read from vectorsWorkSpace
    block* vectorPointer = vectors;
    
    block whenToSwap, leftSum, rightSum;
    int newDbSize = dbSize;
    

    for(int i = 0; i < dbLayers; i++){
        
        //multiply each element by a ``random'' value and xor into the appropriate sum
        //add together left and right halves for next iteration
        for(int j = 0; j < newDbSize; j++){            
            if(j > (1<<(dblayers - i))){ //if j is in right half
                rightSum = dpf_xor(rightSum, );
            }
            else{ // j is in left half
                
            }
            
            //vectorsWorkSpace[j] = vectorPointer[j]  ;
        }
        vectorPointer = vectorsWorkSpace;
        //adjust newDbSize for next round
        newDbSize = 1 << (dbLayers - (i+1));
                
        //check if the halves will be swapped and place the sums in the appropriate spots
        PRF(key, seed, i, -1, whenToSwap);
        if((uint128_t)whenToSwap % 2 == 0){
            memcpy(&outVectors[2*j], leftSum, 16);
            memcpy(&outVectors[2*j+1], rightSum, 16);
        }
        else{
            memcpy(&outVectors[2*j], rightSum, 16);
            memcpy(&outVectors[2*j+1], leftSum, 16);
        }
    }
    
}

//auditor functionality
int auditorVerify(int dbLayers, uint8_t* bits, block* nonZeroVectors, block* outVectorsA, block* outVectorsB){
    
    int pass = 1; //set this to 0 if any check fails
    uint128_t zero = 0;
    
    for(int i = 0; i < dbLayers; i++){
        
        //merge the output vectors to get the values
        //putting the merged values into outVectorsA
        outVectorsA[2*i] = dpf_xor(outVectorsA[2*i], outVectorsB[2*i]);
        outVectorsA[2*i+1] = dpf_xor(outVectorsA[2*i+1], outVectorsB[2*i+1]);
        
        //check that the appropriate side is 0
        //check that the non-zero side matches expected nonZero value
        if(memcmp(outVectorsA[2*i+(1-bits[i])], &zero, 16) != 0 ||
            memcmp(outVectorsA[2*i+bits[i]], &nonZeroVectors[i], 16) != 0) {
            pass = 0;
        }
        
    }
    
    return pass;
}

int main(){
    
    //pick 2 64-bit values as a fixed aes key
    //and use those values to key the aes we will be using as a PRG

	long long userkey1 = 597349; long long userkey2 = 121379; 
	block userkey = dpf_make_block(userkey1, userkey2);

	dpf_seed(NULL);

	AES_KEY key;
	AES_set_encrypt_key(userkey, &key);
    
    
    //generate DPF keys for a particular query
	unsigned char *k0;
	unsigned char *k1;

    //can only test with smaller constants because
    //gcc does not support 128 bit constants
	GEN(&key, 26943, 128, &k0, &k1);
	
    //evaluate dpf
	block res1;
	block res2;
    
	res1 = EVAL(&key, k0, 0);
	res2 = EVAL(&key, k1, 0);
	dpf_cb(res1);
	dpf_cb(res2);
    block out = dpf_xor(res1, res2);
    printf("result is value %d\n", interpret_result(out));
	//dpf_cb(dpf_xor(res1, res2));

	res1 = EVAL(&key, k0, 26943);
	res2 = EVAL(&key, k1, 26943);
	dpf_cb(res1);
	dpf_cb(res2);
    out = dpf_xor(res1, res2);
    printf("result is value %d\n", interpret_result(out));
	//dpf_cb(dpf_xor(res1, res2));

	return 0;
}
