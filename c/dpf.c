#include "dpf.h"
#include <openssl/rand.h>
#include <omp.h>
#include <time.h>



uint128_t dpf_reverse_lsb(uint128_t input){
    uint128_t xor = 1;
	return input ^ xor;
}

uint128_t dpf_lsb(uint128_t input){
    return input & 1;
}

uint128_t dpf_set_lsb_zero(uint128_t input){
    int lsb = input & 1;

	if(lsb == 1){
		return dpf_reverse_lsb(input);	
	}else{
		return input;
	}
}

void _output_bit_to_bit(uint128_t input){
    for(int i = 0; i < 64; i++)
    {
        if( (1ll << i) & input)
            printf("1");
	else
	    printf("0");
    }
}

void print_block(uint128_t input) {
    uint64_t *val = (uint64_t *) &input;

	//printf("%016lx%016lx\n", val[0], val[1]);
	_output_bit_to_bit(val[0]);
	_output_bit_to_bit(val[1]);
	printf("\n");
}

uint128_t addModP(uint128_t in1, uint128_t in2){
    uint128_t out = in1 + in2;
    //if we wrapped around, add in the MODP
    if(out + MODP < in1 || out > 0-MODP){
        out += MODP;
        //printf("addModP wrapped\n");
    }
    return out;
}

uint128_t subModP(uint128_t in1, uint128_t in2){
    uint128_t out = in1 - in2;
    //if we wrapped around, subtract the MODP
    if(in2 > in1){
        out -= MODP;
        //printf("subModP wrapped\n");

    }
    //straight-line version?
    //out -= (in2 > in1) * MODP;
    return out;
}

//performance for this is really bad
//but it gets _much_ better when compiled with -O2
uint128_t multModP(uint128_t in1, uint128_t in2){
    uint128_t out = 0;
    uint128_t in1high = in1 >> 64;
    uint128_t in2high = in2 >> 64;
    uint128_t in1low = in1 & (uint128_t)0xffffffffffffffff;
    uint128_t in2low = in2 & (uint128_t)0xffffffffffffffff;
    
    //printf("\n");
    //print_block(in1high); printf("\n");
    //print_block(in2high); printf("\n");
    //print_block(in1low); printf("\n");
    //print_block(in2low); printf("\n");
    //printf("\n");

    uint128_t outlow = in1low * in2low;
    if(outlow + MODP < in1low || outlow + MODP < in2low|| outlow > 0-MODP) {
        outlow += MODP; 
        //printf("mult wrap\n");
    }
    
    //print_block(outlow);
        
    uint128_t outhigh = in1high * in2high;
    uint128_t outmid1 = in1high*in2low;
    uint128_t outmid2 = in2high*in1low;
    
    //print_block(outhigh);
    //print_block(outmid1);
    //print_block(outmid2);
        
    //the low part gets the low order bits of the mids
    uint128_t outlow1 = addModP(outmid1 << 64, outmid2 << 64);
    
    //uint128_t outlow1 = ((outmid1 & (uint128_t)0xffffffffffffffff) +  (outmid2 & (uint128_t)0xffffffffffffffff)) << 64;
    //if(outlow1 + MODP < ((outmid1 & (uint128_t)0xffffffffffffffff) << 64)) outlow1 += MODP;
        
    //print_block(outlow1);
    
    out = addModP(outlow, outlow1);

    //print_block(out);
    
    //multiply in the wrap for as many times as we wrapped
    uint128_t lowWraps = ((outmid1 >> 64) + (outmid2 >> 64)) * MODP;
    out = addModP(out, lowWraps);
    
    //print_block(lowWraps);
    
    //now we need to account for wraps caused by outhigh
    uint128_t outhighlow = (outhigh & (uint128_t)0xffffffffffffffff) * MODP;
    uint128_t outhighhigh = (outhigh >> 64) * MODP;
    uint128_t outhighhighlow = outhighhigh << 64;
    uint128_t outhighhighhigh = (outhighhigh >> 64) * MODP;
    
    //print_block(outhighlow);
    //print_block(outhighhigh);
    //print_block(outhighhighlow);
    //print_block(outhighhighhigh);
    
    out = addModP(out, addModP(outhighlow, addModP(outhighhighlow, outhighhighhigh)));
    
    //print_block(out);

    return out;
}


uint128_t getRandomBlock(){
    static uint8_t* randKey = NULL;//(uint8_t*) malloc(16);
    static EVP_CIPHER_CTX* randCtx;
    static uint128_t counter = 0;
    
    int len = 0;
    uint128_t output = 0;
    if(!randKey){
        randKey = (uint8_t*) malloc(16);
        if(!(randCtx = EVP_CIPHER_CTX_new())) 
            printf("errors occured in creating context\n");
        if(!RAND_bytes(randKey, 16)){
            printf("failed to seed randomness\n");
        }
        if(1 != EVP_EncryptInit_ex(randCtx, EVP_aes_128_ecb(), NULL, randKey, NULL))
            printf("errors occured in randomness init\n");
        EVP_CIPHER_CTX_set_padding(randCtx, 0);
    }
    
    if(1 != EVP_EncryptUpdate(randCtx, (uint8_t*)&output, &len, (uint8_t*)&counter, 16))
        printf("errors occured in generating randomness\n");
    counter++;
    return output;
}

//this is the PRG used for the DPF 
void dpfPRG(EVP_CIPHER_CTX *ctx, uint128_t input, uint128_t* output1, uint128_t* output2, int* bit1, int* bit2){
    
	input = dpf_set_lsb_zero(input);

    int len = 0;
	uint128_t stashin[2];
	stashin[0] = input;
	stashin[1] = dpf_reverse_lsb(input);
	uint128_t stash[2];

    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if(1 != EVP_EncryptUpdate(ctx, (uint8_t*)stash, &len, (uint8_t*)stashin, 32))
        printf("errors occured in encrypt\n");
    //no need to do this since we're working with exact multiples of the block size
    //if(1 != EVP_EncryptFinal_ex(ctx, stash + len, &len)) 
    //    printf("errors occured in final\n");
    
	stash[0] = stash[0] ^ input;
	stash[1] = stash[1] ^ input;
	stash[1] = dpf_reverse_lsb(stash[1]);

	*bit1 = dpf_lsb(stash[0]);
	*bit2 = dpf_lsb(stash[1]);

	*output1 = dpf_set_lsb_zero(stash[0]);
	*output2 = dpf_set_lsb_zero(stash[1]);
}

static int getbit(uint128_t x, int n, int b){
	return ((uint128_t)(x) >> (n - b)) & 1;
}

void genDPF(EVP_CIPHER_CTX *ctx, int domainSize, uint128_t index, int dataSize, uint8_t* data, unsigned char** k0, unsigned char **k1){
    int maxLayer = domainSize;
    
    uint128_t s[maxLayer + 1][2];
	int t[maxLayer + 1 ][2];
	uint128_t sCW[maxLayer];
	int tCW[maxLayer][2];
    
    s[0][0] = getRandomBlock();
	s[0][1] = getRandomBlock();
	t[0][0] = 0;
	t[0][1] = 1;
    
    uint128_t s0[2], s1[2]; // 0=L,1=R
    int t0[2], t1[2];
	#define LEFT 0
	#define RIGHT 1
	for(int i = 1; i <= maxLayer; i++){
        dpfPRG(ctx, s[i-1][0], &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT]);
		dpfPRG(ctx, s[i-1][1], &s1[LEFT], &s1[RIGHT], &t1[LEFT], &t1[RIGHT]);
        
        int keep, lose;
		int indexBit = getbit(index, domainSize, i);
        if(indexBit == 0){
			keep = LEFT;
			lose = RIGHT;
		}else{
			keep = RIGHT;
			lose = LEFT;
		}
            
		
        sCW[i-1] = s0[lose] ^ s1[lose];

		tCW[i-1][LEFT] = t0[LEFT] ^ t1[LEFT] ^ indexBit ^ 1;
		tCW[i-1][RIGHT] = t0[RIGHT] ^ t1[RIGHT] ^ indexBit;
        
		if(t[i-1][0] == 1){
			s[i][0] = s0[keep] ^ sCW[i-1];
			t[i][0] = t0[keep] ^ tCW[i-1][keep];
		}else{
			s[i][0] = s0[keep];
			t[i][0] = t0[keep];
		}

		if(t[i-1][1] == 1){
			s[i][1] = s1[keep] ^ sCW[i-1];
			t[i][1] = t1[keep] ^ tCW[i-1][keep];
		}else{
			s[i][1] = s1[keep];
			t[i][1] = t1[keep];
		}
		
    }
    
	unsigned char *buff0;
	unsigned char *buff1;
	buff0 = (unsigned char*) malloc(1 + 16 + 1 + 18 * maxLayer + dataSize);
	buff1 = (unsigned char*) malloc(1 + 16 + 1 + 18 * maxLayer + dataSize);
    
    //take data, xor it with dataSize bits generated from s_0^n and another dataSize bits generated from s_1^n
    //use a counter mode encryption of 0 with each seed as key to get prg output
    uint8_t *lastCW = (uint8_t*) malloc(dataSize);
    uint8_t *convert0 = (uint8_t*) malloc(dataSize+16);
    uint8_t *convert1 = (uint8_t*) malloc(dataSize+16);
    uint8_t *zeros = (uint8_t*) malloc(dataSize+16);
    memset(zeros, 0, dataSize+16);
    
    memcpy(lastCW, data, dataSize);
    
    int len = 0;
    //generate dataSize length prg outputs from the seeds

    EVP_CIPHER_CTX *seedCtx0;
    EVP_CIPHER_CTX *seedCtx1;

    if(!(seedCtx0 = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    if(!(seedCtx1 = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    if(1 != EVP_EncryptInit_ex(seedCtx0, EVP_aes_128_ctr(), NULL, (uint8_t*)&s[maxLayer][0], NULL))
        printf("errors occured in init of dpf gen\n");
    if(1 != EVP_EncryptInit_ex(seedCtx1, EVP_aes_128_ctr(), NULL, (uint8_t*)&s[maxLayer][1], NULL))
        printf("errors occured in init of dpf gen\n");
    if(1 != EVP_EncryptUpdate(seedCtx0, convert0, &len, zeros, dataSize))
        printf("errors occured in encrypt\n"); 
    if(1 != EVP_EncryptUpdate(seedCtx1, convert1, &len, zeros, dataSize))
        printf("errors occured in encrypt\n"); 

    for(int i = 0; i < dataSize; i++){
        lastCW[i] = lastCW[i] ^ ((uint8_t*)convert0)[i] ^ ((uint8_t*)convert1)[i];
    }

	if(buff0 == NULL || buff1 == NULL){
		printf("Memory allocation failed\n");
		exit(1);
	}

	buff0[0] = domainSize;
	memcpy(&buff0[1], &s[0][0], 16);
	buff0[17] = t[0][0];
	for(int i = 1; i <= maxLayer; i++){
		memcpy(&buff0[18 * i], &sCW[i-1], 16);
		buff0[18 * i + 16] = tCW[i-1][0];
		buff0[18 * i + 17] = tCW[i-1][1]; 
	}
	memcpy(&buff0[18 * maxLayer + 18], lastCW, dataSize);

	buff1[0] = domainSize;
	memcpy(&buff1[18], &buff0[18], 18 * (maxLayer));
	memcpy(&buff1[1], &s[0][1], 16);
	buff1[17] = t[0][1];
	memcpy(&buff1[18 * maxLayer + 18], lastCW, dataSize);

	*k0 = buff0;
	*k1 = buff1;
    
    free(lastCW);
    free(convert0);
    free(convert1);
    free(zeros);
    EVP_CIPHER_CTX_free(seedCtx0);
    EVP_CIPHER_CTX_free(seedCtx1);
}

uint128_t evalDPF(EVP_CIPHER_CTX *ctx, unsigned char* k, uint128_t x, int dataSize, uint8_t* dataShare){
   //NOTE: if dataSize is not a multiple of 16, the size of dataShare should be
   //the next multiple of 16 after dataSize or else there is a memory bug.
   //Thanks to Emma Dauterman for pointing this out.

    //dataShare is of size dataSize
    
 	int n = k[0];
	int maxLayer = n;

	uint128_t s[maxLayer + 1];
	int t[maxLayer + 1];
	uint128_t sCW[maxLayer];
	int tCW[maxLayer][2];

	memcpy(&s[0], &k[1], 16);
	t[0] = k[17];

	for(int i = 1; i <= maxLayer; i++){
		memcpy(&sCW[i-1], &k[18 * i], 16);
		tCW[i-1][0] = k[18 * i + 16];
		tCW[i-1][1] = k[18 * i + 17];
	}

	uint128_t sL, sR;
	int tL, tR;
	for(int i = 1; i <= maxLayer; i++){
		dpfPRG(ctx, s[i - 1], &sL, &sR, &tL, &tR); 

		if(t[i-1] == 1){
			sL = sL ^ sCW[i-1];
			sR = sR ^ sCW[i-1];
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
    
    //get the data share out
    int len = 0;
    uint8_t *zeros = (uint8_t*) malloc(dataSize+16);
    memset(zeros, 0, dataSize+16);
    //use a counter mode encryption of 0 with each seed as key to get prg output
    //printf("here\n");
    
    EVP_CIPHER_CTX *seedCtx;
    if(!(seedCtx = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    if(1 != EVP_EncryptInit_ex(seedCtx, EVP_aes_128_ctr(), NULL, (uint8_t*)&s[maxLayer], NULL))
        printf("errors occured in init of dpf eval\n");
    if(1 != EVP_EncryptUpdate(seedCtx, dataShare, &len, zeros, ((dataSize-1)|15)+1))
        printf("errors occured in encrypt\n");
    
    for(int i = 0; i < dataSize; i++){
        if(t[maxLayer] == 1){
            //xor in correction word
            dataShare[i] = dataShare[i] ^ k[18*n+18+i];
            
            //printf("xoring stuff in at index %d\n", i);
        }
                //printf("%x\n", (*dataShare)[i]);

    }    
    
    free(zeros);
    EVP_CIPHER_CTX_free(seedCtx);
    
    //print_block(s[maxLayer]);
    //printf("%x\n", t[maxLayer]);

    //use the last seed for dpf checking
	return s[maxLayer];    
}

//use the correllated randomness so that servers and user pick same randomness
//this is the PRF for dpf checking
void PRF(EVP_CIPHER_CTX *ctx, uint128_t seed, int layer, int count, uint128_t* output){
    int len = 0;
    uint128_t input = seed;
    int tries = 0;
    
    //xor count with 32 bits of input and layer with next 32 bits. 
    //count = -1 is for determining whether to swap or not when shuffling halves
    // if output mod 2 == 1, then user/servers will swap
    int* temp; 
    temp = (int*)&input;
    temp[0] = temp[0] ^ count;
    temp[1] = temp[1] ^ layer;
    uint128_t stash = 0;
    
    do{
        temp[2] = temp[2] ^ tries;
        uint128_t stashin = input;

        if(1 != EVP_EncryptUpdate(ctx, (uint8_t*)&stash, &len, (uint8_t*)&stashin, 16))
            printf("errors occured in encrypt\n");

        stash = stash ^ input;
        tries++;
        
        //drop blocks that are not in Z_p when count is not -1
    } while(count != -1 && stash + MODP < stash);

	*output = stash;
}

void clientGenProof(EVP_CIPHER_CTX *ctx, uint128_t seed, int index, uint128_t aShare, uint128_t bShare, uint8_t* outputsAIn, uint8_t* outputsBIn){

    uint128_t *outputsA = (uint128_t*) outputsAIn;
    uint128_t *outputsB = (uint128_t*) outputsBIn;

	//outputs will hold the following items in the following order
	//this comes out to 10 values
	//outputs for server A of the first multiplication proof (cc)	
	//f0amult1 (index) 0
	//g0amult1 1
	//h0amult1 2
	//h1amult1 3
	//h2amult1 4
	//outputs for server A of the second multiplication proof (mC)
	//f0amult2 5
	//g0amult2 6
	//h0amult2 7
	//h1amult2 8
	//h2amult2 9
	//all the same things needed for server B as well

	//client generates a bunch of randomness and assigns most of the outputs 
	//whp these are all in the field we're using
	for(int i = 0; i < 10; i++){
		outputsB[i] = getRandomBlock();	
	}
	outputsA[0] = getRandomBlock(); 
	outputsA[1] = getRandomBlock();
	outputsA[5] = getRandomBlock();
	outputsA[6] = getRandomBlock();

	//find f0,g0 based on randomness generated above
	uint128_t f0mult1 = subModP(outputsA[0], outputsB[0]);
	uint128_t g0mult1 = subModP(outputsA[1], outputsB[1]);
	uint128_t f0mult2 = subModP(outputsA[5], outputsB[5]);
	uint128_t g0mult2 = subModP(outputsA[6], outputsB[6]);

	//find f1,g1 (shortcut since client knows non-zero index)
	uint128_t rvalue;
	PRF(ctx, seed, 0, index, &rvalue);
	uint128_t f1mult1 = multModP(subModP(aShare, bShare), rvalue);
	uint128_t g1mult1 = f1mult1; 
	uint128_t f1mult2 = subModP(aShare, bShare); 
	uint128_t g1mult2 = f1mult1;

	//printf("value for m on client side"); print_block(f1mult2);
	//printf("value for c on client side");print_block(f1mult1);

	//calculate h0,h1 values by multiplying
	uint128_t h0mult1 = multModP(f0mult1,g0mult1);
	uint128_t h0mult2 = multModP(f0mult2,g0mult2);
	uint128_t h1mult1 = multModP(f1mult1,g1mult1);
	uint128_t h1mult2 = multModP(f1mult2,g1mult2);

	//put shares of h0,h1 in output
	outputsA[2] = addModP(h0mult1, outputsB[2]);
	outputsA[7] = addModP(h0mult2, outputsB[7]);
	outputsA[3] = addModP(h1mult1, outputsB[3]);
	outputsA[8] = addModP(h1mult2, outputsB[8]);

	//find f2,g2
	uint128_t two = 2;
	uint128_t f2mult1 = evalLinearR(two, f0mult1, f1mult1);
	uint128_t g2mult1 = evalLinearR(two, g0mult1, g1mult1);
	uint128_t f2mult2 = evalLinearR(two, f0mult2, f1mult2);
	uint128_t g2mult2 = evalLinearR(two, g0mult2, g1mult2);

	//calculate h2 values by multiplying
	uint128_t h2mult1 = multModP(f2mult1,g2mult1);
	uint128_t h2mult2 = multModP(f2mult2,g2mult2);

	//put shares of h2 in output
	outputsA[4] = addModP(h2mult1, outputsB[4]);
	outputsA[9] = addModP(h2mult2, outputsB[9]);

	/*
	//for testing, trying to produce output of proof

	//compute f(r), g(r)
	uint128_t frmult1 = evalLinearR(10, f0mult1, f1mult1);
	uint128_t grmult1 = evalLinearR(10, g0mult1, g1mult1);
	uint128_t frmult2 = evalLinearR(10, f0mult2, f1mult2);
	uint128_t grmult2 = evalLinearR(10, g0mult2, g1mult2);

	//compute h(r)
	uint128_t hrmult1 = evalQuadraticR(10, h0mult1, h1mult1, h2mult1);
	uint128_t hrmult2 = evalQuadraticR(10, h0mult2, h1mult2, h2mult2);
	
	printf("values: ");
	printf("\nf1: ");print_block(frmult1);
	printf("\ng1: ");print_block(grmult1);
	printf("\nh1: ");print_block(hrmult1);
	printf("\nf2: ");print_block(frmult2);
	printf("\ng2: ");print_block(grmult2);
	printf("\nh2: ");print_block(hrmult2);
	*/
}

void serverSetupProof(EVP_CIPHER_CTX *ctx, uint8_t *seedIn, int dbSize, uint8_t* vectorsIn, uint8_t* mIn, uint8_t* cIn){

	uint128_t* m = (uint128_t*) mIn;
	uint128_t* c = (uint128_t*) cIn;
	uint128_t* vectors = (uint128_t*) vectorsIn;
	uint128_t seed;
	memcpy(&seed, seedIn, 16);

	uint128_t prfOutput;
	uint128_t workingM = 0;
	uint128_t workingC = 0;

	for(int i = 0; i < dbSize; i++){
       		PRF(ctx, seed, 0, i, &prfOutput);    
		workingM = addModP(workingM, vectors[i]);
		workingC = addModP(workingC, multModP(vectors[i], prfOutput));
	}

	memcpy(m, &workingM, 16);
	memcpy(c, &workingC, 16);
}

void serverComputeQuery(EVP_CIPHER_CTX *ctx, uint8_t *seedIn, uint8_t* mIn, uint8_t* cIn, uint8_t* proofIn, uint8_t* ansIn){
	uint128_t* m = (uint128_t*) mIn;
	uint128_t* c = (uint128_t*) cIn;
	uint128_t* proof = (uint128_t*) proofIn;
	uint128_t* ans = (uint128_t*) ansIn;
	uint128_t seed;
	memcpy(&seed, seedIn, 16);

	//including this just for readability
	uint128_t f0mult1 = proof[0];
	uint128_t g0mult1 = proof[1];
	uint128_t h0mult1 = proof[2];
	uint128_t h1mult1 = proof[3];
	uint128_t h2mult1 = proof[4];
	uint128_t f0mult2 = proof[5];
	uint128_t g0mult2 = proof[6];
	uint128_t h0mult2 = proof[7];
	uint128_t h1mult2 = proof[8];
	uint128_t h2mult2 = proof[9];

	//generate a random point r from seed
	uint128_t r1, r2; 
       	PRF(ctx, seed, 1, 0, &r1);
       	PRF(ctx, seed, 2, 0, &r2);

	//for testing
	//r1 = 10;
	//r2 = 10;
	
	//compute f(r), g(r)
	uint128_t frmult1 = evalLinearR(r1, f0mult1, *c);
	uint128_t grmult1 = evalLinearR(r1, g0mult1, *c);
	uint128_t frmult2 = evalLinearR(r2, f0mult2, *m);
	uint128_t grmult2 = evalLinearR(r2, g0mult2, *c);

	//compute h(r)
	uint128_t hrmult1 = evalQuadraticR(r1, h0mult1, h1mult1, h2mult1);
	uint128_t hrmult2 = evalQuadraticR(r2, h0mult2, h1mult2, h2mult2);

	//set the appropriate elements of ans (6 elements)
	ans[0] = frmult1;
	ans[1] = grmult1;
	ans[2] = hrmult1;
	ans[3] = frmult2;
	ans[4] = grmult2;
	ans[5] = hrmult2;
}

int serverVerifyProof(uint8_t* ans1In, uint8_t* ans2In){
	uint128_t* ans1 = (uint128_t*) ans1In;
	uint128_t* ans2 = (uint128_t*) ans2In;
	
	uint128_t f1 = subModP(ans1[0], ans2[0]);
	uint128_t g1 = subModP(ans1[1], ans2[1]);
	uint128_t h1 = subModP(ans1[2], ans2[2]);
	uint128_t f2 = subModP(ans1[3], ans2[3]);
	uint128_t g2 = subModP(ans1[4], ans2[4]);
	uint128_t h2 = subModP(ans1[5], ans2[5]);

	uint128_t prod1 = multModP(f1, g1);
	uint128_t prod2 = multModP(f2, g2);
	
	/*
	printf("recovered values: ");
	printf("\nf1: ");print_block(f1);
	printf("\ng1: ");print_block(g1);
	printf("\nh1: ");print_block(h1);
	printf("\nf2: ");print_block(f2);
	printf("\ng2: ");print_block(g2);
	printf("\nh2: ");print_block(h2);

	printf("\n\nprod1: ");print_block(prod1);
	printf("\nprod2: ");print_block(prod2);
	*/

	int pass = (memcmp(&prod1, &h1, 16) == 0) && (memcmp(&prod2, &h2, 16) == 0);
	return pass;
}

uint128_t evalLinearR(uint128_t r, uint128_t p0, uint128_t p1){
	uint128_t slope = subModP(p1, p0);
	uint128_t pr = addModP(multModP(slope, r), p0);
	return pr;
}

uint128_t evalQuadraticR(uint128_t r, uint128_t h0, uint128_t h1, uint128_t h2){
	// h(r) = (1/2)(r-1)(r-2)h0 - r(r-2)h1 + (1/2)r(r-1)h2

	//(1/2)(r-1)(r-2)h0
	uint128_t t0 = 0;
	if(r%2 == 0) {
		t0 = multModP(h0, multModP(r-1, (r-2)/2));
	} 
	else{
		t0 = multModP(h0, multModP((r-1)/2, r-2));
	} 

	//r(r-2)h1
	uint128_t t1 = multModP(multModP(r, r-2), h1);
	
	//(1/2)r(r-1)h2
	uint128_t t2 = 0;
	if(r%2 == 0) {
		t2 = multModP(h2, multModP(r-1, r/2));
	} 
	else{
		t2 = multModP(h2, multModP((r-1)/2, r));
	}
	
	//final sum
	uint128_t ret = addModP(subModP(t0, t1), t2);
}


//client check inputs
void clientVerify(EVP_CIPHER_CTX *ctx, uint128_t seed, int index, uint128_t aShare, uint128_t bShare, int dbLayers, uint8_t* bits, uint8_t* nonZeroVectorsIn){
    
    uint128_t *nonZeroVectors = (uint128_t*) nonZeroVectorsIn;
    
    //note that index is the actual index, not the virtual address, in our application to oblivious key value stores
    //printf("clientVerify\n");
    
    //set bits vector to all zeros
    memset(bits, 0, dbLayers);
    
    //#pragma omp parallel for
    for(int i = 0; i < dbLayers; i++){
        uint128_t whenToSwap;
        int newIndex;
        int oldIndex;

        //set newAlphaIndex
        oldIndex = index % (1<<(dbLayers - i));
        newIndex = index % (1<<(dbLayers - i - 1));

        //if the index has changed, then the nonzero value was in the second half
        if(newIndex != oldIndex){
            bits[i] = 1;
        }
        //printf("bits %d before potential flip: %d\n", i, bits[i]);

        //check if the halves will be swapped and set the entry of bits
        PRF(ctx, seed, i, -1, &whenToSwap);

        bits[i] = bits[i] ^ ((uint128_t)whenToSwap % 2);
        
        uint128_t temp;
        uint128_t temp2;
        //check the mask value and set entry of nonZeroVectors
        PRF(ctx, seed, i, oldIndex, &temp);
        temp2 = multModP(subModP(aShare, bShare), temp);
        memcpy(&nonZeroVectors[i], &temp2, 16);
        
    }
    
}

//server check inputs
void serverVerify(EVP_CIPHER_CTX *ctx, uint8_t *seedIn, int dbLayers, int dbSize, uint8_t* vectorsIn, uint8_t* outVectorsIn){
    //outVectors should be of length 2*dbLayers since there are 2 sums per layer
    //printf("serverVerify\n");
    //don't modify vectors -- it should be treated as read-only, so make a copy
    //uint128_t* vectorsWorkSpace = malloc(dbSize*sizeof(uint128_t));
    //memcpy(vectorsWorkSpace, vectors, dbSize*sizeof(uint128_t));
    
    uint128_t *vectors = (uint128_t*) vectorsIn;
    uint128_t *outVectors = (uint128_t*) outVectorsIn;
    uint128_t seed;
    memcpy(&seed, seedIn, 16);

    
    uint128_t* vectorsWorkSpace = vectors;
    
    uint128_t prfOutput;
    uint128_t leftSum, rightSum;
    int newDbSize = dbSize;
    
    
    //#pragma omp declare reduction(ADDMODP: uint128_t : omp_out += omp_in + (omp_out + omp_in < omp_out || omp_out+omp_in > 0-MODP)*MODP)
    

    for(int i = 0; i < dbLayers; i++){
        
        leftSum = 0;
        rightSum = 0;
        
        //multiply each element by a ``random'' value and add into the appropriate sum
        //#pragma omp parallel for \
        //  default(shared) private(prfOutput) \
        //  reduction(ADDMODP:rightSum,leftSum)
        for(int j = 0; j < newDbSize; j++){
            PRF(ctx, seed, i, j, &prfOutput);         
            if(j >= (1<<(dbLayers - i - 1))){ //if j is in right half
                //rightSum = multModP(vectorsWorkSpace[j], prfOutput);
                //printf("ladeeda%d\n", j);
                //use line commented below when compiling without openmp
                //looks like it actually works with openmp too!
                rightSum = addModP(rightSum, multModP(vectorsWorkSpace[j], prfOutput));
            }
            else{ // j is in left half
                //leftSum = multModP(vectorsWorkSpace[j], prfOutput);
                        //printf("ladeedee%d\n", j);
                //use line commented below when compiling without openmp
                //looks like it actually works with openmp too!
                leftSum = addModP(leftSum, multModP(vectorsWorkSpace[j], prfOutput));
            }
        }
        //printf("\n");
        
        //add together left and right halves for next iteration
        //#pragma omp parallel for
        for(int j = 1<<(dbLayers - i - 1); j < newDbSize; j++){
            vectorsWorkSpace[j - (1<<(dbLayers - i - 1))] =  addModP(vectorsWorkSpace[j - (1<<(dbLayers - i - 1))], vectorsWorkSpace[j]);
        }
        
        //adjust newDbSize for next round
        newDbSize = 1 << (dbLayers - (i+1));
                
        //check if the halves will be swapped and place the sums in the appropriate spots
        PRF(ctx, seed, i, -1, &prfOutput);
        if((uint128_t)prfOutput % 2 == 0){
            memcpy(&outVectors[2*i], &leftSum, 16);
            memcpy(&outVectors[2*i+1], &rightSum, 16);
        }
        else{
            memcpy(&outVectors[2*i], &rightSum, 16);
            memcpy(&outVectors[2*i+1], &leftSum, 16);
        }
        
        //print_block(rightSum);
        //print_block(leftSum);
        
    }
    //free(vectorsWorkSpace);
}

//auditor functionality
int auditorVerify(int dbLayers, uint8_t* bits, uint8_t* nonZeroVectorsIn, uint8_t* outVectorsAIn, uint8_t* outVectorsBIn){
    
    uint128_t *nonZeroVectors = (uint128_t*)nonZeroVectorsIn;
    uint128_t *outVectorsA = (uint128_t*)outVectorsAIn;
    uint128_t *outVectorsB = (uint128_t*)outVectorsBIn;
    
    //printf("auditorVerify\n");
    int pass = 1; //set this to 0 if any check fails
    uint128_t zero = 0;
    
    //#pragma omp parallel for
    for(int i = 0; i < dbLayers; i++){
        uint128_t mergeAB[2];
        
        //merge the output vectors to get the values
        mergeAB[0] = subModP(outVectorsA[2*i], outVectorsB[2*i]);
        mergeAB[1] = subModP(outVectorsA[2*i+1], outVectorsB[2*i+1]);
        
        //printf("%d %lu, %lu, %lu, %lu\n", i, outVectorsA[2*i], outVectorsA[2*i+1], outVectorsB[2*i], outVectorsB[2*i+1]);
        
        //first check that the appropriate side is 0
        //only need to check AB since if it is 0 then so is BA
        //then check that the other side is equal to the corresponding nonZeroVectors entry for one direction
        if( memcmp(&mergeAB[1-bits[i]], &zero, 16) != 0 || (
            memcmp(&mergeAB[bits[i]], &nonZeroVectors[i], 16) != 0
        )){
            printf("fail conditions in round %d: %d %d \n", i, memcmp(&mergeAB[1-bits[i]], &zero, 16), memcmp(&mergeAB[bits[i]], &nonZeroVectors[i], 16));
            printf("auditor expected to see \n");print_block(nonZeroVectors[i]);
            printf("but auditor saw \n");print_block(mergeAB[bits[i]]);
            printf("difference \n"); print_block(nonZeroVectors[i] - mergeAB[bits[i]]);print_block(mergeAB[bits[i]] - nonZeroVectors[i]);

            pass = 0;
        }
        
    }
    
    return pass;
}

void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		printf("digest error\n");

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		printf("digest error\n");

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		printf("digest error\n");

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		printf("digest error\n");

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		printf("digest error\n");

	EVP_MD_CTX_destroy(mdctx);
}

void riposteClientVerify(EVP_CIPHER_CTX *ctx, uint128_t seed, int dbSize, uint128_t *va, uint128_t *vb, uint8_t **digestA, uint8_t **digestB){
    uint128_t *mVectorA = (uint128_t*) malloc(dbSize*16);
    uint128_t *mVectorB = (uint128_t*) malloc(dbSize*16);
    uint128_t prfOutput;

    //#pragma omp parallel for \
    //default(shared) private(prfOutput)
    for(int i = 0; i < dbSize; i++){
        PRF(ctx, seed, 0, i, &prfOutput);
        mVectorA[i] = va[i] ^ prfOutput;
        mVectorB[i] = vb[i] ^ prfOutput;
    }
    
    int len = 0;
    digest_message((uint8_t*)mVectorA, dbSize*16, digestA, &len);
    digest_message((uint8_t*)mVectorB, dbSize*16, digestB, &len);
    free(mVectorA);
    free(mVectorB);
}

void riposteServerVerify(EVP_CIPHER_CTX *ctx, uint128_t seed, int dbSize, uint128_t *vector, uint128_t *mVector, uint128_t *cValue){
    
    PRF(ctx, seed, 1, 0, cValue);
    uint128_t prfOutput;
    
    //#pragma omp parallel for \
    //default(shared) private(prfOutput)
    for(int i = 0; i < dbSize; i++){
        PRF(ctx, seed, 0, i, &prfOutput);
        mVector[i] = vector[i] ^ prfOutput;
    }
}

int riposteAuditorVerify(uint8_t *digestA, uint8_t *digestB, uint8_t *ma, uint8_t *mb, uint128_t ca, uint128_t cb, int dbSize){

    int pass = 1;
    
    //check that the masked seeds are equal
    if(ca != cb){
        printf("failed audit, masked seeds unequal\n");
        pass = 0;
    }
    
    //check that m vectors differ in only 1 place
    int differenceCount = 0;
    
    //#pragma omp parallel for
    for(int i = 0; i < dbSize; i++) {
        if(memcmp(&ma[i*16], &mb[i*16], 16) != 0){
            //#pragma omp critical
            differenceCount++;
        }
    }
    if(differenceCount != 1){
        printf("failed audit, difference count incorrect %d\n", differenceCount);
        pass = 0;
    }

    //check that the digests match their expected values
    int len = 0;
    uint8_t *newDigestA = (uint8_t*)malloc(32);
    uint8_t *newDigestB = (uint8_t*)malloc(32);
    digest_message(ma, dbSize*16, &newDigestA, &len);
    digest_message(mb, dbSize*16, &newDigestB, &len);
    if(memcmp(digestA, newDigestA, 32) != 0 || memcmp(digestB, newDigestB, 32) != 0){
        printf("failed audit, digest mismatch %d %d\n", memcmp(digestA, newDigestA, 32), memcmp(digestB, newDigestB, 32) != 0);
        pass = 0;
    }
    
    free(newDigestA);
    free(newDigestB);
    
    return pass;
}

int dpf_tests(){
//int main(){
    //pick 2 64-bit values as a fixed aes key
    //and use those values to key the aes we will be using as a PRG
    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        printf("errors occured in creating context\n");
    unsigned char *aeskey = (unsigned char*) "0123456789123456";
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aeskey, NULL))
        printf("errors occured in init\n");
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    
    //printf("mult test: %d", multModP((uint128_t)5<<125,((uint128_t)6)<<125)); return 0;
    //generate DPF keys for a particular query
	unsigned char *k0;
	unsigned char *k1;
    
    
    //functionality test for dpf
    char* data = "this is the data!";
    int dataSize = strlen(data)+1;

    //can only test with smaller constants because
    //gcc does not support 128 bit constants
	genDPF(ctx, 128, 300, dataSize, data, &k0, &k1);
    	
    //evaluate dpf
	uint128_t res1;
	uint128_t res2;
    uint8_t* dataShare0 = (uint8_t*) malloc(dataSize+16);
    uint8_t* dataShare1 = (uint8_t*) malloc(dataSize+16);
    
	res1 = evalDPF(ctx, k0, 12, dataSize, dataShare0);
	res2 = evalDPF(ctx, k1, 12, dataSize, dataShare1);
    printf("\nresult evaluated at 12: ");
	print_block(res1 ^ res2);

	res1 = evalDPF(ctx, k0, 300, dataSize, dataShare0);
	res2 = evalDPF(ctx, k1, 300, dataSize, dataShare1);
    printf("\nresult evaluated at 300: ");
	print_block(res1 ^ res2);
    uint8_t* recoveredData = (uint8_t*) malloc(dataSize);
    printf("data recovered: ");
    for(int i = 0; i < dataSize; i++){
        recoveredData[i] = dataShare0[i] ^ dataShare1[i];
        printf("%c", recoveredData[i]);
        //printf("%x\n", dataShare1[i]);

    }
    printf("\n");
                //return 0;
    

    
    //now we'll do a simple functionality test of the dpf checking.
    //this will in no way be rigorous or even representative of the
    //usual use case since all the evaluation points are small
    //just a sanity check before moving on to the obliv key val stuff 
    
    uint128_t db[] = {4343423, 232132, 465437, 43, 300, 5346643};
    int dbSize = 6;
    int dbLayers = 3;
    uint128_t* seed = malloc(sizeof(uint128_t));
    *seed = getRandomBlock(); 
    
    //allocate the various arrays we will need
    uint8_t* bits = malloc(dbLayers);
    uint128_t* nonZeroVectors = malloc(sizeof(uint128_t)*dbLayers);
    uint128_t* vectorsA = malloc(sizeof(uint128_t)*dbSize);
    uint128_t* vectorsB = malloc(sizeof(uint128_t)*dbSize);
    uint128_t* outVectorsA = malloc(sizeof(uint128_t)*2*dbLayers);
    uint128_t* outVectorsB = malloc(sizeof(uint128_t)*2*dbLayers);
    
    //evaluate the db at each point for each server
    //#pragma omp parallel for
    for(int i = 0; i < dbSize; i++){
        uint128_t res1, res2;
        res1 = evalDPF(ctx, k0, db[i], dataSize, dataShare0);
        res2 = evalDPF(ctx, k1, db[i], dataSize, dataShare1);
        memcpy(&vectorsA[i], &res1, 16);
        memcpy(&vectorsB[i], &res2, 16);
    }

    uint128_t* proofA = (uint128_t*)malloc(sizeof(uint128_t)*10);
    uint128_t* proofB = (uint128_t*)malloc(sizeof(uint128_t)*10);
    uint128_t* ansA = (uint128_t*)malloc(sizeof(uint128_t)*6);
    uint128_t* ansB = (uint128_t*)malloc(sizeof(uint128_t)*6);
    uint128_t mA, cA, mB, cB;
    
    //run the dpf verification functions

    clientGenProof(ctx, *seed, 4, vectorsA[4], vectorsB[4], (uint8_t*)proofA, (uint8_t*)proofB);
    serverSetupProof(ctx, (uint8_t*)seed, dbSize, (uint8_t*) vectorsA, (uint8_t*)&mA, (uint8_t*) &cA);
    serverSetupProof(ctx, (uint8_t*)seed, dbSize, (uint8_t*) vectorsB, (uint8_t*)&mB, (uint8_t*) &cB);

    //printf("m on server side"); print_block(subModP(mA,mB));
    //printf("c on server side");print_block(subModP(cA,cB));

    serverComputeQuery(ctx, (uint8_t*)seed, (uint8_t*)&mA, (uint8_t*) &cA, (uint8_t*)proofA, (uint8_t*) ansA);
    serverComputeQuery(ctx, (uint8_t*)seed, (uint8_t*)&mB, (uint8_t*) &cB, (uint8_t*)proofB, (uint8_t*) ansB);
    int pass = -1;
    pass = serverVerifyProof((uint8_t*) ansA, (uint8_t*) ansB);
    printf("dpf check verification: %d (should be 1)\n", pass);
    
    //now test the riposte auditing
    free(outVectorsA);
    free(outVectorsB);
    outVectorsA = malloc(sizeof(uint128_t)*dbSize);
    outVectorsB = malloc(sizeof(uint128_t)*dbSize);
    uint128_t cValueA = 0;
    uint128_t cValueB = 0;
    uint8_t *digestA = (uint8_t*) malloc(32);
    uint8_t *digestB = (uint8_t*) malloc(32);

    riposteClientVerify(ctx, *seed, dbSize, vectorsA, vectorsB, &digestA, &digestB);

    riposteServerVerify(ctx, *seed, dbSize, vectorsA, outVectorsA, &cValueA);
    riposteServerVerify(ctx, *seed, dbSize, vectorsB, outVectorsB, &cValueB);
    
    pass = riposteAuditorVerify(digestA, digestB, (uint8_t*)outVectorsA, (uint8_t*)outVectorsB, cValueA, cValueB, dbSize);
    printf("riposte dpf check verification: %d (should be 1)\n", pass);
    
    //tamper with dpf outputs to see if auditor catches it
    //memcpy(&outVectorsB[2], &outVectorsA[1], 16);
    //pass = riposteAuditorVerify(digestA, digestB, (uint8_t*)outVectorsA, (uint8_t*)outVectorsB, cValueA, cValueB, dbSize);
    //printf("riposte dpf check verification: %d (should be 0)\n", pass);
    
    //return 0;
    //performance test of dpf verification
    
    int dbSizes[4];
    dbSizes[0] = 1000;
    dbSizes[1] = 10000;
    dbSizes[2] = 100000;
    dbSizes[3] = 1000000;
    int dbLayer[4];
    dbLayer[0] = 10;
    dbLayer[1] = 14;
    dbLayer[2] = 17;
    dbLayer[3] = 20;
    clock_t begin, elapsed;

     seed = malloc(sizeof(uint128_t));
    *seed = getRandomBlock(); 
    
    vectorsA = malloc(sizeof(uint128_t)*dbSizes[3]);
    vectorsB = malloc(sizeof(uint128_t)*dbSizes[3]);
    
    memset(vectorsA,'a',dbSizes[3]*16);
    memset(vectorsB,'a',dbSizes[3]*16);
    vectorsA[10] = 13;
    vectorsB[10] = 12;
        
/*
void clientGenProof(EVP_CIPHER_CTX *ctx, uint128_t seed, int index, uint128_t aShare, uint128_t bShare, uint8_t* outputsAIn, uint8_t* outputsBIn);
void serverSetupProof(EVP_CIPHER_CTX *ctx, uint8_t *seedIn, int dbSize, uint8_t* vectorsIn, uint8_t* mIn, uint8_t* cIn);
void serverComputeQuery(EVP_CIPHER_CTX *ctx, uint8_t *seedIn, uint8_t* mIn, uint8_t* cIn, uint8_t* proofIn, uint8_t* ansIn);
int serverVerifyProof(uint8_t* ans1In, uint8_t* ans2In);
*/

    //us
    for(int i = 0; i < 4; i++){
        proofA = (uint128_t*)malloc(sizeof(uint128_t)*10);
        proofB = (uint128_t*)malloc(sizeof(uint128_t)*10);
        ansA = (uint128_t*)malloc(sizeof(uint128_t)*6);
        ansB = (uint128_t*)malloc(sizeof(uint128_t)*6);
        uint128_t mA, cA, mB, cB;
        
        begin = clock();
        clientGenProof(ctx, *seed, 10, vectorsA[10], vectorsB[10], (uint8_t*)proofA, (uint8_t*)proofB);
        elapsed = (clock() - begin) * 1000000 / CLOCKS_PER_SEC;
        printf("client proof gen time for db size %d: %ld microseconds\n", dbSizes[i], elapsed);
        
        begin = clock();
        serverSetupProof(ctx, (uint8_t*)seed, dbSizes[i], (uint8_t*)vectorsA, (uint8_t*)&mA, (uint8_t*)&cA);
        elapsed = (clock() - begin) * 1000000 / CLOCKS_PER_SEC;
        printf("server prep time for db size %d: %ld microseconds\n", dbSizes[i], elapsed);
        serverSetupProof(ctx, (uint8_t*)seed, dbSizes[i], (uint8_t*)vectorsB, (uint8_t*)&mB, (uint8_t*)&cB);

        begin = clock();
        serverComputeQuery(ctx, (uint8_t*)seed, (uint8_t*)&mA, (uint8_t*)&cA, (uint8_t*)proofA, (uint8_t*)ansA);
        elapsed = (clock() - begin) * 1000000 / CLOCKS_PER_SEC;
        printf("server query time for db size %d: %ld microseconds\n", dbSizes[i], elapsed);
        serverComputeQuery(ctx, (uint8_t*)seed, (uint8_t*)&mB, (uint8_t*)&cB, (uint8_t*)proofB, (uint8_t*)ansB);

        pass = 0;
        begin = clock();
        pass = serverVerifyProof((uint8_t*)ansA,(uint8_t*)ansB);
        elapsed = (clock() - begin) * 1000000 / CLOCKS_PER_SEC;
        printf("server verification time for db size %d: %ld microseconds\n", dbSizes[i], elapsed);
        if(pass == 0){
            printf("dpf check verification failed %d\n", i);
        }

	free(proofA);
	free(proofB);
	free(ansA);
	free(ansB);
    }
    
    //riposte
    for(int i = 0; i < 4; i++){ //something went wrong at 4
        outVectorsA = malloc(sizeof(uint128_t)*dbSizes[i]);
        outVectorsB = malloc(sizeof(uint128_t)*dbSizes[i]);
        cValueA = 0;
        cValueB = 0;
        digestA = (uint8_t*) malloc(32);
        digestB = (uint8_t*) malloc(32);
        
        
        begin = clock();
        riposteClientVerify(ctx, *seed, dbSizes[i], vectorsA, vectorsB, &digestA, &digestB);
        elapsed = (clock() - begin) * 1000000 / CLOCKS_PER_SEC;
        printf("riposte client verification time for db size %d: %ld microseconds\n", dbSizes[i], elapsed);
        
        begin = clock();
        riposteServerVerify(ctx, *seed, dbSizes[i], vectorsA, outVectorsA, &cValueA);
        elapsed = (clock() - begin) * 1000000 / CLOCKS_PER_SEC;
        printf("riposte server verification time for db size %d: %ld microseconds\n", dbSizes[i], elapsed);
        riposteServerVerify(ctx, *seed, dbSizes[i], vectorsB, outVectorsB, &cValueB);
        
        pass = 0;
        begin = clock();
        pass = riposteAuditorVerify(digestA, digestB, (uint8_t*)outVectorsA, (uint8_t*)outVectorsB, cValueA, cValueB, dbSizes[i]);
        elapsed = (clock() - begin) * 1000000 / CLOCKS_PER_SEC;
        printf("riposte auditor verification time for db size %d: %ld microseconds\n", dbSizes[i], elapsed);
        if(pass == 0){
            printf("riposte dpf check verification failed %d\n", i);
        }
        
        free(outVectorsA);
        free(outVectorsB);
        free(digestA);
        free(digestB);
    }
    
    free(vectorsA);
    free(vectorsB);
    
    return 0;
    //performance test of the dpf
    
    char *s[10];
    
    s[0] = (char*) malloc(2);
    s[1] = (char*) malloc(16);
    s[2] = (char*) malloc(100);
    s[3] = (char*) malloc(1000);
    s[4] = (char*) malloc(10000);
    s[5] = (char*) malloc(100000);
    s[6] = (char*) malloc(1000000);
    memset(s[0], 'a', 1);
    memset(s[0]+1, '\0', 1);
    memset(s[1], 'a', 15);
    memset(s[1]+15, '\0', 1);
    memset(s[2], 'a', 99);
    memset(s[2]+99, '\0', 1);
    memset(s[3], 'a', 999);
    memset(s[3]+999, '\0', 1);
    memset(s[4], 'a', 9999);
    memset(s[4]+9999, '\0', 1);
    memset(s[5], 'a', 99999);
    memset(s[5]+99999, '\0', 1);    
    memset(s[6], 'a', 999999);
    memset(s[6]+999999, '\0', 1);
       
    free(dataShare0);
    free(dataShare1);
    free(recoveredData);
    recoveredData = (uint8_t*) malloc(strlen(s[5])+1);
    dataShare0 = (uint8_t*) malloc(strlen(s[5])+1);
    dataShare1 = (uint8_t*) malloc(strlen(s[5])+1);
    
    for(int j = 2; j < 6; j++){//skip to the sizes we care about
        dataSize = strlen(s[j])+1;
        genDPF(ctx, 128, 300, dataSize, s[j], &k0, &k1);
        res1 = evalDPF(ctx, k0, 12, dataSize, dataShare0);
        res2 = evalDPF(ctx, k1, 12, dataSize, dataShare1);
        for(int i = 0; i < dataSize; i++){
            recoveredData[i] = dataShare0[i] ^ dataShare1[i];
        }
        if(strcmp(recoveredData, s[j]) == 0){
            printf("string %d recovered data for wrong input", j);
        }
        res1 = evalDPF(ctx, k0, 300, dataSize, dataShare0);
        res2 = evalDPF(ctx, k1, 300, dataSize, dataShare1);
        for(int i = 0; i < dataSize; i++){
            recoveredData[i] = dataShare0[i] ^ dataShare1[i];
        }
        if(strcmp(recoveredData, s[j]) != 0){
            printf("string %d recovered incorrect data", j);
        }

        clock_t start = clock(), diff;
        #pragma omp parallel for
        for(int i = 0; i < 1000; i++){
                res1 = evalDPF(ctx, k0, i*((uint128_t)2<<70), dataSize, dataShare0);
        }
        diff = clock() - start;
        int msec = diff * 1000 / CLOCKS_PER_SEC;
        printf("Time taken for string %d, db size 1,000: %d milliseconds\n", j, msec);
        
        start = clock();
        #pragma omp parallel for
        for(int i = 0; i < 10000; i++){
                res1 = evalDPF(ctx, k0, i*((uint128_t)2<<70), dataSize, dataShare0);
        }
        diff = clock() - start;
        msec = diff * 1000 / CLOCKS_PER_SEC;
        printf("Time taken for string %d, db size 10,000: %d milliseconds\n", j, msec);
        
        start = clock();
        #pragma omp parallel for
        for(int i = 0; i < 100000; i++){
                res1 = evalDPF(ctx, k0, i*((uint128_t)2<<70), dataSize, dataShare0);
        }
        diff = clock() - start;
        msec = diff * 1000 / CLOCKS_PER_SEC;
        printf("Time taken for string %d, db size 100,000: %d milliseconds\n", j, msec);
        
        /*
        start = clock();
        #pragma omp parallel for
        for(int i = 0; i < 1000000; i++){
                res1 = evalDPF(ctx, k0, i*((uint128_t)2<<70), dataSize, dataShare0);
        }
        diff = clock() - start;
        msec = diff * 1000 / CLOCKS_PER_SEC;
        printf("Time taken for string %d, db size 1,000,000: %d milliseconds\n", j, msec);
        */

    }
    
	return 0;
}
