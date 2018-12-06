#include "dpf.h"

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

/*
 * TODO: finish/fix this and maybe move to appropriate header file
 * 
void PRG_SINGLE(AES_KEY *key, block input, block* output){

	block stash* = input;

	AES_ecb_encrypt_blks(stash, 1, key);

	stash = dpf_xor(stash[0], input);

	*output = dpf_set_lsb_zero(stash);
}
*/

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
