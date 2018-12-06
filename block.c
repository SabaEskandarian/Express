#include "block.h"
#include "aes.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <openssl/rand.h>

static AES_KEY rand_aes_key;
static uint64_t current_rand_index;

block
dpf_seed(block *seed)
{
    block cur_seed;
    current_rand_index = 0;
    if (seed) {
        cur_seed = *seed;
    } else {
        if (RAND_bytes((unsigned char *) &cur_seed, 16) == 0) {
            fprintf(stderr, "** unable to seed securely\n");
            return dpf_zero_block();
        }
    }
    AES_set_encrypt_key(cur_seed, &rand_aes_key);
    return cur_seed;
}

inline block
dpf_random_block(void)
{
    block out;
    uint64_t *val;
    int i;

    out = dpf_zero_block();
    val = (uint64_t *) &out;
    val[0] = current_rand_index++;
    out = _mm_xor_si128(out, rand_aes_key.rd_key[0]);
    for (i = 1; i < 10; ++i)
        out = _mm_aesenc_si128(out, rand_aes_key.rd_key[i]);
    return _mm_aesenclast_si128(out, rand_aes_key.rd_key[i]);
}

block *
dpf_allocate_blocks(size_t nblocks)
{
    int res;
    block *blks = NULL;
    blks = calloc(nblocks, sizeof(block));
    /* res = posix_memalign((void **) &blks, 128, sizeof(block) * nblocks); */
    /* if (res == 0) { */
    /*     return blks; */
    /* } else { */
    /*     perror("allocate_blocks"); */
    /*     return NULL; */
    /* } */
    return blks;
}


void _output_bit_to_bit(uint64_t input){
    for(int i = 0; i < 64; i++)
    {
        if( (1ll << i) & input)
            printf("1");
	else
	    printf("0");
    }
}

void dpf_cb(block input) {
    uint64_t *val = (uint64_t *) &input;

	//printf("%016lx%016lx\n", val[0], val[1]);
	_output_bit_to_bit(val[0]);
	_output_bit_to_bit(val[1]);
	printf("\n");
}

void dpf_cbnotnewline(block input) {
    uint64_t *val = (uint64_t *) &input;

	_output_bit_to_bit(val[0]);
	_output_bit_to_bit(val[1]);
}
