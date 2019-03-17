document.write('hello, ');
//import nacl = require("tweetnacl") // cryptographic functions
//import util = require("tweetnacl-util") // encoding & decoding 
const keypair = nacl.box.keyPair()
const receiverPublicKey = nacl.util.encodeBase64(keypair.publicKey)
const keypair2 = nacl.box.keyPair()
const receiverPublicKey2 = nacl.util.encodeBase64(keypair2.publicKey)
runTest(receiverPublicKey, receiverPublicKey2);

//using SJCL crypto library

//performance test of computation needed to send a message to the server
//1. generate dpf keys
//2. encrypt message including the message size and the dpf key for server b to some public key
//3. run client audit component
//  a) eval dpf at 1 point for each key generated above
//  b) run actual audit component
//4. encrypt message including client audit output to some public key

/*
 * this is meant as a test of the performance of the primitives if they were to 
 * be run inside of a browser and is not meant to be fully correct or compatible
 * with the rest of the system built and tested as part of this project.
 * It probably contains many, many bugs (even more than the other part).
 */
function runTest(receiver1pk, receiver2pk){
    t0 = performance.now();

    var dbLayers = 10;

    rb = randomBlock(32);
    seed = rb.slice(0,16);
    ctx = initCipher(rb.slice(16,32));
    
    dpfKeys = genDPF(ctx);
    //see function code for all assumptions we make to make things easier
    //none of this matters for security since the browser is just sending dummy messages
    //and doesn't need full functionality to send real messages
    
    server2msg = encrypt(receiver1pk, JSON.stringify(dpfKeys['k1']));
    
    shareA = evalDPF(ctx, dpfKeys['k0']);
    shareB = evalDPF(ctx, dpfKeys['k1']);
    
    auditOut = auditDPF(ctx, seed, shareA, shareB, dbLayers);
    
    auditormsg = encrypt(receiver2pk, JSON.stringify(auditOut));

    t1 = performance.now();
    document.write("the operation took "+(t1-t0)+"ms");
}

function initCipher(key) {
    const bitarrayKey = sjcl.codec.bytes.toBits(key);
    return new sjcl.cipher.aes(bitarrayKey);
}

function encryptBlock(ctx, plaintext) {
  const bitarrayPT = sjcl.codec.bytes.toBits(plaintext);
  const c = ctx.encrypt(bitarrayPT);
  return sjcl.codec.bytes.fromBits(c);
}

function randomBlock(len) {
  if (len % 32 != 0) {
      throw "random_bit_array: len not divisible by 32";
  }
  const rawOutput = sjcl.random.randomWords(len / 32, 0);
  return sjcl.codec.bytes.fromBits(rawOutput);
}

function xor128bit(x, y){
    var z = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    for(i = 0; i < 16; i++){
        z[i] = x[i] ^ y[i];
    }
    return z;
}

function dpf_set_lsb_zero(input){//input will be a byte
    lsb = input & 1;
    
	if(lsb == 1){
		return input ^ 1;
	}else{
		return input;
	}
}

function dpfPRG(ctx, input, output1, output2, bit1, bit2) {
    returnBlob = {}
    
    in0 = input.slice();
    in0[0] = dpf_set_lsb_zero(in0[0]);
    in1 = input.slice();
    
    returnBlob['output1'] = encryptBlock(ctx,in0);
    returnBlob['output2'] = encryptBlock(ctx,in1);
    
    returnBlob['output1'] = xor128bit(input, returnBlob['output1']);
    returnBlob['output2'] = xor128bit(input, returnBlob['output2']);
    returnBlob['output2'][0] = returnBlob['output2'][0] ^ 1;
    
    returnBlob['bit1'] = returnBlob['output1'] & 1;
    returnBlob['bit2'] = returnBlob['output2'] & 1;
    
    returnBlob['output1'][0] = dpf_set_lsb_zero(returnBlob['output1'][0]);
    returnBlob['output2'][0] = dpf_set_lsb_zero(returnBlob['output2'][0]);
    
    return returnBlob;
}

function getbit(input, i){
    //input is array of 16 bytes (128 bits)
    //i is between 0 and 127
    index = 15 - Math.floor((127-i)/8);
    shift = i % 8;
    return (input[index] >> shift) & 1;
    
}

function auditPRF(ctx, input, layer, count) {
    //simplification of the version in the C code
    //probability of getting a bad output is negligible given the size of the prime field
    //so just don't check for failure there

    temp = input.slice();
    temp[0] = temp[0] ^ count;
    temp[1] = temp[1] ^ layer;
    
    output = encryptBlock(ctx,input);
    
    output = xor128bit(output, input);
    
    return output;
}

function genDPF(ctx) {
    //index is 128 bits in an array of bytes
    //data is an array of bytes
    
    //assume domainSize is 128 dataSize is 1024, index is all 0s, data is all 'a'
    
    returnBlob = {};
    returnBlob['k0'] = [];
    returnBlob['k1'] = [];
    
    maxLayer = domainSize;
    
}

function evalDPF(ctx, dpfKey) {
    
}

function toBigNum(input) {
    //convert an array of 16 bytes to a Big Num
    bigVal = 0n;
    shift = 1n;
    for(i = 0; i < 16; i++){
        bigVal = bigVal + (BigInt(input[i]) * shift);
        shift = shift * 256n;
    }
}

function bigIntOps(aShare, bShare, m, p) {
//take in bignums
//subtract bShare from aShare, multiply the result by m, all mod p=2^128-159
//return an array of bytes
    val = (aShare - bShare) % p;
    val = (val * m) % p;
    
    //convert back to byte array
    retArray = [];
    shift = 1n;
    for(i = 0; i < 16; i++){
        tempVal = (val/shift) % 256n;
        retArray.push(BigInt.asUintN(tempVal));
        shift = shift * 256n;
    }
    return retArray;
}

function auditDPF(ctx, seed, shareA, shareB, dbLayers) {
    returnBlob = {};
    returnBlob['vals'] = [];
    returnBlob['bits'] = [];
    //since index is hard-coded to 0, bits will be an entirely random vector
    //so we can do it in one shot
    bitsVector = auditPRF(ctx, seed, 0, -1);
    
    aShare = toBigNum(shareA);
    bShare = toBigNum(shareB);
    
    p = 2n ** 128n - 159n;
    
    for(i = 0; i < dbLayers; i++){
        returnBlob['bits'].push(getbit(bitsVector, i));

        m = toBigNum(auditPRF(ctx, seed, i, 0));
        returnBlob['vals'].push(bigIntOps(aShare, bShare, m, p));
    }
    
    return returnBlob;
}
