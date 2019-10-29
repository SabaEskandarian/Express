document.write('hello, ');
//import nacl = require("tweetnacl") // cryptographic functions
//import util = require("tweetnacl-util") // encoding & decoding 
const keypair = nacl.box.keyPair()
const receiverPublicKey = nacl.util.encodeBase64(keypair.publicKey)
const keypair2 = nacl.box.keyPair()
const receiverPublicKey2 = nacl.util.encodeBase64(keypair2.publicKey)
runTest(receiverPublicKey, receiverPublicKey2);

//using SJCL crypto library and nacl

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
    time0 = performance.now();

    rb = randomBlock(512);
    seed = rb.slice(0,16);
    ctx = initCipher(rb.slice(16,32));
    
    dpfKeys = genDPF(ctx, rb.slice(32, 48), rb.slice(48, 64));
    //see function code for all assumptions we make to make things easier
    //none of this matters for security since the browser is just sending dummy messages
    //and doesn't need full functionality to send real messages
    
    server2msg = encrypt(receiver1pk, JSON.stringify(dpfKeys['k1']));
    
    shareA = evalDPF(ctx, dpfKeys['k0']);
    shareB = evalDPF(ctx, dpfKeys['k1']);
    
    auditOut = auditDPF(ctx, seed, shareA, shareB);
    
    auditormsg = encrypt(receiver2pk, JSON.stringify(auditOut));

    time1 = performance.now();
    document.write("the operation took "+(time1-time0)+"ms");
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

function encryptBlockCtr(ctx, numBlocks) {
    ct = [];
    pt = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    for(var i = 0; i < numBlocks; i++){
        pt[0] = pt[0]+1;
        const bitarrayPT = sjcl.codec.bytes.toBits(pt);
        const c = ctx.encrypt(bitarrayPT);
        nextBlock = sjcl.codec.bytes.fromBits(c);
        ct = ct.concat(nextBlock);
    }
    return ct;
}

function randomBlock(len) {
  if (len % 32 != 0) {
      throw "random_bit_array: len not divisible by 32";
  }
  const rawOutput = sjcl.random.randomWords(len / 32, 0);
  return sjcl.codec.bytes.fromBits(rawOutput);
}

//this encrypt function is fom https://medium.com/zinc_work/using-cryptography-tweetnacl-js-to-protect-user-data-intro-tips-tricks-a8e38e1818b5
//author: George Bennett, 2018

/* This function encrypts a message using a base64 encoded
** publicKey such that only the corresponding secretKey will
** be able to decrypt
*/
function encrypt(receiverPublicKey, msgParams) {

  const ephemeralKeyPair = nacl.box.keyPair()  
  const pubKeyUInt8Array = nacl.util.decodeBase64(receiverPublicKey)  
  const msgParamsUInt8Array = nacl.util.decodeUTF8(msgParams)  
  const nonce = nacl.randomBytes(nacl.box.nonceLength)

  const encryptedMessage = nacl.box(
     msgParamsUInt8Array,
     nonce,        
     pubKeyUInt8Array,
     ephemeralKeyPair.secretKey
  )  

  return {    
    ciphertext: nacl.util.encodeBase64(encryptedMessage),    
    ephemPubKey: nacl.util.encodeBase64(ephemeralKeyPair.publicKey),
    nonce: nacl.util.encodeBase64(nonce),     
    version: "x25519-xsalsa20-poly1305"  
  }
  
}

function xor128bit(x, y){
    var z = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    for(var i = 0; i < 16; i++){
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

function dpfPRG(ctx, input) {
    returnBlob = {}
    //document.write(input);
    in0 = input.slice();
    in1 = input.slice();
    in1[0] = in1[0] ^ 1;

    returnBlob['output1'] = encryptBlock(ctx,in0);
    returnBlob['output2'] = encryptBlock(ctx,in1);
    
    returnBlob['output1'] = xor128bit(input, returnBlob['output1']);
    returnBlob['output2'] = xor128bit(input, returnBlob['output2']);
    returnBlob['output2'][0] = returnBlob['output2'][0] ^ 1;
    
    returnBlob['bit1'] = returnBlob['output1'][0] & 1;
    returnBlob['bit2'] = returnBlob['output2'][0] & 1;
    
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
    
    output = encryptBlock(ctx,temp);
    
    output = xor128bit(output, input);
    
    return output;
}

function genDPF(ctx, randblock1, randblock2) {
    //index is 128 bits in an array of bytes
    //data is an array of bytes
    
    //assume domainSize is 128 dataSize is 1024, index is all 0s, data is all 'a'
    
    returnBlob = {};
    s = [];
    tt = [];
    sCW = [];
    tCW = [];
        
    maxLayer = 128;
    
    for(var i = 0; i < maxLayer+1; i++){
        s[i] = [];
        tt[i] = [0,0];
        sCW[i] = [];
        
        if(i != maxLayer) {
            tCW[i] = [0,0];
        }
    }
    
    s[0][0] = randblock1.slice();
    s[0][1] = randblock2.slice();
    //document.write(s[0][0]);
    //document.write(s[0][1]);    
    tt[0][0] = 0;
    tt[0][1] = 1;
    
    s0 = [];
    s0[0] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    s0[1] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    s1 = [];
    s1[0] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    s1[1] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    
    t0 = [0,0];
    t1 = [0,0];
    
    for(var i = 1; i <= maxLayer; i++){
        //document.write(i);
        prg0 = dpfPRG(ctx, s[i-1][0]);
        prg1 = dpfPRG(ctx, s[i-1][1]);
        s0[0] = prg0['output1'];
        s0[1] = prg0['output2'];
        t0[0] = prg0['bit1'];
        t0[1] = prg0['bit2'];
        s1[0] = prg1['output1'];
        s1[1] = prg1['output2'];
        t1[0] = prg1['bit1'];
        t1[1] = prg1['bit2'];
        
        sCW[i-1] = xor128bit(s0[1], s1[1]);
        
        tCW[i-1][0] = t0[0] ^ t1[0] ^ 1;
        tCW[i-1][1] = t0[1] ^ t1[1];
        
        if(tt[i-1][0] == 1){
			s[i][0] = xor128bit(s0[0], sCW[i-1]);
			tt[i][0] = t0[0] ^ tCW[i-1][0];
		}else{
			s[i][0] = s0[0];
			tt[i][0] = t0[0];
		}

		            //console.log("tt[i-1][1] == 1 "+(tt[i-1][1] == 1))

		if(tt[i-1][1] == 1){
			s[i][1] = xor128bit(s1[0], sCW[i-1]);
			tt[i][1] = t1[0] ^ tCW[i-1][0];
		}else{
			s[i][1] = s1[0];
			tt[i][1] = t1[0];
		}
    }
    
    k0 = [];
    k1 = [];
    lastCW = [];
    zeros = [];
    for(var i = 0; i < 128; i++){
        zeros[i] = 0;
    }
    
    seedCtx0 = initCipher(s[maxLayer][0]);
    seedCtx1 = initCipher(s[maxLayer][1]);
    convert0 = encryptBlockCtr(seedCtx0, 8);
    convert1 = encryptBlockCtr(seedCtx1, 8);

    for(var i = 0; i < 128; i++){
        lastCW[i] = 'a' ^ convert0[i] ^ convert1[i];
    }
    
    k0[0] = 128;
    k0 = k0.concat(s[0][0]);//16 bytes
    k0[17] = tt[0][0];
	for(i = 1; i <= 128; i++){
        k0 = k0.concat(sCW[i-1]);
		k0[18 * i + 16] = tCW[i-1][0];
		k0[18 * i + 17] = tCW[i-1][1];
	}
	k0 = k0.concat(lastCW);
    
    k1[0] = 128;
    k1 = k1.concat(s[0][1]);
    k1[17] = tt[0][1];
    k1 = k1.concat(k0.slice(18, 18*128));
    k1 = k1.concat(lastCW);
    
    returnBlob['k0'] = k0;
    returnBlob['k1'] = k1;
    
    return returnBlob;
}

function evalDPF(ctx, k) {
    //only need to get the seed, no need to expand it for auditing inputs
    maxLayer = 128;
    
    s = [];
    tt = [];
    sCW = [];
    tCW = [];
    for(var i = 0; i < maxLayer+1; i++){
        s[i] = [];
        
        if(i != maxLayer) {
            tCW[i] = [0,0];
        }
    }
    
    s[0] = k.slice(1, 17);
    tt[0] = k[17];
    
    for(var i = 1; i <= maxLayer; i++){
        
        sCW[i-1] = k.slice(18*i, 18*i+16);
		tCW[i-1][0] = k[18 * i + 16];
		tCW[i-1][1] = k[18 * i + 17]; 
	}

	for(var i = 1; i <= maxLayer; i++){
        prg = dpfPRG(ctx, s[i-1])
        sL = prg['output1'];
        tL = prg['bit1'];
        sR = prg['output2'];
        tR = prg['bit2'];

		if(t[i-1] == 1){
			sL = xor128bit(sL, sCW[i-1]);
			sR = xor128bit(sR, sCW[i-1]);
			tL = tL ^ tCW[i-1][0];
			tR = tR ^ tCW[i-1][1];	

		}
		
        s[i] = sL.slice();
        tt[i] = tL;
	}
    
    return s[maxLayer];
}

function toBigNum(input) {
    //convert an array of 16 bytes to a Big Num
    bigVal = 0n;
    shift = 1n;
    for(var i = 0; i < 16; i++){
        bigVal = bigVal + (BigInt(input[i]) * shift);
        shift = shift * 256n;
    }
    return bigVal;
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
    for(var i = 0; i < 16; i++){
        tempVal = (val/shift) % 256n;
        retArray.push(Number(tempVal));
        shift = shift * 256n;
    }
    return retArray;
}

function evalLinear2(p0, p1, p) {
    slope = (p1 - p0) % p;
    p2 = (slope+slope+p0)%p;
    return p2;
}

function bigIntToByteArray(val){
    retArray = [];
    shift = 1n;
    for(var i = 0; i < 16; i++){
        tempVal = (val/shift) % 256n;
        retArray.push(Number(tempVal));
        shift = shift * 256n;
    }
    return retArray;
}

function auditDPF(ctx, seed, shareA, shareB) {
    returnBlob = {};
    returnBlob['proofA'] = [];
    returnBlob['proofB'] = [];
    
    aShare = toBigNum(shareA);
    bShare = toBigNum(shareB);
    
    p = 2n ** 128n - 159n;
    
    for(i = 0; i < 10; i++){
        returnBlob['proofB'].push(nacl.randomBytes(16));
    }
    
    //are these integers or random bytes?
    A0 = toBigNum(nacl.randomBytes(16));
    A1 = toBigNum(nacl.randomBytes(16));
    A5 = toBigNum(nacl.randomBytes(16));
    A6 = toBigNum(nacl.randomBytes(16));
    
    f0mult1 = (A0 - toBigNum(returnBlob['proofB'][0])) % p;
    g0mult1 = (A1 - toBigNum(returnBlob['proofB'][1])) % p;
    f0mult2 = (A5 - toBigNum(returnBlob['proofB'][5])) % p;
    g0mult2 = (A6 - toBigNum(returnBlob['proofB'][6])) % p;
    
    rvalue = toBigNum(auditPRF(ctx, seed, 0, 0));
    
    f1mult1 = (((aShare - bShare)%p)*rvalue)%p;
    g1mult1 = f1mult1;
    f1mult2 = (aShare - bShare) % p;
    g1mult2 = f1mult1;
    
    h0mult1 = (f0mult1*g0mult1)%p;
	h0mult2 = (f0mult2*g0mult2)%p;
	h1mult1 = (f1mult1*g1mult1)%p;
	h1mult2 = (f1mult2*g1mult2)%p;
    
    A2 = (h0mult1 + toBigNum(returnBlob['proofB'][2]))%p;
    A7 = (h0mult2 + toBigNum(returnBlob['proofB'][7]))%p;
    A3 = (h1mult1 + toBigNum(returnBlob['proofB'][3]))%p;
    A8 = (h1mult2 + toBigNum(returnBlob['proofB'][8]))%p;
    
    f2mult1 = evalLinear2(f0mult1, f1mult1, p);
    g2mult1 = evalLinear2(g0mult1, g1mult1, p);
    f2mult2 = evalLinear2(f0mult2, f1mult2, p);
    g2mult2 = evalLinear2(g0mult2, g1mult2, p);
    
    h2mult1 = (f2mult1*g2mult1)%p;
    h2mult2 = (f2mult2*g2mult2)%p;
    
    A4 = (h2mult1 + toBigNum(returnBlob['proofB'][4]))%p;
    A9 = (h2mult1 + toBigNum(returnBlob['proofB'][9]))%p;
    
    returnBlob['proofA'].push(bigIntToByteArray(A0));
    returnBlob['proofA'].push(bigIntToByteArray(A1));
    returnBlob['proofA'].push(bigIntToByteArray(A2));
    returnBlob['proofA'].push(bigIntToByteArray(A3));
    returnBlob['proofA'].push(bigIntToByteArray(A4));
    returnBlob['proofA'].push(bigIntToByteArray(A5));
    returnBlob['proofA'].push(bigIntToByteArray(A6));
    returnBlob['proofA'].push(bigIntToByteArray(A7));
    returnBlob['proofA'].push(bigIntToByteArray(A8));
    returnBlob['proofA'].push(bigIntToByteArray(A9));
    
    return returnBlob;
}
