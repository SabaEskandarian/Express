//initial source code based on denji/golang-tls

package main

/*
#cgo CFLAGS: -fopenmp -O2
#cgo LDFLAGS: -lcrypto -lm -fopenmp
#include "../c/dpf.h"
#include "../c/okv.h"
#include "../c/dpf.c"
#include "../c/okv.c"
*/
import "C"
import (
    "log"
    "crypto/tls"
    "net"
    "os"
    "time"
    "unsafe"
    "io"
    "crypto/rand"
    "golang.org/x/crypto/nacl/box"
    "strings"
    "sync"
    "strconv"
)

var numThreads int
var numCores int

func main() {
    numThreads = 16
    numRowsSetup := 0
    dataSizeSetup := 160

    log.SetFlags(log.Lshortfile) 
    
    if len(os.Args) < 5 {
        log.Println("usage: serverB [numThreads] [numCores] [numRows] [rowDataSize]")
        return
    } else {
        numThreads, _ = strconv.Atoi(os.Args[1])
        numCores, _ = strconv.Atoi(os.Args[2])
        numRowsSetup, _ = strconv.Atoi(os.Args[3])
        dataSizeSetup, _ = strconv.Atoi(os.Args[4])
    }
    
    C.initializeServer(C.int(numThreads))

    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }
    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    port := ":4442"
    ln, err := tls.Listen("tcp", port, config)  
    if err != nil {
        log.Println(err)
        return
    }
    defer ln.Close()
    
    //using a deterministic source of randomness for testing
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers/auditors should be known 
    //ahead of time and those would be used
    clientPublicKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("c",10000)))
    if err != nil {
        log.Println(err)
        return
    }    
    _, s2SecretKey, err := box.GenerateKey(strings.NewReader(strings.Repeat("b",10000)))
    if err != nil {
        log.Println(err)
        return
    }
    auditorPublicKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("a",10000)))
    if err != nil {
        log.Println(err)
        return
    }
    
    auditorSharedKey := new([32]byte)
    box.Precompute(auditorSharedKey, auditorPublicKey, s2SecretKey)
    
        
    //first connection for setting up rows
    conn, err := ln.Accept()
    if err != nil {
        log.Println(err)
        //continue
    }
    conn.SetDeadline(time.Time{})
    addRows(0, conn)
    
    //server sets up a numRows rows on its own
    for i:=0; i < numRowsSetup; i++ {
        var setupRowKey [16]byte
        _, err = rand.Read(setupRowKey[:])
        if err != nil{
            log.Println("couldn't get randomness for row key!")
        }
        C.processnewEntry(C.int(dataSizeSetup), (*C.uchar)(&setupRowKey[0]))
    }
    //no more adding rows after here
    
    //create a bunch of workers to handle requests
    var m sync.Mutex
    for i := 0; i < numThreads; i++ {
        conn, err := ln.Accept()
        if err != nil {
            log.Println(err)
        }
        conn.SetDeadline(time.Time{})
        go worker(i, conn, m, clientPublicKey, auditorSharedKey, s2SecretKey)
    }

    //main loop of reads -- writes handled inside workers
    //this implementation needs all writes to be done before a read happens
    //or there might be inconsistent state between servers
    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println(err)
            //continue
        }
        conn.SetDeadline(time.Time{})
        
        connType := make([]byte, 1)  
        n, err:= conn.Read(connType)
        if err != nil && n != 1 {
            log.Println(err)
            log.Println(n)
        }
        
        if connType[0] == 1 { //writeHappened == true
            //run rerandomization
            C.rerandDB()
        }
        
        //handle the read
        handleRead(conn, clientPublicKey, s2SecretKey)
            
    }
}

func byteToInt(myBytes []byte) (x int) {
    x = int(myBytes[3]) << 24 + int(myBytes[2]) << 16 + int(myBytes[1]) << 8 + int(myBytes[0])
    return
}

func intToByte(myInt int) (retBytes []byte){
    retBytes = make([]byte, 4)
    retBytes[3] = byte((myInt >> 24) & 0xff)
    retBytes[2] = byte((myInt >> 16) & 0xff)
    retBytes[1] = byte((myInt >> 8) & 0xff)
    retBytes[0] = byte(myInt & 0xff)
    return
}

func worker(id int, conn net.Conn, m sync.Mutex, clientPublicKey, auditorSharedKey, s2SecretKey *[32]byte) {
    //log.Println("starting worker")
    //setup the worker-specific db
    dbSize :=  int(C.dbSize)
    db := make([][]byte, dbSize)
    for i := 0; i < dbSize; i++ {
        db[i] = make([]byte, int(C.db[i].dataSize))
    }
    vector := make([]byte, dbSize*16)
    outVector := make([]byte, 2*int(C.layers)*16)
    
    for {
        //log.Println("worker sees a new connection")
        
        //log.Println("worker processing write")
        
        //read sizes and boxed query
        in1 := make([]byte, 4)
        in2 := make([]byte, 4)
        seed := make([]byte, 16)
        
        count := 0
        //read dataTransferSize
        for count < 4 {
            n, err:= conn.Read(in1[count:])
            count += n
            if err != nil && count != 4{
                log.Println(err)
                log.Println(n)
            }
        }
        
        //if dataTransferSize was 0, this is really a read
        if byteToInt(in1) == 0 {
            m.Lock()
            //xor worker's DB into main DB
            for i := 0; i < dbSize; i++ {
                C.xorIn(C.int(i), (*C.uchar)(&db[i][0]))
                db[i] = make([]byte, int(C.db[i].dataSize))
            }
            m.Unlock()
            continue
        }
        
        
        count = 0
        //read dataSize
        for count < 4 {
            n, err:= conn.Read(in2[count:])
            count += n
            if err != nil && count != 4{
                log.Println(err)
                log.Println(n)
            }
        }
        
        //read seed
        count = 0
        for count < 16 {
            n, err:= conn.Read(seed[count:])
            count += n
            if err != nil && count != 16{
                log.Println(err)
                log.Println(n)
            }
        }
        
        dataTransferSize := byteToInt(in1)
        //dataSize := byteToInt(in2)
        
        clientInput := make([]byte, 24+dataTransferSize+box.Overhead)
        for count := 0; count < 24+dataTransferSize+box.Overhead; {
            n, err:= conn.Read(clientInput[count:])
            count += n
            if err != nil && err != io.EOF && count != 24+dataTransferSize+box.Overhead{
                log.Println(err)
            }
        }
        
        //unbox query
        var decryptNonce [24]byte
        copy(decryptNonce[:], clientInput[:24])
        decryptedQuery, ok := box.Open(nil, clientInput[24:], &decryptNonce, clientPublicKey, s2SecretKey)
        if !ok {
            log.Println("Decryption not ok!!")
        }
        
        //log.Println("worker decrypted client query")
        
        /*
        //run dpf, xor into local db
        //spread the eval across goroutines
        parablocker := make(chan int)
        startPoint := 0
        endPoint := dbSize
        for k:=1; k <= numThreads; k++{
            endPoint = k*dbSize/numThreads
            go func(startPoint, endPoint int, vector []byte, db [][]byte) {
                for i:= startPoint; i < endPoint; i++{
                    ds := int(C.db[i].dataSize)
                    dataShare := make([]byte, ds)
                    v := C.evalDPF(C.ctx[id], (*C.uchar)(&decryptedQuery[0]), C.db[i].rowID, C.int(ds), (*C.uchar)(&dataShare[0]))
                    copy(vector[i*16:(i+1)*16], C.GoBytes(unsafe.Pointer(&v), 16))
                    for j := 0; j < ds; j++ {
                        db[i][j] = db[i][j] ^ dataShare[j]
                    }
                }
                parablocker <- 1
            }(startPoint, endPoint, vector, db)
            startPoint = endPoint
        }
        for k:= 1; k <= numThreads; k++{
            <-parablocker
        }
        */
            
        //log.Println(decryptedQuery)
        //run dpf, xor into local db
        for i:= 0; i < dbSize; i++ {
            ds := int(C.db[i].dataSize)
            dataShare := make([]byte, ds)
            v := C.evalDPF(C.ctx[id], (*C.uchar)(&decryptedQuery[0]), C.db[i].rowID, C.int(ds), (*C.uchar)(&dataShare[0]))
            copy(vector[i*16:(i+1)*16], C.GoBytes(unsafe.Pointer(&v), 16))
            for j := 0; j < ds; j++ {
                db[i][j] = db[i][j] ^ dataShare[j]
            }
        }
        
        
        //run audit part
        C.serverVerify(C.ctx[id], (*C.uchar)(&seed[0]), C.layers, C.dbSize, (*C.uchar)(&vector[0]), (*C.uchar)(&outVector[0]));
        
        //send boxed audit to leader
        var nonce [24]byte
        _, err := rand.Read(nonce[:])
        if err != nil{
            log.Println("couldn't get randomness for nonce!")
        }
        auditPlaintext := append(intToByte(int(C.layers)), outVector...)
        auditCiphertext := box.SealAfterPrecomputation(nonce[:], auditPlaintext, &nonce, auditorSharedKey)
        n, err := conn.Write(auditCiphertext)
        if err != nil {
            log.Println(n, err)
            return
        }            
    }
}

func handleRead(conn net.Conn, clientPublicKey, s2SecretKey *[32]byte){
    index:= make([]byte, 4)
    rowId:= make([]byte, 16)
    
    //read index and rowId
    count := 0
    //read index
    for count < 4 {
        n, err:= conn.Read(index[count:])
        count += n
        if err != nil && count != 4{
            log.Println(err)
            log.Println(n)
        }
    }
    
    count = 0
    //read virtual address
    for count < 16 {
        n, err:= conn.Read(rowId[count:])
        count += n
        if err != nil && count != 16{  
            log.Println(err)
            log.Println(n)
        }
    }
    
    
    //get data size
    size := C.getEntrySize((*C.uchar)(&rowId[0]), C.int(byteToInt(index)))
        
    //make space for responses
    data := make([]byte, size)
    seed := make([]byte, 16)

    //get data
    C.readEntry((*C.uchar)(&rowId[0]), C.int(byteToInt(index)), (*C.uchar)(&data[0]), (*C.uchar)(&seed[0]))
    
    
    //write back seed and data
    //box response, send to server A

    readPlaintext := append(seed, data...)
    var nonce [24]byte
    
    //fill nonce with randomness
    _, err := rand.Read(nonce[:])
    if err != nil{
        log.Println("couldn't get randomness for nonce!")
    }
    
    readCiphertext := box.Seal(nonce[:], readPlaintext, &nonce, clientPublicKey, s2SecretKey)
    //log.Println(readCiphertext)
        
    //send boxed message to server A
    n, err := conn.Write(readCiphertext)
    if err != nil {
        log.Println(n, err)
        return
    }
    
}

func addRows(leader int, conn net.Conn) {
    done := 0
    
    for done == 0{
        connEnd := make([]byte, 1)  
        n, err:= conn.Read(connEnd)
        if err != nil && n != 1 {
            log.Println(err)
            log.Println(n)
        }
        
        if connEnd[0] == 1 {
            conn.Close()
            done = 1
            break
        }
        
        dataSize:=make([]byte, 4)
        rowKey:=make([]byte, 16)
        
        count := 0
        //read dataSize 
        for count < 4 {
            n, err= conn.Read(dataSize[count:])
            count += n
            if err != nil && count != 4{
                log.Println(err)
                log.Println(n)
            }
        }
        
        count = 0
        //read rowKey
        for count < 16 {
            n, err= conn.Read(rowKey[count:])
            count += n
            if err != nil && count != 16{
                log.Println(err)
                log.Println(n)
            }
        }
        //call C command to register row
        newIndex:= C.processnewEntry(C.int(byteToInt(dataSize)), (*C.uchar)(&rowKey[0]))
        
        if leader == 1 {
            //send the newIndex number back
            n, err=conn.Write(intToByte(int(newIndex)))
            if err != nil {
                log.Println(n, err)
                return
            }
            //send the rowId back 
            n, err=conn.Write(C.GoBytes(unsafe.Pointer(C.tempRowId), 16))
            if err != nil {
                log.Println(n, err)
                return
            }
        }
    }
}
