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
    "crypto/rand"
)

func main() {
    auditor = "127.0.0.1:4444"
    serverB = "127.0.0.1:4442"
    numThreads := 16

    log.SetFlags(log.Lshortfile) 
    
    leader := 0
    if len(os.Args) > 1 {
        leader = 1
    }
    
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    C.initializeServer(numThreads)

    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }
    
    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    port := ":4442"
    if leader == 1 { //if there is a second parameter
        port = ":4443"
    }
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
    
    //first connection for setting up rows
    addRows(leader)
    //no more adding rows after here
    
    //create a bunch of channels & workers to handle requests
    blocker := make(chan int)
    conns := make(chan net.Conn)
    for i := 0; i < numThreads; i++ {
        if leader == 1{
            go leaderWorker(i, conns, blocker, serverB, auditor)
        } else {
            go worker(i, conns, blocker, auditorPublicKey, s2SecretKey)
        }
    }
    
    writeHappened := false
    
    //main loop of writes & reads
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
        
        if connType[0] == 2 { //read
            
            if writeHappened == true {
                for i:= 0; i < numThreads; i++ {
                    //signal workers one at a time by sending them nil connections
                    var nilConn net.Conn
                    conns <- nilConn
                    //wait for workers to come back after xoring into the db
                    <- blocker
                }
                
                //run rerandomization
                C.rerandDB()   
                writeHappened = false
            }
            //handle the read
            if leader == 1 {
                handleRead(conn, serverB)
            } else {
                handleRead(conn, clientPublicKey, s2SecretKey)
            }
            
        } else if connType[0] == 3 { //write
            //pass the connection on to a worker
            conns <- conn
            writeHappened = true
        }
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

func leaderWorker(id int, conns <-chan net.Conn, blocker chan<- int, serverB, auditor string) {
    //setup the worker-specific db
    dbSize :=  int(C.dbSize)
    db := make([][]byte, dbSize)
    for i := 0; i < dbSize; i++ {
        db[i] = make([]byte, int(C.db[i].dataSize))
    }
    vector := make([][16]byte, dbSize)
    outVector := make([][16]byte, 2*int(C.layers))
    
    for conn := range conns {        
        if conn == nil {//this is a read
            //xor the worker's DB into the main DB
            for i := 0; i < dbSize; i++ {
                for j := 0; j < len(db[i]); j++ {
                    C.db[i].data[j] = C.db[i].data[j] ^ db[i][j]
                    db[i][j] = 0
                }
            }
            
            //signal that you're done
            blocker <- 1
        } else {//this is a write
            
            //set up connections to server B and auditor
            conf := &tls.Config{
                InsecureSkipVerify: true,
            }
            
            //connect to server B
            connB, err := tls.Dial("tcp", serverB, conf)
            if err != nil {
                log.Println(err)
            }
            
            //connect to auditor
            connAudit, err = tls.Dial("tcp", auditor, conf)
            if err != nil {
                log.Println(err)
            }
            
            //tell server B it's a write
            //1 byte connection type 3
            connType := make([]byte, 1)
            connType[0] = 3
            n, err := conn.Write(connType)
            if err != nil {
                log.Println(n, err)
                return
            }
            //TODO some of the below should potentially be reordered
            
            //TODO read sizes, query, and boxed query
                    
            //TODO forward sizes and boxed query
                
            //TODO send seed and layers to client
            
            //TODO receive boxed client audit part
                        
            //TODO run dpf, xor into local db
            //TODO run audit part
            
            //TODO read server B boxed audit part, read client boxed audit part
            
            //TODO send audit parts to auditor, wait for response 
                
        }
    }
}


func worker(id int, conns <-chan net.Conn, blocker chan<- int, auditorPublicKey, s2SecretKey *[32]byte) {
    //setup the worker-specific db
    dbSize :=  int(C.dbSize)
    db := make([][]byte, dbSize)
    for i := 0; i < dbSize; i++ {
        db[i] = make([]byte, int(C.db[i].dataSize))
    }
    vector := make([][16]byte, dbSize)
    outVector := make([][16]byte, 2*int(C.layers))
    
    for conn := range conns {        
        if conn == nil {//this is a read
            //xor the worker's DB into the main DB
            for i := 0; i < dbSize; i++ {
                for j := 0; j < len(db[i]); j++ {
                    C.db[i].data[j] = C.db[i].data[j] ^ db[i][j]
                    db[i][j] = 0
                }
            }
            
            //signal that you're done
            blocker <- 1
        } else {//this is a write
            
            //read sizes and boxed query
            in1 := make([]byte, 4)
            in2 := make([]byte, 4)
            
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
            
            dataTransferSize := byteToInt(in1)
            dataSize := byteToInt(in2)
            
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
            
            //TODO run dpf, xor into local db
            
            for i:= 0; i < dbSize; i++ {
                
            }
            
            //TODO run audit part
            
            //TODO send boxed audit to leader
                            
        }
    }
}

func handleLeaderRead(conn net.Conn, serverB string){
    index:= make([]byte, 4)
    rowId:= make([]byte, 16)
    
    //read index and rowId
    count = 0
    //read index
    for count < 4 {
        n, err= conn.Read(index[count:])
        count += n
        if err != nil && count != 4{
            log.Println(err)
            log.Println(n)
        }
    }
    
    count = 0
    //read virtual address
    for count < 16 {
        n, err= conn.Read(rowId[count:])
        count += n
        if err != nil && count != 16{  
            log.Println(err)
            log.Println(n)
        }
    }
    
    //send request to server B
    conf := &tls.Config{
        InsecureSkipVerify: true,
    }
    
    //connect to server B
    connB, err := tls.Dial("tcp", serverB, conf)
    if err != nil {
        log.Println(err)
    }
    
    //write index and rowId to server B
    //1 byte connection type 2
    connType := make([]byte, 1)
    connType[0] = 2
    n, err := connB.Write(connType)
    if err != nil {
        log.Println(n, err)
    }
    
    //write index 4 bytes
    n, err = connB.Write(index)
    if err != nil {
        log.Println(n, err)
    }
    
    n, err = connB.Write(rowId)
    if err != nil {
        log.Println(n, err)
    }
    
    //get data size
    size := int(C.getEntrySize((*C.uchar)(&rowId[0]), C.int(byteToInt(index))))
    
    //make space for responses
    data := make([]byte, size)
    seed := make([]byte, 16)

    //get data
    C.readEntry((*C.uchar)(&rowId[0]), C.int(byteToInt(index)), (*C.uchar)(&data[0]), (*C.uchar)(&seed[0]))
    
    
    //write back seed and data
    //read response from server B
    boxBSize := 24+box.Overhead+16+size
    boxB := make([]byte, boxBSize)
    for count := 0; count < boxBSize; {
        n, err= conn.Read(boxB[count:])
        count += n
        if err != nil && count != boxBSize{
            log.Println(err)
            log.Println(n)
        }
    }
    
    //write server A response
    n, err=conn.Write(seed)
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err=conn.Write(data)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write server B response
    n, err=conn.Write(boxB)
    if err != nil {
        log.Println(n, err)
        return
    }
    
}


func handleRead(conn net.Conn, clientPublicKey, s2SecretKey *[32]byte){
    index:= make([]byte, 4)
    rowId:= make([]byte, 16)
    
    //read index and rowId
    count = 0
    //read index
    for count < 4 {
        n, err= conn.Read(index[count:])
        count += n
        if err != nil && count != 4{
            log.Println(err)
            log.Println(n)
        }
    }
    
    count = 0
    //read virtual address
    for count < 16 {
        n, err= conn.Read(rowId[count:])
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

    readPlaintext := append(seed, data)
    var nonce [24]byte
    
    //fill nonce with randomness
    _, err = rand.Read(nonce[:])
    if err != nil{
        log.Println("couldn't get randomness for nonce!")
    }
    
    readCiphertext := box.Seal(nonce[:], readPlaintext, &nonce, clientPublicKey, s2SecretKey)
    
    //send boxed message to server A
    n, err = conn.Write(readCiphertext)
    if err != nil {
        log.Println(n, err)
        return
    }
}

func addRows(leader int) {
    conn, err := ln.Accept()
    if err != nil {
        log.Println(err)
        //continue
    }
    conn.SetDeadline(time.Time{})
    for {
        connEnd := make([]byte, 1)  
        n, err:= conn.Read(connEnd)
        if err != nil && n != 1 {
            log.Println(err)
            log.Println(n)
        }
        
        if connEnd[0] == 1 {
            conn.Close()
            return
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

//TODO delete this after finishing code for workers
func handleWrite(conn net.Conn, leader int, conn2 *tls.Conn) {
    dataTransferSize:= 0 //how big the query from the user is
    dataSize := 0 //how big the data in a row is
    in1 := make([]byte, 4)
    in2 := make([]byte, 4)

    
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
    
    dataTransferSize = byteToInt(in1)
    dataSize = byteToInt(in2)
        
    //get the input
    count= 0
    input := make([]byte, dataTransferSize)
    for count < dataTransferSize {
        n, err:= conn.Read(input[count:])
        count += n
        if err != nil && count != dataTransferSize {
            log.Println(err)
        }
    } 
    
    //log.Println(dataSize)
    //log.Println(dataTransferSize)
    //register the input with c  
    var auditSeed [16]byte
    auditSeed = C.registerQuery((*C.uchar)(&input[0]), C.int(dataSize), C.int(dataTransferSize))
    //log.Println(auditSeed[:])
    
    // if leader, send back the seed to the user
    if leader == 1{
        n, err:=conn.Write(auditSeed[:])
        if err != nil {
            log.Println(n, err)
            return
        }
        
        //also send number of layers
        //log.Println(int(C.layers))
        n, err=conn.Write(intToByte(int(C.layers)))
        if err != nil {
            log.Println(n, err)
            return
        }
    }
    
    //process query
    C.processQuery()

    //send audit info to auditor 
    
    n, err := conn2.Write(intToByte(int(C.layers)))
    if err != nil {
        log.Println(n, err)
        return
    }

    n, err = conn2.Write(C.GoBytes(unsafe.Pointer(C.outVector), C.layers*16*2))
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //log.Println("audit materials sent")
    //log.Println(C.GoBytes(unsafe.Pointer(C.outVector), C.layers*16*2))
    
    //read auditor response and give an error if it doesn't accept
    auditResp := make([]byte, 1)
    count = 0
    for count < 1 {
        n, err = conn2.Read(auditResp)
        count += n
        if err != nil && n != 1 {
            log.Println(n, err)
        }
    }
    
    if auditResp[0] != 1 {
        log.Println("Audit Failed.")
    }
    
    return
}
