//initial source code based on denji/golang-tls

package main


/*
#cgo CFLAGS: -O2
#cgo LDFLAGS: -lcrypto -lm
#include "../c/dpf.h"
#include "../c/okvClient.h"
#include "../c/dpf.c"
#include "../c/okvClient.c"
*/
import "C"
import (
    "log"
    "crypto/tls"
    "unsafe"
    "time"
    "crypto/rand"
    "golang.org/x/crypto/nacl/box"
    "strings"
    "os"
    "strconv"
)

var serverA string
var serverB string

func main() {
     
    serverA = "127.0.0.1:4443"
    serverB = "127.0.0.1:4442"
    
    //parameters for tests
    //remember to start servers in order: auditor, server 1, server, client
    latencyTest := 1 //set to 0 for throughput test instead
    numThreads := 8 //how many writes to initiate at once when going for throughput
    dataLen := 160
    rowsCreated := 1 //just create 1 row this way, the rest will be created by the servers
    //dataLen values to try: 100, 1000, 10000, 100000, 1000000
    //dbSize values to try: 1000, 10000, 100000, 1000000

    if len(os.Args) < 5 {
        log.Println("usage: client [serverAip:port] [serverBip:port] [numThreads] [rowDataSize] (optional)throughput")
        return
    } else {
        serverA = os.Args[1]
        serverB = os.Args[2]
        numThreads, _ = strconv.Atoi(os.Args[3])
        dataLen, _ = strconv.Atoi(os.Args[4])
    }

    if len(os.Args) > 5 {
        latencyTest = 0
    }
    
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    log.SetFlags(log.Lshortfile)
    
    C.initializeClient(C.int(numThreads))   
    
    //using a deterministic source of randomness for testing
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers/auditors should be known 
    //ahead of time and those would be used
    _, clientSecretKey, err := box.GenerateKey(strings.NewReader(strings.Repeat("c",10000)))
    if err != nil {
        log.Println(err)
        return
    }    
    s2PublicKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("b",10000)))
    if err != nil {
        log.Println(err)
        return
    }
    auditorPublicKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("a",10000)))
    if err != nil {
        log.Println(err)
        return
    }
    
    //hacky setup phase
    connA, err := tls.Dial("tcp", serverA, conf)
    if err != nil {
        log.Println(err)
        return
    }

    connB, err := tls.Dial("tcp", serverB, conf)
    if err != nil {
        log.Println(err)
        return
    }
    //use the connections set up at the beginning to add a bunch of rows really fast
    for i:= 0; i < rowsCreated; i++ {
        addRow(dataLen, connA, connB) 
        //if i % 10000 == 0 && i != 0 {
        //    log.Println("added 10000 rows")
        //}
    }
    //close the connections we used for setup
    connEnd := make([]byte, 1) 
    connEnd[0] = 1
    n, err := connA.Write(connEnd)
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err = connB.Write(connEnd)
    if err != nil {
        log.Println(n, err)
        return
    }
    connA.Close()
    connB.Close()
    
    //msg := []byte("this is the message!")
    msg := make([]byte, dataLen)
    for i := 0; i < dataLen; i++ {
        msg[i] = 'a'
    }
    
    //begin tests
    if latencyTest == 1 {
        
        var totalTimeWrite time.Duration
        var totalTimeRead time.Duration
        
        //there's a warmup effect on the server, so drop first time
        for i:=0; i < 11; i++{
            //measured ops here
            startTime := time.Now()

            writeRow(0, 0, msg, serverA, s2PublicKey, auditorPublicKey, clientSecretKey)

            elapsedTime := time.Since(startTime)
            log.Printf("write operation time (dataLen %d): %s\n", dataLen, elapsedTime)
            if i > 0 {
                totalTimeWrite += elapsedTime
            }

            //measured ops here
            startTime = time.Now()
            
            readRow(0, serverA, s2PublicKey, clientSecretKey)

            elapsedTime = time.Since(startTime)
            log.Printf("read operation time (dataLen %d): %s\n", dataLen, elapsedTime)
            if i > 0 {
                totalTimeRead += elapsedTime
            }
        }
        
        log.Printf("average write operation time (dataLen %d): %s\n", dataLen, totalTimeWrite/10)
        log.Printf("average read operation time (dataLen %d): %s\n", dataLen, totalTimeRead/10)
        
    } else { //throughput test
        maxOps := 10000 //number of times each thread will write
        blocker := make(chan int)

        //runs nonstop 
        for i := 0; i < numThreads; i++ {
            go throughputWriter(i, maxOps, 0, msg, serverA, s2PublicKey, auditorPublicKey, clientSecretKey, blocker)
        }
        //measurement for this will be taken care of at the server side
        
        for i := 0; i < numThreads; i++{
            <- blocker
        }
    }
    
    
    //end measurement
    
    /*
     * this stuff won't work with the new test setup
    //the rest is here to make sure nothing is broken
    //not important for measurement
    rowVal := readRow(13, serverA, s2PublicKey, clientSecretKey)
    log.Println("rowVal 13 is ")
    log.Println(string(rowVal))
    
    writeRow(0, 13, msg, serverA, s2PublicKey, auditorPublicKey, clientSecretKey, 0)
    log.Println("wrote message")
    
    rowVal = readRow(11, serverA, s2PublicKey, clientSecretKey)
    log.Println("rowVal 11 is ")
    log.Println(string(rowVal))      
    
    rowVal = readRow(13, serverA, s2PublicKey, clientSecretKey)
    log.Println("rowVal 13 is ")
    log.Println(string(rowVal))
    */
    
}

func throughputWriter(threadNum, totalRuns, localIndex int, data []byte, serverA string, s2PublicKey, auditorPublicKey, clientSecretKey *[32]byte, blocker chan<- int) {
    
    for i:=0;i<totalRuns;i++ {
        writeRow(threadNum, localIndex, data, serverA, s2PublicKey, auditorPublicKey, clientSecretKey)
    }
    blocker <- 1
    return
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

func addRow(dataSize int, connA, connB *tls.Conn) {

    
    //allocate space to hold return values
    rowAKey := (*C.uchar)(C.malloc(16))
    rowBKey := (*C.uchar)(C.malloc(16))
    
    //Call c function to get the row prepared
    C.prepNewRow(C.int(dataSize), rowAKey, rowBKey)
    
    //log.Println(C.GoBytes(unsafe.Pointer(rowId), 16))
    //log.Println(C.GoBytes(unsafe.Pointer(rowAKey), 16))
    //log.Println(C.GoBytes(unsafe.Pointer(rowBKey), 16))
    //log.Println(rowId)
    //log.Println()

    
    //write the data to each connection
    //1 byte connection type 0
    connType := make([]byte, 1) 
    connType[0] = 0
    n, err := connA.Write(connType)
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err = connB.Write(connType)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //4 bytes dataSize
    sendDataSize := intToByte(dataSize)
    n, err = connA.Write(sendDataSize)
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err = connB.Write(sendDataSize)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //16 bytes key
    n, err = connA.Write(C.GoBytes(unsafe.Pointer(rowAKey), 16))
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err = connB.Write(C.GoBytes(unsafe.Pointer(rowBKey), 16))
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //log.Println(C.GoBytes(unsafe.Pointer(rowAKey), 16))
    //log.Println(C.GoBytes(unsafe.Pointer(rowBKey), 16))
    
    newIndex := make([]byte, 4)
    //read back the new index number
    for count := 0; count < 4; {
        n, err= connA.Read(newIndex[count:])
        count += n
        if err != nil && count != 4 {
            log.Println(err)
            log.Println(n)
        }
    }
    
    newRowID := make([]byte, 16)
    //read back the row id
    for count := 0; count < 16; {
        n, err= connA.Read(newRowID[count:])
        count += n
        if err != nil && count != 16 {
            log.Println(err)
            log.Println(n)
        }
    }
    
    C.addAddr(C.int(byteToInt(newIndex)), (*C.uchar)(&newRowID[0]))
}

func readRow(localIndex int, serverA string, s2PublicKey, clientSecretKey *[32]byte) ([]byte){
    
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    //connect to server A
    conn, err := tls.Dial("tcp", serverA, conf)
    if err != nil {
        log.Println(err)
    }
    
    //1 byte connection type 2
    connType := make([]byte, 1)
    connType[0] = 2
    n, err := conn.Write(connType)
    if err != nil {
        log.Println(n, err)
    }
    
    //write index 4 bytes
    sendIndex := intToByte(localIndex)
    n, err = conn.Write(sendIndex)
    if err != nil {
        log.Println(n, err)
    }
    
    //write virtual address, 16 bytes
    //virtAddr := make([]byte, 16)
    //C.getVirtualAddress(C.int(localIndex), (*C.uchar)(&virtAddr[0]))
    virtAddr := C.GoBytes(unsafe.Pointer(&(C.db[localIndex].rowID)), 16)
    n, err = conn.Write(virtAddr)
    if err != nil {
        log.Println(n, err)
    }
    
    //read seed and data from server A
    seedA := make([]byte, 16)
    for count := 0; count < 16; {
        n, err= conn.Read(seedA[count:])
        count += n
        if err != nil && count != 16{
            log.Println(err)
            log.Println(n)
        }
    }
    
        
    size := C.db[localIndex].dataSize
    dataA := make([]byte, size)
    for count := 0; count < int(size); {
        n, err= conn.Read(dataA[count:])
        count += n
        if err != nil && count != int(size){
            log.Println(err)
            log.Println(n)
        }
    }
    
    
    //read, unbox, and parse seed and data from server B
    boxBSize := box.Overhead+16+int(size)+24
    boxB := make([]byte, boxBSize)
    for count := 0; count < boxBSize; {
        n, err= conn.Read(boxB[count:])
        count += n
        if err != nil && count != boxBSize{
            log.Println(err)
            log.Println(n)
        }
    }
    
    var decryptNonce [24]byte
    copy(decryptNonce[:], boxB[:24])
    decryptedS2, ok := box.Open(nil, boxB[24:], &decryptNonce, s2PublicKey, clientSecretKey)
    if !ok {
        //log.Println(boxB)
        log.Println("Decryption not ok!!")
    }
    
    //seedB := make([]byte, 16)
    seedB := decryptedS2[:16]
    //dataB := make([]byte, size)
    dataB := decryptedS2[16:16+size]
    
    //log.Println(dataA)
    //log.Println(dataB)
    //log.Println(seedA)
    //log.Println(seedB)
    //log.Println()
    
    //decrypt
    //void decryptRow(int localIndex, uint8_t *dataA, uint8_t *dataB, uint8_t *seedA, uint8_t *seedB);
    C.decryptRow(C.int(localIndex), (*C.uchar)(&dataA[0]), (*C.uchar)(&dataB[0]), (*C.uchar)(&seedA[0]), (*C.uchar)(&seedB[0]))

    return C.GoBytes(unsafe.Pointer(C.outData), size)
}

//this is the only function that can safely be called in parallel goroutines
func writeRow(threadNum, localIndex int, data []byte, serverA string, s2PublicKey, auditorPublicKey, clientSecretKey *[32]byte) {
    
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    //connect to server A
    conn, err := tls.Dial("tcp", serverA, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()
    
    dataSize := len(data)
    querySize := make([]byte, 4)
    
    //prep the query
    cIntQuerySize := C.int(byteToInt(querySize))
    var dpfQueryA *C.uchar
    var dpfQueryB *C.uchar
    
    C.prepQuery(C.int(threadNum), C.int(localIndex), (*C.uchar)(&data[0]), C.int(dataSize), &cIntQuerySize, &dpfQueryA, &dpfQueryB)
    
    intQuerySize := int(cIntQuerySize)//byteToInt(querySize)
    
    //write first message to server A
    //1 byte connection type 3
    connType := make([]byte, 1)
    connType[0] = 3
    n, err := conn.Write(connType)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //log.Println(dataSize)
    //log.Println(querySize)
    
    msg := append(intToByte(intQuerySize), intToByte(dataSize)...)
    
    //write dataTransferSize

    
    //write dataSize
    
    //write the query
    sendQuery := C.GoBytes(unsafe.Pointer(dpfQueryA), C.int(intQuerySize))
    
    msg = append(msg, sendQuery...)
    
    
    
    //prepare message for server B, box it, and send to server A
    
    serverBPlaintext := C.GoBytes(unsafe.Pointer(dpfQueryB), C.int(intQuerySize))
    
    //box serverBPlaintext
    
    var nonce [24]byte
    //fill nonce with randomness
    _, err = rand.Read(nonce[:])
    if err != nil{
        log.Println("couldn't get randomness for nonce!")
    }
    
    serverBCiphertext := box.Seal(nonce[:], serverBPlaintext, &nonce, s2PublicKey, clientSecretKey)
    
    msg = append(msg, serverBCiphertext...)
    n, err = conn.Write(msg)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //read seed and layers from server A (in preparation for auditing)
    retA := make([]byte, 20)
    for count := 0; count < 20; {
        n, err= conn.Read(retA[count:])
        count += n
        if err != nil && count != 20{
            log.Println(err)
            log.Println(n)
        }
    }
    
    seed := retA[:16]
    layers := retA[16:20]
    
    //prepare message for auditor, box it, and send to server A
    //prepare the auditor message
    
    userBits := (*C.uchar)(C.malloc(C.ulong(byteToInt(layers))))
    nonZeroVectors := (*C.uchar)(C.malloc(C.ulong(16*byteToInt(layers))))
    
    C.prepAudit(C.int(threadNum), C.int(localIndex), C.int(byteToInt(layers)), (*C.uchar)(&seed[0]), userBits, nonZeroVectors, dpfQueryA, dpfQueryB)
    
    
    //box message to auditor
    //var nonce [24]byte already declared above
    //fill nonce with randomness
    _, err = rand.Read(nonce[:])
    if err != nil{
        log.Println("couldn't get randomness for nonce!")
    }
    
    auditPlaintext := append(C.GoBytes(unsafe.Pointer(userBits), C.int(byteToInt(layers))), C.GoBytes(unsafe.Pointer(nonZeroVectors), C.int(byteToInt(layers)*16))...)
    
    auditCiphertext := box.Seal(nonce[:], auditPlaintext, &nonce, auditorPublicKey, clientSecretKey)
    
    //send boxed audit message to server A
    n, err = conn.Write(auditCiphertext)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    C.free(unsafe.Pointer(userBits))
    C.free(unsafe.Pointer(nonZeroVectors))
    C.free(unsafe.Pointer(dpfQueryA))
    C.free(unsafe.Pointer(dpfQueryB))
    
    done := make([]byte, 4)
    for count := 0; count < 4; {
        n, err= conn.Read(done[count:])
        count += n
        if err != nil && count != 4{
            log.Println(err)
            log.Println(n)
        }
    }
}
