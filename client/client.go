//initial source code based on denji/golang-tls

package main


/*
#cgo LDFLAGS: -fopenmp -lcrypto -lm
#include "../c/dpf.h"
#include "../c/okvClient.h"
#include "../c/dpf.c"
#include "../c/okvClient.c"
*/
import "C"
import (
    "log"
    "crypto/tls"
)

serverA := "127.0.0.1:4443"
serverB := "127.0.0.1:4442"
auditor := "127.0.0.1:4444"

conf := &tls.Config{
         InsecureSkipVerify: true,
    }

func main() {
    log.SetFlags(log.Lshortfile)
    
    C.initializeClient()
    
    //TODO test operations go here
    
    for i:= 0; i < 1000; i++ {
        addRow(25)
        if i % 100 == 0 {
            log.Println("added 100 rows to db")
        }
    }
}

//functions corresponding to the okvClient.h functions 
//to act as wrappers and do the network communication

//if needed, consider splitting communication with each
//server into a different goroutine so it can happen in parallel

func addRow(dataSize int) {
    connA, err := tls.Dial("tcp", serverA, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer connA.Close()
    connB, err := tls.Dial("tcp", serverB, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer connB.Close()
    
    //allocate space to hold return values
    rowAKey := C.malloc(16)
    rowBKey := C.malloc(16)
    rowId := C.malloc(16)
    
    //Call c function to get the row prepared
    C.prepNewRow(C.int(dataSize), rowId, rowAKey, rowBKey)    
    
    //write the data to each connection
    //1 byte connection type 1
    connType := make([]byte, 1)
    connType[0] = 1
    n, err := connA.Write(connType)
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err := connB.Write(connType)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //16 bytes rowId
    sendRowId := C.GoBytes(rowId, 16)
    n, err := connA.Write(sendRowId)
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err := connB.Write(sendRowId)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //4 bytes dataSize
    sendDataSize := C.int(dataSize)
    n, err := connA.Write(sendDataSize)
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err := connB.Write(sendDataSize)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //16 bytes key
    n, err := connA.Write(C.GoBytes(rowAKey, 16))
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err := connB.Write(C.GoBytes(rowBKey, 16))
    if err != nil {
        log.Println(n, err)
        return
    }
    
    newIndex := make([]byte, 4)
    //read back the new index number
    for count := 0; count < 4 {
        n, err= conn.Read(newIndex[count:])
        if err != nil {
            log.Println(err)
            log.Println(n)
        }
        count += n
    }
    
    C.addIndex(C.int(newIndex))
}

func readRow(localIndex int) ([]byte){
    connA, err := tls.Dial("tcp", serverA, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer connA.Close()
    connB, err := tls.Dial("tcp", serverB, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer connB.Close()
    
    //1 byte connection type 2
    connType := make([]byte, 1)
    connType[0] = 2
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
    
    //write index 4 bytes
    sendIndex := C.int(localIndex)
    n, err = connA.Write(sendIndex)
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err = connB.Write(sendIndex)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write virtual address, 16 bytes
    virtAddr := make([]byte, 16)
    C.getVirtualAddress(localIndex, (*C.uchar)(&virtAddr[0]))
    n, err = connA.Write(virtAddr)
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err = connB.Write(virtAddr)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //read seed
    seedA := make([]byte, 16)
    seedB := make([]byte, 16)
    for count := 0; count < 16 {
        n, err= connA.Read(seedA[count:])
        if err != nil {
            log.Println(err)
            log.Println(n)
        }
        count += n
    }
    for count := 0; count < 16 {
        n, err= connB.Read(seedB[count:])
        if err != nil {
            log.Println(err)
            log.Println(n)
        }
        count += n
    }
    
    //read data
    size := C.db[localIndex].dataSize
    dataA := make([]byte, size)
    dataB := make([]byte, size)
    //read back the new index number
    for count := 0; count < size {
        n, err= conn.Read(dataA[count:])
        if err != nil {
            log.Println(err)
            log.Println(n)
        }
        count += n
    }
    for count := 0; count < size {
        n, err= conn.Read(dataB[count:])
        if err != nil {
            log.Println(err)
            log.Println(n)
        }
        count += n
    }
    
    //decrypt
    //void decryptRow(int localIndex, uint8_t *dataA, uint8_t *dataB, uint8_t *seedA, uint8_t *seedB);
    C.decryptRow(C.int(localIndex), (*C.uchar)(&dataA[0]), (*C.uchar)(&dataB[0]), (*C.uchar)(&seedA[0]), (*C.uchar)(&seedB[0]))

    return C.GoBytes(C.outData, size)
}

func writeRow(localIndex int, data []byte) {
    
    dataSize := len(data)
    querySize := make([]byte, 4)
    
    //prep the query
    C.prepQuery(localIndex, (*C.uchar)(&data[0]), dataSize, (*C.int)(querySize))
    
    //call helper function goroutines to communicate with each party
    go writeRowServerA(dataSize, querySize)
    go writeRowServerB(dataSize, querySize)
    
}

func writeRowServerA(dataSize, querySize int) {
    connA, err := tls.Dial("tcp", serverA, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer connA.Close()
    
    //1 byte connection type 3
    connType := make([]byte, 1)
    connType[0] = 3
    n, err := connA.Write(connType)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write dataTransferSize
    sendDataTransferSize := C.int(querySize)
    n, err := connA.Write(sendDataTransferSize)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write dataSize
    sendDataSize := C.int(dataSize)
    n, err := connA.Write(sendDataSize)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write the query
    sendQuery := C.GoBytes(C.dpfQueryA, querySize)
    n, err := connA.Write(sendQuery)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //read seed and layers from server A
    seed := make([]byte, 16)
    for count := 0; count < 16 {
        n, err= connA.Read(seed[count:])
        if err != nil {
            log.Println(err)
            log.Println(n)
        }
        count += n
    }
    layers := make([]byte, 4)
    for count := 0; count < 4 {
        n, err= connA.Read(layers[count:])
        if err != nil {
            log.Println(err)
            log.Println(n)
        }
        count += n
    }
    
    writeRowAuditor(localIndex, C.int(layers), seed)
    return
}

func writeRowServerB(dataSize, querySize int) {
    
    connB, err := tls.Dial("tcp", serverB, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer connB.Close()
    
    //1 byte connection type 3
    connType := make([]byte, 1)
    connType[0] = 3
    n, err := connB.Write(connType)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write dataTransferSize
    sendDataTransferSize := C.int(querySize)
    n, err := connA.Write(sendDataTransferSize)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write dataSize
    sendDataSize := C.int(dataSize)
    n, err := connA.Write(sendDataSize)
    if err != nil {
        log.Println(n, err)
        return
    }
        
    //write the query
    sendQuery := C.GoBytes(C.dpfQueryB, querySize)
    n, err := connB.Write(sendQuery)
    if err != nil {
        log.Println(n, err)
        return
    }
    return
}

func writeRowAuditor(index int, layers C.int, seed [16]byte) {
    
    //connect to auditor
    conn, err := tls.Dial("tcp", auditor, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()
        
    //prepare the auditor message
    C.prepAudit(C.int(index), layers, (*C.uchar)(&seed[0]))
    
    //send layers to auditor
    n, err := connA.Write(layers)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //send userbits to auditor
    sendBits := C.GoBytes(C.userBits, int(layers))
    n, err := connA.Write(sendBits)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //send nonzero vectors to auditor
    sendVectors := C.GoBytes(C.nonZeroVectors, int(layers)*2*16)
    n, err := connA.Write(sendVectors)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //read success bit
    auditResp := make([]byte, 1)
    n, err = conn.Read(auditResp)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    if success[0] != 1 {
        log.Println("user failed audit")
    }
    return
}
