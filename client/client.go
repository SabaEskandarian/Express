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
    "unsafe"
)

var serverA string
var serverB string
var auditor string

func main() {
     
    serverA = "127.0.0.1:4443"
    serverB = "127.0.0.1:4442"
    auditor = "127.0.0.1:4444"
    
    
    log.SetFlags(log.Lshortfile)
    
    C.initializeClient()
    
    //TODO test operations go here
    
    for i:= 0; i < 30; i++ {
        addRow(25) 
    }
      
    rowVal := readRow(13)
    log.Println("rowVal 13 is ")
    log.Println(rowVal)
    
    msg := []byte("this is the message!")
    writeRow(13, msg)
    log.Println("wrote message")
    /*
    rowVal = readRow(11)
    log.Println("rowVal 11 is ")
    log.Println(rowVal)    
    
    rowVal = readRow(13)
    log.Println("rowVal 13 is ")
    log.Println(rowVal)
    
    rowVal = readRow(11)
    log.Println("rowVal 11 is ")
    log.Println(rowVal)    
    
    rowVal = readRow(13)
    log.Println("rowVal 13 is ")
    log.Println(rowVal)
    */
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

//functions corresponding to the okvClient.h functions 
//to act as wrappers and do the network communication

//if needed, consider splitting communication with each
//server into a different goroutine so it can happen in parallel

func addRow(dataSize int) {
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
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
    //1 byte connection type 1
    connType := make([]byte, 1) 
    connType[0] = 1
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

func readRow(localIndex int) ([]byte){
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    connA, err := tls.Dial("tcp", serverA, conf)
    if err != nil {
        log.Println(err)
    }
    defer connA.Close()
    connB, err := tls.Dial("tcp", serverB, conf)
    if err != nil {
        log.Println(err)
    }
    defer connB.Close()
    
    //1 byte connection type 2
    connType := make([]byte, 1)
    connType[0] = 2
    n, err := connA.Write(connType)
    if err != nil {
        log.Println(n, err)
    }
    n, err = connB.Write(connType)
    if err != nil {
        log.Println(n, err)
    }
    
    //write index 4 bytes
    sendIndex := intToByte(localIndex)
    n, err = connA.Write(sendIndex)
    if err != nil {
        log.Println(n, err)
    }
    n, err = connB.Write(sendIndex)
    if err != nil {
        log.Println(n, err)
    }
    
    //write virtual address, 16 bytes
    //virtAddr := make([]byte, 16)
    //C.getVirtualAddress(C.int(localIndex), (*C.uchar)(&virtAddr[0]))
    virtAddr := C.GoBytes(unsafe.Pointer(&(C.db[localIndex].rowID)), 16)
    n, err = connA.Write(virtAddr)
    if err != nil {
        log.Println(n, err)
    }
    n, err = connB.Write(virtAddr)
    if err != nil {
        log.Println(n, err)
    }
    
    //read seed  
    seedA := make([]byte, 16)
    seedB := make([]byte, 16)
    for count := 0; count < 16; {
        n, err= connA.Read(seedA[count:])
        count += n
        if err != nil && count != 16{
            log.Println(err)
            log.Println(n)
        }
    }
    for count := 0; count < 16; {
        n, err= connB.Read(seedB[count:])
        count += n
        if err != nil && count != 16{
            log.Println(err)
            log.Println(n)
        }
    }
    
    //read data 
    size := C.db[localIndex].dataSize
    dataA := make([]byte, size)
    dataB := make([]byte, size)
    for count := 0; count < int(size); {
        n, err= connA.Read(dataA[count:])
        count += n
        if err != nil && count != int(size){
            log.Println(err)
            log.Println(n)
        }
    }
    for count := 0; count < int(size); {
        n, err= connB.Read(dataB[count:])
        count += n
        if err != nil && count != int(size){
            log.Println(err)
            log.Println(n)
        }
    }
    
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

func writeRow(localIndex int, data []byte) {
    
    dataSize := len(data)
    querySize := make([]byte, 4)
    
    //prep the query
    cIntQuerySize := C.int(byteToInt(querySize))
    C.prepQuery(C.int(localIndex), (*C.uchar)(&data[0]), C.int(dataSize), &cIntQuerySize)
    
    //call helper function goroutines to communicate with each party
    intQuerySize := int(cIntQuerySize)//byteToInt(querySize)
    
    flag1 := make(chan int)
    flag2 := make(chan int)

    go writeRowServerA(dataSize, intQuerySize, localIndex, flag1)
    go writeRowServerB(dataSize, intQuerySize, flag2)
    
    //wait for connections to be handled before returning
    done1 := <- flag1
    done2 := <- flag2
    
    if done1 != 1 || done2 != 1 {
        log.Println("something strange happened :(")
    }
}

func writeRowServerA(dataSize, querySize int, localIndex int, flag chan int) {
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
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
    
    //log.Println(dataSize)
    //log.Println(querySize)
    
    //write dataTransferSize
    n, err = connA.Write(intToByte(querySize))
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write dataSize
    n, err = connA.Write(intToByte(dataSize))
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write the query
    sendQuery := C.GoBytes(unsafe.Pointer(C.dpfQueryA), C.int(querySize))
    n, err = connA.Write(sendQuery)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //read seed and layers from server A
    seed := make([]byte, 16)
    for count := 0; count < 16; {
        n, err= connA.Read(seed[count:])
        count += n
        if err != nil && count != 16{
            log.Println(err)
            log.Println(n)
        }
    }
    layers := make([]byte, 4)
    for count := 0; count < 4; {
        n, err= connA.Read(layers[count:])
        count += n
        if err != nil && count != 4{
            log.Println(err)
            log.Println(n)
        }
    }
    
    writeRowAuditor(localIndex, C.int(byteToInt(layers)), seed)
    flag <- 1
    return
}

func writeRowServerB(dataSize, querySize int, flag chan int) {
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
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
    n, err = connB.Write(intToByte(querySize))
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write dataSize
    n, err = connB.Write(intToByte(dataSize))
    if err != nil {
        log.Println(n, err)
        return
    }
        
    //write the query
    sendQuery := C.GoBytes(unsafe.Pointer(C.dpfQueryB), C.int(querySize))
    n, err = connB.Write(sendQuery)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    flag <- 1
    
    return
}

func writeRowAuditor(index int, layers C.int, seed []byte) {
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
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
    n, err := conn.Write(intToByte(int(layers)))
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //send userbits to auditor
    sendBits := C.GoBytes(unsafe.Pointer(&(C.userBits[0])), layers)
    n, err = conn.Write(sendBits)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //send nonzero vectors to auditor
    sendVectors := C.GoBytes(unsafe.Pointer(&(C.nonZeroVectors[0])), layers*2*16)
    n, err = conn.Write(sendVectors)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //read success bit
    auditResp := make([]byte, 1)
    n, err = conn.Read(auditResp)
    if err != nil && n != 1{
        log.Println(n, err)
        return
    }
    
    if auditResp[0] != 1 {
        log.Println("user failed audit")
    }
    return
}
