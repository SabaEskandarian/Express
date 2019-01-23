//initial source code based on denji/golang-tls

package main

/*
#cgo LDFLAGS: -fopenmp -lcrypto -lm
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
)

var auditor string

//TODO: make the servers generate the row ID by themselves from a seed and send it to the client

func main() {
    auditor = "127.0.0.1:4444"

    log.SetFlags(log.Lshortfile)
    
    leader := 0
    if len(os.Args) > 1 {
        leader = 1
    }
    
    C.initializeServer()

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

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        conn.SetDeadline(time.Time{})
        handleConnection(conn, leader)
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

func handleConnection(conn net.Conn, leader int) {
    defer conn.Close()
    
    //determine what kind of connection this is
    connType := make([]byte, 1)
    n, err:= conn.Read(connType)
    if err != nil && n != 1 {
        log.Println(err)
        log.Println(n)
    }
    
    count := 0

    if connType[0] == 1 { //register row

        rowId:=make([]byte, 16)
        dataSize:=make([]byte, 4)
        rowKey:=make([]byte, 16)
        
        count = 0
        //read rowId
        for count < 16 {
            n, err= conn.Read(rowId[count:])
            count += n
            if err != nil && count != 16{
                log.Println(err)
                log.Println(n)
            }
        }
        
        count = 0
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
        newIndex:= C.processnewEntry((*C.uchar)(&rowId[0]), C.int(byteToInt(dataSize)), (*C.uchar)(&rowKey[0]))
        //log.Println(rowKey) 
        //log.Println()
        
        //send the newIndex number back
        n, err=conn.Write(intToByte(int(newIndex)))
        if err != nil {
            log.Println(n, err)
            return
        }
        
        //log.Println(dataSize)
        //log.Println(rowId)
        
    } else if connType[0] == 2 { //read
        
        index:= make([]byte, 4)
        rowId:= make([]byte, 16)
        
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
        //log.Println(index)
        //log.Println(rowId)
        //log.Println(size) 
        
        //make space for responses
        data := make([]byte, size)
        seed := make([]byte, 16)
        
        //get data
        C.readEntry((*C.uchar)(&rowId[0]), C.int(byteToInt(index)), (*C.uchar)(&data[0]), (*C.uchar)(&seed[0]))
        //log.Println(data)
        //log.Println(seed) 
        
        //write seed
        n, err=conn.Write(seed)
        if err != nil {
            log.Println(n, err)
            return
        }
        
        //write data
        n, err:=conn.Write(data)
        if err != nil {
            log.Println(n, err)
            return
        }
        
    } else if connType[0] == 3 { //write
        handleWrite(conn, leader)
    } else {
        log.Println("invalid connection type")
        return
    }
}

func handleWrite(conn net.Conn, leader int) {
    dataTransferSize:= 0 //how big the query from the user is
    dataSize := 0 //how big the data in a row is
    
    count := 0
    //read dataTransferSize
    for count < 4 {
        n, err:= conn.Read(intToByte(dataTransferSize)[count:])
        count += n
        if err != nil && count != 4{
            log.Println(err)
            log.Println(n)
        }
    }
    count = 0
    //read dataSize
    for count < 4 {
        n, err:= conn.Read(intToByte(dataSize)[count:])
        count += n
        if err != nil && count != 4{
            log.Println(err)
            log.Println(n)
        }
    }
        
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
    
    //register the input with c  
    var auditSeed [16]byte
    auditSeed = C.registerQuery((*C.uchar)(&input[0]), C.int(dataSize), C.int(dataTransferSize))
    
    // if leader, send back the seed to the user
    if leader == 1{
        n, err:=conn.Write(auditSeed[:])
        if err != nil {
            log.Println(n, err)
            return
        }
        
        //also send number of layers
        n, err=conn.Write(intToByte(int(C.layers)))
        if err != nil {
            log.Println(n, err)
            return
        }
    }
    
    //process query
    C.processQuery()
    
    //send audit info to auditor
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }

    conn2, err := tls.Dial("tcp", auditor, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn2.Close()
    
    l := make([]byte, 1)
    l[0] = byte(leader)
    n, err := conn2.Write(append(l, C.GoBytes(unsafe.Pointer(&C.outVector), C.layers)...))
    if err != nil {
        log.Println(n, err)
        return
    }

    //read auditor response and give an error if it doesn't accept
    auditResp := make([]byte, 1)
    n, err = conn.Read(auditResp)
    if err != nil && n != 1 {
        log.Println(n, err)
        return
    }
    
    if auditResp[0] != 1 {
        log.Println("Audit Failed.")
    }
    
    return
}
