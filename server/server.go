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
    "io"
    "unsafe"
)

var auditor string

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

func handleConnection(conn net.Conn, leader int) {
    defer conn.Close()
    
    //determine what kind of connection this is
    connType := make([]byte, 1)
    n, err:= conn.Read(connType)
    if err != nil {
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
            if err != nil {
                log.Println(err)
                log.Println(n)
            }
            count += n
        }
        
        count = 0
        //read dataSize 
        for count < 4 {
            n, err= conn.Read(dataSize[count:])
            if err != nil {
                log.Println(err)
                log.Println(n)
            }
            count += n
        }
        
        count = 0
        //read rowKey
        for count < 16 {
            n, err= conn.Read(rowKey[count:])
            if err != nil {
                log.Println(err)
                log.Println(n)
            }
            count += n
        }
        //call C command to register row
        newIndex:= C.processnewEntry((*C.uchar)(&rowId[0]), C.int(ReadInt32Unsafe(dataSize)), (*C.uchar)(&rowKey[0]))
        
        //send the newIndex number back
        n, err=conn.Write(newIndex)
        if err != nil {
            log.Println(n, err)
            return
        }
        
    } else if connType[0] == 2 { //read
        
        index:= make([]byte, 4)
        rowId:= make([]byte, 16)
        
        count = 0
        //read index
        for count < 4 {
            n, err= conn.Read(index[count:])
            if err != nil{
                log.Println(err)
                log.Println(n)
            }
            count += n
        }
        
        count = 0
        //read virtual address
        for count < 16 {
            n, err= conn.Read(rowId[count:])
            if err != nil{
                log.Println(err)
                log.Println(n)
            }
            count += n
        }
        
        //get data size
        size := C.getEntrySize((*C.uchar)(&rowId[0]), C.int(ReadInt32Unsafe(index)))
        
        //make space for responses
        data := make([]byte, size)
        seed := make([]byte, 16)
        
        //get data
        C.readEntry((*C.uchar)(&rowId[0]), C.int(ReadInt32Unsafe(index)), (*C.uchar)(&data[0]), (*C.uchar)(&seed[0]))
        
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
        n, err:= conn.Read(dataTransferSize[count:])
        if err != nil{
            log.Println(err)
            log.Println(n)
        }
        count += n
    }
    count = 0
    //read dataSize
    for count < 4 {
        n, err:= conn.Read(dataSize[count:])
        if err != nil{
            log.Println(err)
            log.Println(n)
        }
        count += n
    }
        
    //get the input
    count= 0
    input := make([]byte, dataTransferSize)
    for count < dataTransferSize {
        n, err:= conn.Read(input[count:])
        if err != nil && err != io.EOF {
            log.Println(err)
        }
        count += n
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
        n, err=conn.Write(C.layers)
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
    if err != nil {
        log.Println(n, err)
        return
    }
    
    if auditResp[0] != 1 {
        log.Println("Audit Failed.")
    }
    
    return
}

//from stackexchange
func ReadInt32Unsafe(b []byte) int32 {
    return *(*int32)(unsafe.Pointer(&b[0]))
}
