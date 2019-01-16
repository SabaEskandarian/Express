//source code based on denji/golang-tls

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
    "strconv"
    "time"
    "io"
    "unsafe"
)

func main() {
    log.SetFlags(log.Lshortfile)
    
    expSetup, err := strconv.Atoi(os.Args[1])//which setup to use
    if err != nil {
        log.Println("error: can't read experiment number")
    }
    leader := 0
    if len(os.Args) > 2 {
        leader = 1
    }
    
    C.initializeServer(C.int(expSetup))

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
        handleConnection(conn, expSetup, leader)
    }
}

func handleConnection(conn net.Conn, experiment int, leader int) {
    defer conn.Close()
    
    //these will be set by experiment
    dataTransferSize:= 0
    dataSize := 0
    switch experiment {//TODO
        case 1:
            
        case 2:
            
        case 3:
            
        case 4:
            
        case 5:
            
    }
    
    //get the input
    count:= 0
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
    }
    
    //process query
    C.processQuery()
    
    //send audit info to auditor
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }

    conn2, err := tls.Dial("tcp", "127.0.0.1:4444", conf)
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
