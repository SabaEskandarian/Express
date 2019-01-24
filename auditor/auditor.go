//initial source code based on denji/golang-tls

package main

/*
#cgo LDFLAGS: -fopenmp -lcrypto -lm
#include "../c/dpf.h"
#include "../c/dpf.c"
*/
import "C"
import (
    "log"
    "crypto/tls"
    "net"
    "time"
    "io"
)

var userBits []byte
var userNonZeros []byte
var serverAInput []byte
var serverBInput []byte
var layers [3]int

func main() {
    log.SetFlags(log.Lshortfile)

    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }

    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    ln, err := tls.Listen("tcp", ":4444", config) //run on a different port than the server for local testing
    if err != nil {
        log.Println(err)
        return
    }
    defer ln.Close()

    for {
        flag1 := make(chan int)
        flag2 := make(chan int)
        flag3 := make(chan int)

        conn, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        conn.SetDeadline(time.Time{})
        go handleConnection(conn, flag1)
        
        conn2, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        conn2.SetDeadline(time.Time{})
        go handleConnection(conn2, flag2)
        
        conn3, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        conn3.SetDeadline(time.Time{})
        go handleConnection(conn3, flag3)
        
        //wait for the connections to be handled
        done1 := <- flag1
        done2 := <- flag2
        done3 := <- flag3
        
        if done1 != 1 || done2 != 1 || done3 != 1 {
            log.Println("something went wrong in getting audit messages")
        }
        
        log.Println(layers[0])
        log.Println(layers[1])
        log.Println(layers[2])
        
        if layers[0] != layers[1] || layers[1] != layers[2] {
            log.Println("disagreement about number of layers!")
        }
        
        //run the auditing
        auditResp := int(C.auditorVerify(C.int(layers[0]), (*C.uchar)(&userBits[0]), (*C.uchar)(&userNonZeros[0]), (*C.uchar)(&serverAInput[0]), (*C.uchar)(&serverBInput[0])));

        //send responses
        flag1 <- auditResp
        flag2 <- auditResp
        flag3 <- auditResp
        
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

func handleConnection(conn net.Conn, flag chan int) {
    defer conn.Close()
    
    //determine who is contacting the auditor
    UorS:= make([]byte, 1)
    n, err:= conn.Read(UorS)
    if err != nil {
        log.Println(err)
    }
        
    //get input
    count := 0
    if UorS[0] == 2 { //user
        
        layersInput := make([]byte, 4)
        for count = 0; count < 4; {
            n, err= conn.Read(layersInput[count:])
            count += n
            if err != nil && count != 4{
                log.Println(err)
                log.Println(n)
            }
        }
        layers[2] = byteToInt(layersInput)
        log.Println(layers[2])
        
        dataTransferSize := layers[2]
        userBits = make([]byte, dataTransferSize)
        for count < dataTransferSize {
            n, err:= conn.Read(userBits[count:])
            count += n
            if err != nil && err != io.EOF && count != dataTransferSize {
                log.Println(err)
            }
        }

        count = 0
        dataTransferSize = layers[2]*16
        userNonZeros = make([]byte, dataTransferSize)
        for count < int(dataTransferSize) {
            n, err:= conn.Read(userNonZeros[count:])
            count += n
            if err != nil && err != io.EOF && count != dataTransferSize {
                log.Println(err)
            }
        }

    } else if UorS[0] == 1 { //server A
        layersInput := make([]byte, 4)
        for count = 0; count < 4; {
            n, err= conn.Read(layersInput[count:])
            count += n
            if err != nil && count != 4{
                log.Println(err)
                log.Println(n)
            }
        }
        layers[1] = byteToInt(layersInput)
        log.Println(layers[1])

        
        dataTransferSize := layers[1]*2*16
        serverAInput = make([]byte, dataTransferSize)
        for count < dataTransferSize {
            n, err:= conn.Read(serverAInput[count:])
            count += n
            if err != nil && err != io.EOF && count != dataTransferSize{
                log.Println(err)
            }
        }
    } else if UorS[0] == 0 { //server B
        layersInput := make([]byte, 4)
        for count = 0; count < 4; {
            n, err= conn.Read(layersInput[count:])
            count += n
            if err != nil && count != 4{
                log.Println(err) 
                log.Println(n)
            }
        }
        layers[0] = byteToInt(layersInput)
        log.Println(layers[0])

        
        dataTransferSize := layers[0]*2*16
        serverBInput = make([]byte, dataTransferSize)
        for count < dataTransferSize {
            n, err:= conn.Read(serverBInput[count:])
            count += n
            if err != nil && err != io.EOF && count != dataTransferSize {
                log.Println(err)
            }
        }
    }
    
    //write to flag saying we got the input
    flag <- 1
    
    //wait for auditor
    auditSuccess:= <- flag
    
    if auditSuccess == 0 {
        log.Println("auditing failed? :(")
        return
    }
    
    //write back to user/server saying auditing succeeded
    auditPass :=make([]byte,1)
    auditPass[0] =byte( auditSuccess)
    n, err = conn.Write(auditPass)
    if err != nil {
        log.Println(n, err)
        return
    }

    return
}
