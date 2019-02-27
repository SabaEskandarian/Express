//initial source code based on denji/golang-tls

package main

/*
#cgo CFLAGS: -O2
#cgo LDFLAGS: -lcrypto -lm
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
    "golang.org/x/crypto/nacl/box"
    "strings"
)

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
    
    
    //using a deterministic source of randomness for testing
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers/auditors should be known 
    //ahead of time and those would be used
    clientPublicKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("c",10000)))
    if err != nil {
        log.Println(err)
        return
    }    
    s2PublicKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("b",10000)))
    if err != nil {
        log.Println(err)
        return
    }
    _, auditorSecretKey, err := box.GenerateKey(strings.NewReader(strings.Repeat("a",10000)))
    if err != nil {
        log.Println(err)
        return
    }
    
    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println(err)
        }
        conn.SetDeadline(time.Time{})
        
        go handleConnection(conn, auditorSecretKey, clientPublicKey, s2PublicKey)
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

func handleConnection(conn net.Conn, auditorSecretKey, clientPublicKey, s2PublicKey *[32]byte) {
    defer conn.Close()
    
    var userBits []byte
    var userNonZeros []byte
    var serverAInput []byte
    var serverBInput []byte
    var layers [2]int
    
    //read server 1 input
    layersInput := make([]byte, 4)
    for count := 0; count < 4; {
        n, err := conn.Read(layersInput[count:])
        count += n
        if err != nil && count != 4{
            log.Println(err)
            log.Println(n)
            return
        }
    }
    layers[0] = byteToInt(layersInput)
    
    dataTransferSize := layers[1]*2*16
    serverAInput = make([]byte, dataTransferSize)
    for count := 0; count < dataTransferSize; {
        n, err:= conn.Read(serverAInput[count:])
        count += n
        if err != nil && err != io.EOF && count != dataTransferSize{
            log.Println(err)
        }
    }
    
    
    //read, unbox, and parse server 2 input
    s2Input := make([]byte, 24+4+dataTransferSize+box.Overhead)
    for count := 0; count < 24+4+dataTransferSize+box.Overhead; {
        n, err:= conn.Read(s2Input[count:])
        count += n
        if err != nil && err != io.EOF && count != 24+4+dataTransferSize+box.Overhead{
            log.Println(err)
        }
    }
    
    var decryptNonce [24]byte
    copy(decryptNonce[:], s2Input[:24])
    decryptedS2, ok := box.Open(nil, s2Input[24:], &decryptNonce, s2PublicKey, auditorSecretKey)
    if !ok {
        log.Println("Decryption not ok!!")
    } 
    
    layers[1] = byteToInt(decryptedS2[:4])
    
    //serverBInput = make([]byte, dataTransferSize)
    serverBInput = decryptedS2[4:]
    
    
    //read, unbox, and parse client input
    clientDataSize := 24+box.Overhead+layers[0]+layers[0]*16
    clientInput := make([]byte, clientDataSize)
    for count := 0; count < clientDataSize; {
        n, err:= conn.Read(clientInput[count:])
        count += n
        if err != nil && err != io.EOF && count != clientDataSize{
            log.Println(err)
        }
    }
    
    copy(decryptNonce[:], clientInput[:24])
    decryptedClient, ok := box.Open(nil, clientInput[24:],&decryptNonce, clientPublicKey, auditorSecretKey)
    if !ok {
        log.Println("Decryption not ok!!")
    }
    
    //userBits = make([]byte, layers[0])
    userBits = decryptedClient[:layers[0]]
    
    //userNonZeros = make([]byte, layers[0]*16)
    userNonZeros = decryptedClient[layers[0]:]

    
    auditResp := 0
    //run the auditing
    if layers[0] == layers[1]{
        auditResp = int(C.auditorVerify(C.int(layers[0]), (*C.uchar)(&userBits[0]), (*C.uchar)(&userNonZeros[0]), (*C.uchar)(&serverAInput[0]), (*C.uchar)(&serverBInput[0])));
    } else {
        log.Println("values for layers did not match")
    }

    if auditResp == 0 {
        log.Println("auditing failed? :(")
        //return
    }
    
    //send response
    auditPass :=make([]byte,1)
    auditPass[0] = byte(auditResp)
    n, err := conn.Write(auditPass)
    if err != nil {
        log.Println(n, err)
        return
    }
}
