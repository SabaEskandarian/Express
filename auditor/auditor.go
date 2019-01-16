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
    "bufio"
)

func main() {
    log.SetFlags(log.Lshortfile)
    
    expSetup, err := strconv.Atoi(os.Args[1])//which setup to use
    if err != nil {
        log.Println("error: can't read experiment number")
    }
    
    layers := 0 //this will be set by expSetup
    switch expSetup {//TODO
        case 1: 
            
        case 2:
            
        case 3:
            
        case 4:
            
        case 5:
            
    }
    
    userInput := make([]byte, layers+layers*128)
    serverAInput := make([]byte, 2*128*layers)
    serverBInput := make([]byte, 2*128*layers)
    userIn := false
    serverAIn := false
    serverBIn := false

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
        conn, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        conn.SetDeadline(time.Time{})
        go handleConnection(conn, layers)
    }
}

func handleConnection(conn net.Conn, layers int) {
    
    
    /*
     
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
     
     */
    
    defer conn.Close()

    return
}
