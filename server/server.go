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
)


func main() {
    auditor := "127.0.0.1:4444"
    serverB := "127.0.0.1:4442"
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
        if leader == 1 {
            go leaderWorker(i, conns, blocker)
        } else {
            go worker(i, conns, blocker)
        }
    }
    
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
            
            for i:= 0; i < numThreads; i++ {
                //signal workers one at a time by sending them nil connections
                var nilConn net.Conn
                conns <- nilConn
                //wait for workers to come back after xoring into the db
                <- blocker
            }
            
            //run rerandomization
            C.rerandDB()
            
            //handle the read
            handleRead(conn, leader)
            
        } else if connType[0] == 3 { //write
            //pass the connection on to a worker
            conns <- conn
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

func leaderWorker(id int, conns <-chan net.Conn, blocker chan<- int) {
    for conn := range conns {
        //TODO handle connection
    }
}

func worker(id int, conns <-chan net.Conn, blocker chan<- int) {
    //TODO setup the worker-specific db
    
    for conn := range conns {        
        if conn == nil {//this is a read
            //TODO xor the worker's DB into the main DB
            
            //signal that you're done
            blocker <- 1
        } else {//this is a write
            //TODO handle write
            
        }
    }
}

func handleRead(conn net.Conn, leader int){
    //TODO
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

func handleConnection(conn net.Conn, leader int, conn2 *tls.Conn) {
    defer conn.Close()
    for{
        //determine what kind of connection this is
        connType := make([]byte, 1)  
        n, err:= conn.Read(connType)
        if err != nil && n != 1 {
            log.Println(err)
            log.Println(n)
        }
         
        //log.Println("handling a connection of type ")
        //log.Println(connType[0])
        
        count := 0

        if connType[0] == 1 { //register row

            dataSize:=make([]byte, 4)
            rowKey:=make([]byte, 16)
            
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
            newIndex:= C.processnewEntry(C.int(byteToInt(dataSize)), (*C.uchar)(&rowKey[0]))
            //log.Println(rowKey) 
            //log.Println() 
            
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
            handleWrite(conn, leader, conn2)
        } else {
            log.Println("invalid connection type")
            return
        }
    }
}

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
