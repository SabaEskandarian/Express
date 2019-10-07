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
    "io"
    "crypto/rand"
    "golang.org/x/crypto/nacl/box"
    "sync/atomic"
    "strconv"
)

var numThreads int
var numCores int 

func main() {
    auditor := "127.0.0.1:4444"
    serverB := "127.0.0.1:4442"
    numCores = 0
    numThreads = 16
    numRowsSetup := 0
    dataSizeSetup := 160

    log.SetFlags(log.Lshortfile) 
    
    if len(os.Args) < 7 {
        log.Println("usage: serverA [auditorip:port] [serverBip:port] [numThreads] [numCores (set it to 0)] [numRows] [rowDataSize]")
        return
    } else {
        auditor = os.Args[1]
        serverB = os.Args[2]
        numThreads, _ = strconv.Atoi(os.Args[3])
        numCores, _ = strconv.Atoi(os.Args[4])
        numRowsSetup, _ = strconv.Atoi(os.Args[5])
        dataSizeSetup, _ = strconv.Atoi(os.Args[6])
    }
    
    if numCores != 0 {
        numThreads = 1
    }
    
    log.Printf("running with parameters %d %d %d %d\n", numThreads, numCores, numRowsSetup, dataSizeSetup)

    
    C.initializeServer(C.int(numThreads))

    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }
    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    port := ":4443"
    ln, err := tls.Listen("tcp", port, config)  
    if err != nil {
        log.Println(err)
        return
    }
    defer ln.Close()
        
    //first connection for setting up rows
    conn, err := ln.Accept()
    if err != nil {
        log.Println(err)
        //continue
    }
    conn.SetDeadline(time.Time{})
    addRows(1, conn)
    
    //numRowsSetup = 10
    //server sets up a numRows rows on its own
    for i:=0; i < numRowsSetup; i++ {
        var setupRowKey [16]byte
        _, err = rand.Read(setupRowKey[:])
        if err != nil{
            log.Println("couldn't get randomness for row key!")
        }
       // log.Printf("data size %d\n", dataSizeSetup)
        C.processnewEntry(C.int(dataSizeSetup), (*C.uchar)(&setupRowKey[0]))
    }
    
    //no more adding rows after here
    
    var ops uint64
    ops = 0
    
    //create a bunch of channels & workers to handle requests
    blocker := make(chan int)
    blocker2 := make(chan int)
    conns := make(chan net.Conn)
    for i := 0; i < numThreads; i++ {
        go leaderWorker(i, conns, blocker, blocker2, serverB, auditor, &ops)
        <- blocker
    }
    
    go reportThroughput(&ops)    
    
    writeHappened := false
    
    //main loop of writes & reads
    //this implementation needs all writes to be done before a read happens
    //or there might be inconsistent state between servers
    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println(err)
        }
        conn.SetDeadline(time.Time{})
        
        connType := make([]byte, 1)  
        n, err:= conn.Read(connType)
        if err != nil && n != 1 {
            log.Println(err)
            log.Println(n)
        }
        
        if connType[0] == 2 { //read
            
            conf := &tls.Config{
                InsecureSkipVerify: true,
            }
            
            //connect to server B
            connB, err := tls.Dial("tcp", serverB, conf)
            if err != nil {
                log.Println(err)
            }
            
            if writeHappened == true {
                
                //log.Println("write happened")
                for i:= 0; i < numThreads; i++ {
                    //signal workers one at a time by sending them nil connections
                    var nilConn net.Conn
                    conns <- nilConn
                    //wait for workers to come back after xoring into the db
                    <- blocker
                }
                for i:= 0; i < numThreads; i++ {
                    blocker2 <- 1
                }
                
                //tell server B that a write happened
                connType := make([]byte, 1)
                connType[0] = 1
                n, err := connB.Write(connType)
                if err != nil {
                    log.Println(n, err)
                }
                
                //run rerandomization
                C.rerandDB()
                writeHappened = false
            } else {
               //tell server B that a write did not happen
                connType := make([]byte, 1)
                connType[0] = 0
                n, err := connB.Write(connType)
                if err != nil {
                    log.Println(n, err)
                }
            }
            //log.Println("time to handle the read")
            
            //handle the read
            handleLeaderRead(conn, connB)
            
        } else if connType[0] == 3 { //write
            //pass the connection on to a worker
            conns <- conn
            writeHappened = true
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

func reportThroughput(ops *uint64) {
    startTime := time.Now()
    for {
        time.Sleep(time.Second*10)
        elapsedTime := time.Since(startTime)
        opCount := atomic.LoadUint64(ops)
        log.Printf("Time Elapsed: %s; number of writes: %d", elapsedTime, opCount)   
    }
}

func leaderWorker(id int, conns <-chan net.Conn, blocker chan<- int, blocker2 <-chan int, serverB, auditor string, ops *uint64 ) {
    //setup the worker-specific db
    dbSize :=  int(C.dbSize)
    db := make([][]byte, dbSize)
    for i := 0; i < dbSize; i++ {
        db[i] = make([]byte, int(C.db[i].dataSize))
    }
    vector := make([]byte, dbSize*16)
    outVector := make([]byte, 2*int(C.layers)*16)
    writeHappened := false
    
    
    //set up connections to server B and auditor
    conf := &tls.Config{
        InsecureSkipVerify: true,
    }
    
    //connect to server B
    connB, err := tls.Dial("tcp", serverB, conf)
    if err != nil {
        log.Println(err)
        return
    }
    
    //connect to auditor
    connAudit, err := tls.Dial("tcp", auditor, conf)
    if err != nil {
        log.Println(err)
        return
    }
    
    blocker <- 1
    
    for conn := range conns {
        if conn == nil {//this is a read
            //xor the worker's DB into the main DB
            if writeHappened {
                
                //signal serverB worker to xor db into main db
                connType := make([]byte, 4)
                connType[0] = 0
                n, err := connB.Write(connType)
                if err != nil {
                    log.Println(n, err)
                }
                
                for i := 0; i < dbSize; i++ {
                    C.xorIn(C.int(i), (*C.uchar)(&db[i][0]))
                    db[i] = make([]byte, int(C.db[i].dataSize))
                }
            }
            
            //signal that you're done
            blocker <- 1
            <- blocker2
            writeHappened = false
        } else {//this is a write
            writeHappened = true
                        
            //read sizes, query, and boxed query
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
            
            dataTransferSize := byteToInt(in1)
            //dataSize := byteToInt(in2)
            
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
            
            clientInput := make([]byte, 24+dataTransferSize+box.Overhead)
            for count := 0; count < 24+dataTransferSize+box.Overhead; {
                n, err:= conn.Read(clientInput[count:])
                count += n
                if err != nil && err != io.EOF && count != 24+dataTransferSize+box.Overhead{
                    log.Println(err)
                }
            }
            
            
            //generate seed
            var seed [16]byte
            _, err = rand.Read(seed[:])
            if err != nil{
                log.Println("couldn't get randomness for seed!")
            }
            
            blockClient := make(chan int)
            blockS2 := make(chan int)
            
            s2Input := make([]byte, 24+4+(int(C.layers)*2*16)+box.Overhead)

            clientDataSize := 24+box.Overhead+int(C.layers)+int(C.layers)*16
            clientAuditInput := make([]byte, clientDataSize)
            
            go func(){
                //forward sizes, seed, and boxed query to server B
                msg := append(in1, in2...)
                msg = append(msg, seed[:]...)
                msg = append(msg, clientInput...)
                
                n, err:=connB.Write(msg)
                if err != nil {
                    log.Println(n, err)
                    return
                } 

                //read server B boxed audit part
                for count := 0; count < 24+4+(int(C.layers)*2*16)+box.Overhead; {
                    n, err:= connB.Read(s2Input[count:])
                    count += n
                    if err != nil && err != io.EOF && count != 24+4+(int(C.layers)*2*16)+box.Overhead{
                        log.Println(err)
                        return
                    }
                }
                
                blockS2 <- 1
            }()
            
            go func(){
                //send seed and layers to client
                n, err:=conn.Write(append(seed[:], intToByte(int(C.layers))...))
                if err != nil {
                    log.Println(n, err)
                    return
                }
                
                //receive boxed client audit part
                for count := 0; count < clientDataSize; {
                    n, err:= conn.Read(clientAuditInput[count:])
                    count += n
                    if err != nil && err != io.EOF && count != clientDataSize{
                        log.Println(err)
                    }
                }
                
                blockClient <- 1
            }()

            
            //log.Println("done forwarding stuff")
            
            
            if numCores == 0 { //usual case
                //run dpf, xor into local db
                for i:= 0; i < dbSize; i++ {
                    ds := int(C.db[i].dataSize)
                    dataShare := make([]byte, ds)
                    v := C.evalDPF(C.ctx[id], (*C.uchar)(&input[0]), C.db[i].rowID, C.int(ds), (*C.uchar)(&dataShare[0]))
                    copy(vector[i*16:(i+1)*16], C.GoBytes(unsafe.Pointer(&v), 16))
                    for j := 0; j < ds; j++ {
                        db[i][j] = db[i][j] ^ dataShare[j]
                    }
                }
            } else { //edge case for the latency vs cores experiment
                //run dpf, xor into local db
                //spread the eval across goroutines
                parablocker := make(chan int)
                startPoint := 0
                endPoint := dbSize
                for k:=1; k <= numCores; k++{
                    endPoint = k*dbSize/numCores
                    go func(startPoint, endPoint int, vector []byte, db [][]byte) {
                        for i:= startPoint; i < endPoint; i++{
                            ds := int(C.db[i].dataSize)
                            dataShare := make([]byte, ds)
                            v := C.evalDPF(C.ctx[id], (*C.uchar)(&input[0]), C.db[i].rowID, C.int(ds), (*C.uchar)(&dataShare[0]))
                            copy(vector[i*16:(i+1)*16], C.GoBytes(unsafe.Pointer(&v), 16))
                            for j := 0; j < ds; j++ {
                                db[i][j] = db[i][j] ^ dataShare[j]
                            }
                        }
                        parablocker <- 1
                    }(startPoint, endPoint, vector, db)
                    startPoint = endPoint
                }
                for k:= 1; k <= numCores; k++{
                    <-parablocker
                }
            }
            
            //run audit part
            C.serverVerify(C.ctx[id], (*C.uchar)(&seed[0]), C.layers, C.dbSize, (*C.uchar)(&vector[0]), (*C.uchar)(&outVector[0]));
            
            //log.Println("received client audit, ran computation")
            
            <- blockS2
            <- blockClient
            
            //log.Println("received worker audit")
            
            //send audit parts to auditor
            msg := append(intToByte(int(C.layers)), outVector...)
            msg = append(msg, s2Input...)
            msg = append(msg, clientAuditInput...)
            
            n, err := connAudit.Write(msg)
            if err != nil {
                log.Println(n, err)
                return
            }
            
            //log.Println("sent audit materials")
            

            //read auditor response and give an error if it doesn't accept
            auditResp := make([]byte, 1)
            count = 0
            for count < 1 {
                n, err = connAudit.Read(auditResp)
                count += n
                if err != nil && n != 1 {
                    log.Println(n, err)
                    return
                }
            }
            
            if auditResp[0] != 1 {
                log.Println("Audit Failed.")
            }
            
            //send signal that we're done if client is still connected
            done := 1
            go conn.Write(intToByte(done))
            //ignore any error this may return 
            //since sometimes the client will not wait for this
            
            //increment counter
            atomic.AddUint64(ops, 1)
            
            //log.Println("done")
        }
    }
}

func handleLeaderRead(conn, connB net.Conn){
    
    //log.Println("server A is reading")
    
    index:= make([]byte, 4)
    rowId:= make([]byte, 16)
    
    //read index and rowId
    count := 0
    //read index
    for count < 4 {
        n, err:= conn.Read(index[count:])
        count += n
        if err != nil && count != 4{
            log.Println(err)
            log.Println(n)
        }
    }
    
    count = 0
    //read virtual address
    for count < 16 {
        n, err:= conn.Read(rowId[count:])
        count += n
        if err != nil && count != 16{  
            log.Println(err)
            log.Println(n)
        }
    }
    
    //log.Println(index)
    
    //log.Println("server A is forwarding")

    
    //write index 4 bytes
    n, err := connB.Write(index)
    if err != nil {
        log.Println(n, err)
    }
    
    n, err = connB.Write(rowId)
    if err != nil {
        log.Println(n, err)
    }
    
        //log.Println("data forwarded")

    
    //get data size
    size := int(C.getEntrySize((*C.uchar)(&rowId[0]), C.int(byteToInt(index))))

    
    //make space for responses
    data := make([]byte, size)
    seed := make([]byte, 16)

    //get data
    C.readEntry((*C.uchar)(&rowId[0]), C.int(byteToInt(index)), (*C.uchar)(&data[0]), (*C.uchar)(&seed[0]))
        
        //log.Println("waiting on response from server B")
    
    
    //read response from server B
    boxBSize := 24+box.Overhead+16+size
    boxB := make([]byte, boxBSize)
    for count := 0; count < boxBSize; {
        n, err= connB.Read(boxB[count:])
        count += n
        if err != nil && count != boxBSize{
            log.Println(err)
            log.Println(n)
        }
    }
    
    //log.Println(boxB)
    
    //log.Println("now going to write back to client")

        
    //write back seed and data
    //write server A response
    n, err=conn.Write(seed)
    if err != nil {
        log.Println(n, err)
        return
    }
    n, err=conn.Write(data)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    //write server B response
    n, err=conn.Write(boxB)
    if err != nil {
        log.Println(n, err)
        return
    }
    
    connB.Close()
}

func addRows(leader int, conn net.Conn) {
    done := 0
    
    for done == 0{
        connEnd := make([]byte, 1)  
        n, err:= conn.Read(connEnd)
        if err != nil && n != 1 {
            log.Println(err)
            log.Println(n)
        }
        
        if connEnd[0] == 1 {
            conn.Close()
            done = 1
            break
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
