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

func main() {
    log.SetFlags(log.Lshortfile)
    
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    
    var indexes []int
    var ids [][16]byte
    var keysA [][16]byte
    var keysB [][16]byte

    conn, err := tls.Dial("tcp", serverA, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()

    n, err := conn.Write([]byte("hello\n"))
    if err != nil {
        log.Println(n, err)
        return
    }

    buf := make([]byte, 100)
    n, err = conn.Read(buf)
    if err != nil {
        log.Println(n, err)
        return
    }

    println(string(buf[:n]))
}

func newRow
