package main

import (
    "bufio"
    "crypto/rand"
    "encoding/hex"
    "flag"
    "fmt"
    "log"
    "math/big"
    "net"
    "os"
)

const (
    MIN_PORT = 1024
    MAX_PORT = 65535
    KEY_SIZE = 32
)

func main() {
    var port int
    var keyPath string

    flag.IntVar(&port, "p", 1024, "port (1024-65535)")
    flag.StringVar(&keyPath, "k", "", "keys")

    flag.Parse()

    if port < MIN_PORT || port > MAX_PORT {
        log.Fatal("invalid port")
    }

    if len(keyPath) <= 0 {
        log.Fatal("no keys file") 
    }
    
    file, err := os.Open(keyPath)

    if err != nil {
       log.Fatal(err) 
    }

    scanner := bufio.NewScanner(file)

    var keys [32][]byte

    for scanner.Scan() {
        keys[0], err = hex.DecodeString(scanner.Text())
        
        if err != nil {
            log.Fatal(err)
        }
    }

    file.Close()
    err = scanner.Err()

    if err != nil {
        log.Fatal(err)
    }

    address := fmt.Sprintf(":%d", port)
    listener, err := net.Listen("tcp", address)

    if err != nil {
        log.Fatal(err)
    }

    for {
        conn, err := listener.Accept()

        if err != nil {
            log.Fatal(err)    
        }

        id, err := bufio.NewReader(conn).ReadByte()

        fmt.Printf("Id: %d\n", id)

        go verify(conn, keys[id])
    }
}

func verify(conn net.Conn, key []byte) {
    // generate nonce
    nonce, err := rand.Int(rand.Reader, big.NewInt(27))

    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Nonce: %v\n", nonce)

    // challenge
    fmt.Fprintf(conn, "Test")

    // decrypt
    enc, err := bufio.NewReader(conn).ReadBytes('\n')

    /*
    if err != nil {
        log.Fatal(err)
    }
    */

    fmt.Printf("Enc: %v", enc)
}
