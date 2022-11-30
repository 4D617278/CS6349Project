package main

import (
    "bufio"
    "bytes"
    "crypto/rand"
    "encoding/hex"
    "flag"
    "fmt"
    "golang.org/x/crypto/nacl/box"
    "golang.org/x/crypto/curve25519"
    "io"
    "log"
    "net"
    "os"
)

const (
    MIN_PORT = 1024
    MAX_PORT = 65535
)

func check(err error) {
    if err != nil {
        log.Fatal(err)
    }
}

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

    hexBytes, err := os.ReadFile(keyPath)
    check(err)

    hexArray := bytes.Split(hexBytes, []byte{'\n'})
    keys := make([][curve25519.ScalarSize]byte, len(hexArray))

    for i := 0; i < len(hexArray); i++ {
        n, err := hex.Decode(keys[i][:], hexArray[i])
        check(err)    

        if n != curve25519.ScalarSize {
            log.Fatal("Bad key")
        }
    }

    address := fmt.Sprintf(":%d", port)
    listener, err := net.Listen("tcp", address)
    check(err)

    for {
        conn, err := listener.Accept()
        check(err)

        id, err := bufio.NewReader(conn).ReadByte()

        go verify(conn, keys[0], keys[id])
    }
}

func verify(conn net.Conn, pubKey [32]byte, key [32]byte) {
    var test [24]byte
    var nonce [24]byte

    _, err := io.ReadFull(rand.Reader, test[:])
    check(err)

    conn.Write(test[:])

    enc := make([]byte, 64)
    reader := bufio.NewReader(conn)

    _, err = io.ReadFull(reader, enc)
    check(err)

    copy(nonce[:], enc[:len(nonce)])

    // decrypt
    msg, valid := box.Open(nil, enc[len(nonce):], &nonce, &pubKey, &key)

    if valid && bytes.Equal(test[:], msg[:]) {
        fmt.Println("Valid")
    } else {
        fmt.Println("Invalid")
    }
}
