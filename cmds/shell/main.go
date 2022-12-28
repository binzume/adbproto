package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/binzume/adbproto"
)

func loadRsaKey(keyPath string) (*rsa.PrivateKey, error) {
	pemData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parseResult.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Invalid key type")
	}
	return key, nil
}

func main() {
	homeDir, _ := os.UserHomeDir()
	adb := flag.String("t", "localhost:5555", "adb device (host:port)")
	adbKey := flag.String("k", filepath.Join(homeDir, ".android/adbkey"), "RSA Private key file for ADB")
	flag.Parse()

	dest := "shell:"
	if flag.NArg() > 0 {
		dest = flag.Arg(0) + ":" + strings.Join(flag.Args()[1:], " ")
	}

	key, err := loadRsaKey(*adbKey)
	if err != nil {
		log.Println("Failed to load rsa key file: ", err)
	}

	conn, err := net.Dial("tcp", *adb)
	if err != nil {
		log.Fatal("Failed to connect ", *adb, err)
	}
	defer conn.Close()

	adbconn, err := adbproto.Connect(conn, key)
	if err != nil {
		log.Fatal("Failed to connect adb ", err)
	}
	defer adbconn.Close()

	stream, err := adbconn.Open(dest)
	if err != nil {
		log.Fatal("Failed to start ", dest, err)
	}
	defer stream.Close()

	// std-in/out
	go func() {
		io.Copy(stream, os.Stdin) // TODO: WithContext
	}()
	io.Copy(os.Stdout, stream)
}
