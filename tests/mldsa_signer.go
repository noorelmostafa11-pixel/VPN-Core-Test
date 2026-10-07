// Independent REALITY PQ test signer using only Go's standard ML-DSA.
package main

import (
	"bufio"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()))
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		message, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			panic(err)
		}
		signature, err := key.Sign(rand.Reader, message, crypto.Hash(0))
		if err != nil {
			panic(err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(signature))
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}
