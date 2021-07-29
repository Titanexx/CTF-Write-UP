package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

// https://gist.github.com/tinti/1afe25d09ed918b4b3cf5bea8632e798

func CheckErr(str string, err error) {
	if err != nil {
		fmt.Printf("%s: %s\n", str, err.Error())
		os.Exit(1)
	}
}

func ValidateKeyAndNonce(keyHexStr, nonceHexStr string) ([]byte, []byte, error) {
	key, err := hex.DecodeString(keyHexStr)
	if err != nil {
		return nil, nil, err
	}

	nonce, err := hex.DecodeString(nonceHexStr)
	if err != nil {
		return nil, nil, err
	}

	return key, nonce, nil
}

func Decrypt(key []byte, nonce []byte, cipherHexStr string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	cipherText, err := hex.DecodeString(cipherHexStr)
	if err != nil {
		return "", err
	}

	plainText, err := aesgcm.Open(nil, nonce, []byte(cipherText), nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func main() {
	keyPtr := flag.String("key", "", "cipher key (hex string)")
	cipherTextPtr := flag.String("ciphertext", "", "ciphertext to decrypt (hex string)")
	flag.Parse()

	key, nonce, err := ValidateKeyAndNonce(*keyPtr, (*cipherTextPtr)[:24])
	CheckErr("validate key/nonce", err)

	// fmt.Printf("key: %s\n", key)
	// fmt.Printf("nonce: %s\n", nonce)
	// fmt.Printf("ciphertext: %s\n", (*cipherTextPtr)[24:])

	plainText, err := Decrypt(key, nonce, (*cipherTextPtr)[24:])
	CheckErr("decrypt", err)

	fmt.Printf("%s\n", plainText)
}