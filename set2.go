package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"log"
	mrand "math/rand"
)

// Pad plainText with n bytes based on blockSize using PCKS#7
// Example:
//
//	Padding "YELLOW SUBMARINE" with a blockSize of 20:
//	gives us: "YELLOW SUBMARINE" + "\x04\x04\x04\x04"
//
// Even if the plaintext length is already a multiple of 16, we still add
// a full block of padding (16 bytes). This is required by PKCS#7 so that
// the unpadding logic can always safely determine and strip padding.
func padPCKS7(plainText []byte, blockSize int) []byte {
	padLen := blockSize - (len(plainText) % blockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(plainText, padding...)
}

// Removes PKCS#7 padding.
// It is critical to verify that all padding bytes have the correct value;
// otherwise, we may process invalid data, which can lead to security
// vulnerabilities like padding oracle attacks.
func unpadPKCS7(plainText []byte) []byte {
	if len(plainText) == 0 {
		panic("unpadPKCS7: input is empty")
	}

	padLen := int(plainText[len(plainText)-1])
	if padLen == 0 || padLen > len(plainText) {
		panic("unpadPKCS7: invalid padding")
	}

	// Verify all padding bytes match padLen
	for _, b := range plainText[len(plainText)-padLen:] {
		if int(b) != padLen {
			panic("unpadPKCS7: invalid padding bytes")
		}
	}

	return plainText[:len(plainText)-padLen]
}

func runSet2Ch09() {
	i := "YELLOW SUBMARINE"
	bi := []byte(i)
	output := string(padPCKS7(bi, 20))
	fmt.Printf("input  %x\noutput %x\n", i, output)
}

func getAESCipher(key []byte) cipher.Block {
	if len(key) != 16 {
		log.Fatalf("getAESCipher(): invalid key size: %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	return block
}

// AES-128 CBC mode
// pass innitializion vector
//
// Encrypt:
// For each plaintext block Pᵢ:
//
//	Cᵢ = Encrypt(Pᵢ XOR Cᵢ₋₁)
//
// where C₋₁ is the IV for the first block
func encryptCBC(plainText, key, iv []byte) []byte {
	block := getAESCipher(key)
	blockSize := 16

	paddedPlainText := padPCKS7(plainText, blockSize)
	cipherText := make([]byte, len(paddedPlainText))
	prevBlock := iv

	for i := 0; i < len(paddedPlainText); i += blockSize {
		plainChunk := paddedPlainText[i : i+blockSize]
		xorBlock := xorBytes(plainChunk, prevBlock)
		block.Encrypt(cipherText[i:i+blockSize], xorBlock)
		prevBlock = cipherText[i : i+blockSize]
	}

	return cipherText
}

// Decrypt:
// For each ciphertext block Cᵢ:
//
//	Pᵢ = Decrypt(Cᵢ) XOR Cᵢ₋₁
//
// where C₋₁ is the IV for the first block
func decryptCBC(cipherText, key, iv []byte) []byte {
	blockSize := 16
	block := getAESCipher(key)

	plainText := make([]byte, len(cipherText))
	prevBlock := iv
	for i := 0; i < len(cipherText); i += blockSize {
		cipherChunk := cipherText[i : i+blockSize]

		// decrypt the ciphertext block
		decrypted := make([]byte, blockSize)
		block.Decrypt(decrypted, cipherChunk)

		// XOR with previous cipherText (iv on the first iteration)
		xorBlock := xorBytes(decrypted, prevBlock)

		copy(plainText[i:i+blockSize], xorBlock)

		prevBlock = cipherChunk
	}

	return plainText
}

func runSet2Ch10() {
	//cipherText := loadFromFileInBase64("data/set2/10.txt")
	plainText := []byte(`This is a very important secret and should never shared with anyone`)
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)

	cipherText := encryptCBC(plainText, key, iv)
	result := decryptCBC(cipherText, key, iv)
	unpadResult := unpadPKCS7(result)
	fmt.Printf("inputText : %s\n", plainText)
	fmt.Printf("cipherText: %x\n", cipherText)
	fmt.Printf("result    : %s\n", unpadResult)
}

// encryptECB encrypts plainText with AES in ECB mode
func encryptECB(plainText, key []byte) []byte {
	block := getAESCipher(key)
	blockSize := 16

	paddedPlainText := padPCKS7(plainText, blockSize)
	cipherText := make([]byte, len(paddedPlainText))
	for i := 0; i < len(paddedPlainText); i += blockSize {
		plainChunk := paddedPlainText[i : i+blockSize]
		block.Encrypt(cipherText[i:i+blockSize], plainChunk)
	}

	return cipherText
}

// genRandSlice creates a slice of size between [min, max] with
// random bytes in it
func genRandSlice(min, max int) []byte {
	to := (max - min) + 1
	newSlice := []byte{}
	for range min + mrand.Intn(to) {
		b := make([]byte, 1)
		crand.Read(b)
		newSlice = append(newSlice, b...)
	}
	return newSlice
}

// genRandomAESKey creates a random key for AES
func genRandomAESKey() []byte {
	k := make([]byte, 16)
	for i := range 16 {
		b := make([]byte, 1)
		crand.Read(b)
		k[i] += b[0]
	}
	return k
}

// AESOracle receives a plaintext and:
//  1. randomly decides if to encrypt in ECB or CBC mode.
//  2. prepends and appends 5-10 random bytes to your input
//  3. it uses a new random key (and IV for CBC) every time.
func AESOracle(plaintext []byte) ([]byte, string) {
	// pick a mode
	mode := ""
	if mrand.Intn(2) == 0 {
		mode = "ECB"
	} else {
		mode = "CBC"
	}

	// add random pre / post
	pre := genRandSlice(5, 10)
	pos := genRandSlice(5, 10)
	withPre := append(pre, plaintext...)
	withPrePos := append(withPre, pos...)

	key := genRandomAESKey()
	cipherText := []byte{}
	if mode == "ECB" {
		cipherText = encryptECB(withPrePos, key)
	}

	if mode == "CBC" {
		iv := []byte("IVIVIV SUBMARINE") // TODO: random
		cipherText = encryptCBC(withPrePos, key, iv)
	}

	return cipherText, mode
}

func runSet2Ch11() {
	plainText := bytes.Repeat([]byte("A"), 128)

	// Part 1: we have the oracle implemented
	cipherText, mode := AESOracle(plainText)

	// Part 2: write logic to determine if the oracle used ECB or CBC
	call := ""
	if findBlockDuplicates(genBlocks(cipherText, 16)) > 0 {
		call = "ECB"
	} else {
		call = "CBC"
	}
	// test with: for i in $(seq 1 100); do make run; echo ; done
	if mode != call {
		log.Fatalf("Call did not match the oracle! oracle=%s call=%s plaintext=%x\n", mode, call, plainText)
	}
}
