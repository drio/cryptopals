package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
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
func padBlock(plainText []byte, blockSize int) []byte {
	padLen := blockSize - (len(plainText) % blockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(plainText, padding...)
}

func runSet2Ch09() {
	i := "YELLOW SUBMARINE"
	bi := []byte(i)
	output := string(padBlock(bi, 20))
	fmt.Printf("input  %x\noutput %x\n", i, output)
}

func getAESCipher(key []byte) cipher.Block {
	if len(key) != 16 {
		log.Fatal("invalid key size")
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

	paddedPlainText := padBlock(plainText, blockSize)
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
	fmt.Printf("inputText : %s\n", plainText)
	fmt.Printf("cipherText: %x\n", cipherText)
	fmt.Printf("result    : %s\n", result)
}
