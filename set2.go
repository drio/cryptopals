package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	mrand "math/rand"
	"net/url"
	"slices"
	"strings"
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
func padPKCS7(plainText []byte, blockSize int) []byte {
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
	output := string(padPKCS7(bi, 20))
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

	paddedPlainText := padPKCS7(plainText, blockSize)
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

	paddedPlainText := padPKCS7(plainText, blockSize)
	cipherText := make([]byte, len(paddedPlainText))
	for i := 0; i < len(paddedPlainText); i += blockSize {
		plainChunk := paddedPlainText[i : i+blockSize]
		block.Encrypt(cipherText[i:i+blockSize], plainChunk)
	}

	return cipherText
}

func decryptECB(ciphertext, key []byte) []byte {
	if len(ciphertext)%aes.BlockSize != 0 {
		log.Fatalf("ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Can't get cipher: %s", err)
	}

	plaintext := make([]byte, len(ciphertext))
	for start := 0; start < len(ciphertext); start += aes.BlockSize {
		block.Decrypt(plaintext[start:start+aes.BlockSize], ciphertext[start:start+aes.BlockSize])
	}

	plaintext = unpadPKCS7(plaintext)
	return plaintext
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

func makeOracle(key, unknownB64 string) func([]byte) []byte {
	unknown, err := base64.StdEncoding.DecodeString(unknownB64)
	if err != nil {
		panic(err)
	}

	return func(input []byte) []byte {
		plain := append(input, unknown...)
		return encryptECB(plain, []byte(key))
	}
}

// encrypt plaintext with AES in ECB mode using key
func AESOracleECBWithPre(pre, plaintext, key []byte) []byte {
	withPre := append(pre, plaintext...)

	cipherText := []byte{}
	cipherText = encryptECB(withPre, key)

	return cipherText
}

func runSet2Ch12() {
	base64Plain := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`
	key := `YELLOW SUBMARINE`

	oracle := makeOracle(key, base64Plain)

	// Part 1: Find the BlockSize size (16)
	detectBlockSize := func() int {
		initialLen := len(oracle([]byte{}))
		for i := range 64 {
			input := bytes.Repeat([]byte("A"), i)
			newLen := len(oracle(input))
			if newLen > initialLen {
				return newLen - initialLen
			}
		}
		panic("could not detect block size")
	}
	blockSize := detectBlockSize()
	fmt.Printf("block size: %d\n", detectBlockSize())

	// Part2: confirm the cipher run in ECB mode
	isECB := func(blockSize int) bool {
		input := bytes.Repeat([]byte("A"), blockSize*3) // 3 identical blocks
		ct := oracle(input)

		// Break into blocks
		seen := make(map[string]bool)
		for i := 0; i < len(ct); i += blockSize {
			block := string(ct[i : i+blockSize])
			if seen[block] {
				return true // duplicate found → ECB
			}
			seen[block] = true
		}
		return false
	}
	if isECB(blockSize) == false {
		panic("Not ECB mode used AES cipher!")
	}
	fmt.Printf("AES cipher in ECB mode. Good.\n")

	// Part 3: This is the fun part. Break the cipherText using some
	// clever techniques that exploit the deficiencies of AES in ECB
	// mode. Mainly the fact that the the same 16-byte plaintext
	// block always encrypts to the same ciphertext block.
	recoverCipherText := func() []byte {
		var recovered []byte
		for {
			// Determine the block index we’re targeting
			currentBlock := len(recovered) / blockSize

			// Run the oracle with the appropriate padding so the byte we
			// are trying to decrypt aligns with the end of the current
			// block
			bytesInBlock := len(recovered) % blockSize
			numPaddingBytes := blockSize - 1 - bytesInBlock
			padding := bytes.Repeat([]byte("A"), numPaddingBytes)
			fullCiphertext := oracle(padding)

			// Let's now get the cipherText values for the block
			// This will be our target block and we want to decrypt the
			// last byte
			start := currentBlock * blockSize
			end := start + blockSize
			if end > len(fullCiphertext) {
				break // Oracle response is shorter than expected; probably done
			}
			targetBlock := fullCiphertext[start:end]

			// Now we have our target block.
			// We know all [0:blockSize-2] bytes we need to decrypt [0:blockSize-1]
			// We know AES(ECB) is deterministic on its output giving the same input.
			// So we can enumerate all possible 255 byte values (guess).
			// We can generate a plainText that looks like:
			// testInput = padding + recovered pt + guess
			// Then we can run AES_ECB on that plainText (testInput) and compare the
			// result to our targetBlock. If targetBlock and testBlock (output) match
			// then we know our guess was correct and that byte is part of the original
			// plain text.
			var found bool
			for guess := range 256 {
				// Construct the input: padding + recovered + guess byte
				testInput := slices.Clone(padding)
				testInput = append(testInput, recovered...)
				testInput = append(testInput, byte(guess))

				// Get ciphertext for this input
				testCiphertext := oracle(testInput)
				testBlock := testCiphertext[start:end]

				if bytes.Equal(testBlock, targetBlock) {
					recovered = append(recovered, byte(guess))
					found = true
					break
				}
			}

			if !found {
				break // No match found — likely end of the unknown string
			}
		}

		return recovered
	}
	fmt.Printf("%s\n", recoverCipherText())
}

// Ch13: part 1: key-value parser
func parseKV(input string) map[string]string {
	values, _ := url.ParseQuery(input)
	result := make(map[string]string)
	for k, v := range values {
		result[k] = v[0] // only take the first value
	}
	return result
}

// Ch13: part 2: generateProfile
func profileFor(email string) string {
	// Strip '&' and '=' to prevent injection
	safeEmail := strings.ReplaceAll(strings.ReplaceAll(email, "&", ""), "=", "")
	return "email=" + safeEmail + "&uid=10&role=user"
}

// Ch13: part 3: encrypt/decrypt profiles using AES-ECB
type profileTool struct {
	key []byte
}

func (pt *profileTool) init() {
	pt.key = genRandomAESKey()
}

func (pt *profileTool) encrypt(profile string) []byte {
	return encryptECB([]byte(profile), pt.key)
}

func (pt *profileTool) decrypt(cipherText []byte) map[string]string {
	queryString := decryptECB([]byte(cipherText), pt.key)
	return parseKV(string(queryString))
}

func runSet2Ch13() {
	// Ch13-part3
	pt := profileTool{}
	pt.init()
	plainText := profileFor("rufus@wonderland.com")
	cipherText := pt.encrypt(plainText)
	fmt.Println("Decrypted profile:")
	for k, v := range pt.decrypt(cipherText) {
		fmt.Printf("  %s: %s\n", k, v)
	}
}
