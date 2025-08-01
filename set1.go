package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/bits"
	"os"
	"strings"
)

type resultBlockHD struct {
	sumHD float64
	pairs float64
}

// For each candidate keysize, compute the mean Hamming distance per byte:
//  1. average the HD across all block pairs (removes sample‑size bias)
//  2. divide by the keysize (removes length bias)
//
// TODO: return directly the lowest hamming distance
func printNormHD(text []byte, min, max int) {
	for ks := min; ks <= max; ks++ {
		r := computeBlockHD(text, ks)
		norm := (r.sumHD / r.pairs) / float64(ks)
		fmt.Printf("%2d  %2.0f  %2.0f  %.4f\n",
			ks, r.pairs, r.sumHD, norm)
	}
}

// Compute normalized hamming distances given a list of bytes and size
func computeBlockHD(text []byte, keySize int) resultBlockHD {
	sumHD := 0
	numBlocks := 0
	i := 0
	for {
		j := i + keySize
		if j+keySize >= len(text) {
			break
		}
		ba := text[i:j]
		bb := text[j : j+keySize]

		hmd := hamming(string(ba), string(bb))
		//fmt.Printf("[%s] [%s] %d\n", string(ba), string(bb), hmd)
		sumHD += hmd
		i = j
		numBlocks += 1
	}
	//fmt.Printf("--sumHD: %d\n", sumHD)
	return resultBlockHD{
		float64(sumHD),
		float64(numBlocks - 1),
	}
}

func hamming(a, b string) int {
	if len(a) != len(b) {
		log.Fatalf("different len(): %d ,%d", len(a), len(b))
	}

	ba := []byte(a)
	bb := []byte(b)
	distance := 0
	for i := range ba {
		distance += bits.OnesCount8(ba[i] ^ bb[i])
	}
	return distance
}

// apply the repeating-key XOR rkey against the plaintText
// returns the hex representation of the encrypted result
func repeatXOR(plainText, rkey string) string {
	skey := stringToRepeateKey(rkey)

	xorHexOutput := []string{}
	for i, b := range plainText {
		hb := fmt.Sprintf("%02x", b)
		x := runXOR(hb, skey[i%len(rkey)])
		xorHexOutput = append(xorHexOutput, x)
	}
	output := strings.Join(xorHexOutput, "")
	return output
}

// convert a string to a slice of the hex values of each character so
// it can be use as a repeating key
func stringToRepeateKey(rkey string) []string {
	skey := []string{}
	for _, b := range rkey {
		skey = append(skey, fmt.Sprintf("%02x", b))
	}
	return skey
}

func scoreText(s string) float64 {
	// Simple scoring based on common English letter frequencies
	frequencies := map[rune]float64{
		' ': 0.13, 'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075,
		'n': 0.067, 'i': 0.066, 's': 0.063, 'h': 0.061, 'r': 0.06,
		'd': 0.043, 'l': 0.04, 'u': 0.028, 'c': 0.027, 'm': 0.024,
		'f': 0.022, 'w': 0.02, 'y': 0.02, 'g': 0.02, 'p': 0.019,
		'b': 0.015, 'v': 0.01, 'k': 0.008, 'x': 0.001, 'q': 0.001,
		'j': 0.001, 'z': 0.001,
	}

	score := 0.0
	for _, r := range strings.ToLower(s) {
		if freq, exists := frequencies[r]; exists {
			score += freq
		}
	}

	return score
}

// score input string based on chracter frequency
func scoreStrRepeatKey(cipherText []byte, key []byte) float64 {
	plainBytes := runXORBytes(cipherText, key)
	plainText := string(plainBytes)
	if isReadableText(plainText) {
		s := scoreText(plainText)
		return s
	}
	return 0.0
}

// generate a list of printable ascii bytes
func getPrintableBytes() []byte {
	pb := []byte{}
	for b := byte(32); b <= 126; b++ {
		pb = append(pb, b)
	}
	return pb
}

// given a chunk of bytes, return the repeated key that scores best
func scoreLoopBest(input []byte) (float64, []byte) {
	bestScore := 0.0
	bestKey := []byte{}
	for _, b := range getPrintableBytes() {
		rKey := bytes.Repeat([]byte{b}, len(input))
		if score := scoreStrRepeatKey(input, rKey); score > bestScore {
			bestScore = score
			bestKey = rKey
		}
	}
	return bestScore, bestKey
}

// encodes a hex string into base64
func hexToBase64(data string) string {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		fmt.Printf("Decode error: %s", err)
		return ""
	}

	sEnc := base64.StdEncoding.EncodeToString([]byte(decoded))
	return sEnc
}

// encodes a hex to binary
func hexToBin(data string) []byte {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		log.Fatalf("Decode error: %s ", err)
	}
	return decoded
}

// run xor on a and b
// a and b have to be hex encoded
func runXOR(a string, b string) string {
	// Step 1: hex decode and get the bytes for the inputs
	aBytes, err := hex.DecodeString(a)
	if err != nil {
		log.Fatalf("Failed to decode a: %v", err)
	}

	bBytes, err := hex.DecodeString(b)
	if err != nil {
		log.Fatalf("Failed to decode b: %v", err)
	}

	result := runXORBytes(aBytes, bBytes)

	// Step 3 (convert to hex) coming next
	return hex.EncodeToString(result)
}

func runXORBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		log.Fatalf("Inputs must be of equal length")
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func isReadableText(s string) bool {
	if len(s) == 0 {
		return false
	}

	printableCount := 0
	spaceCount := 0
	letterCount := 0

	for i := range s {
		// Printable ASCII
		if s[i] >= 32 && s[i] <= 126 {
			printableCount++

			// Count spaces
			if s[i] == 32 {
				spaceCount++
			}

			// Count letters
			if (s[i] >= 65 && s[i] <= 90) || (s[i] >= 97 && s[i] <= 122) {
				letterCount++
			}
		}
	}

	// Criteria for readable text:
	// 1. At least 90% printable characters
	// 2. At least one space (to suggest multiple words)
	// 3. At least some letters
	return float64(printableCount)/float64(len(s)) > 0.9 &&
		spaceCount > 0 &&
		float64(letterCount)/float64(len(s)) > 0.1
}

func getBytesFromBase64(a string) []byte {
	aBytes, err := base64.StdEncoding.DecodeString(a)
	if err != nil {
		log.Fatalf("Failed to decode base64: %v", err)
	}
	return aBytes
}

func getBytesFromHex(hexStr string) []byte {
	// Decode the hex string to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
	}
	return bytes
}

// given a cipherText return all the blocks of kSize
func getBlocks(kSize int, cipherBytes []byte) [][]byte {
	blocks := [][]byte{}
	for i := 0; i < len(cipherBytes); i = i + kSize {
		//fmt.Printf("%d %s\n", i, string(cipherBytes[i]))
		end := min(i+kSize, len(cipherBytes))
		blocks = append(blocks, cipherBytes[i:end])
	}
	return blocks
}

// given a list of blocks, return another set of blocks that contain
// the nth byte of each block
// [ [ b11, b12] [b21, b22], ...] -> [ [b11, b21, ...], [b12, b22, ...]
func transpose(blocks [][]byte, kSize int) [][]byte {
	tBlocks := [][]byte{}

	for i := range kSize {
		tmpBlock := []byte{}
		for _, block := range blocks { // block
			if i >= len(block) {
				break
			}
			tmpBlock = append(tmpBlock, block[i])
		}
		tBlocks = append(tBlocks, tmpBlock)
	}

	return tBlocks
}

func loadFromFileInBase64(fn string) []byte {
	content, err := os.ReadFile(fn)
	if err != nil {
		log.Fatalf("Cannot read file: %s", err)
	}

	contentClean := strings.ReplaceAll(string(content), "\n", "")
	cipherText := strings.ReplaceAll(string(contentClean), "\n", "")
	cipherBytes := getBytesFromBase64(cipherText)

	return cipherBytes
}

// given a ciphertext and a key size find the actual key
func findKeyByTransposing(cipherBytes []byte, kSize int) string {
	blocks := getBlocks(kSize, cipherBytes)

	tBlocks := transpose(blocks, kSize)
	r := []byte{}
	for _, value := range tBlocks {
		_, keyBytes := scoreLoopBest(value)
		r = append(r, keyBytes[0])
	}
	key := string(r)
	return fmt.Sprintf("%s", key)
}

// apply a key that is smaller than the input chunk by XORing repeatedly
func runSliceXOR(cipherText, key []byte) []byte {
	plainText := make([]byte, len(cipherText))
	for i := range cipherText {
		plainText[i] = cipherText[i] ^ key[i%len(key)]
	}
	return plainText
}

// XOR two strings
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		log.Fatalf("Inputs must be of equal length")
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func runSet1Ch3() {
	hexCipherText := `1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736`
	cipherTextBytes := hexToBin(hexCipherText)
	score, rKey := scoreLoopBest(cipherTextBytes)
	plainBytes := runXORBytes(cipherTextBytes, rKey)
	plainText := string(plainBytes)
	fmt.Printf("%2.2f %s\n", score, plainText)
}

func runSet1Ch4() {
	bestScore := 0.0
	bestPlainText := ""
	eachLine("data/set1/4.txt", func(line string, lineNum int) {
		hexCipherText := strings.TrimSuffix(line, "\r")
		cipherTextBytes := hexToBin(hexCipherText)
		if score, rKey := scoreLoopBest(cipherTextBytes); score > bestScore {
			plainBytes := runXORBytes(cipherTextBytes, rKey)
			bestPlainText = string(plainBytes)
			bestScore = score
		}
	})

	fmt.Printf("%s", bestPlainText)
}

func runSet1Ch5() {
	stanza := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	fmt.Println(repeatXOR(stanza, "ICE"))
}

func runSet1Ch6(part int) {
	cipherBytes := loadFromFileInBase64("data/set1/6.txt")
	// Set1-Part 1: find key size
	// make run  | sort -k4,4n
	// keysize is 29 for the challenge
	if part == 1 {
		printNormHD(cipherBytes, 4, 40)
	} else {
		keySize := 29
		keyBytes := []byte(findKeyByTransposing(cipherBytes, keySize))
		plainTextBytes := runSliceXOR(cipherBytes, keyBytes)
		fmt.Printf("%s\n", string(plainTextBytes))
	}
}

// AES-128 (cipher)
// Mode in which we use AES-128: ECB (Electronic Codebook)
// In ECB mode:
// 1. plaintext is divided into keysize blocks.
// 2. Each block is encrypted independently using the same key.
func runSet1Ch7() {
	cipherText := loadFromFileInBase64("data/set1/7.txt")
	key := []byte("YELLOW SUBMARINE")
	blockSize := len(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	dst := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i += blockSize {
		block.Decrypt(dst[i:i+blockSize], cipherText[i:i+blockSize])
	}

	fmt.Printf("%s\n", dst)
}

// genBlocks returns byte blocks of blockSize from data
func genBlocks(data []byte, blockSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(data); i += blockSize {
		end := min(i+blockSize, len(data))
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// findBlockDuplicates counts the number of blocks that are duplicates
func findBlockDuplicates(blocks [][]byte) int {
	mapDuplicates := make(map[string]int)
	totalDupCount := 0

	for _, block := range blocks {
		mapDuplicates[string(block)] += 1
	}

	for _, count := range mapDuplicates {
		if count > 1 {
			totalDupCount += count - 1
		}
	}

	return totalDupCount
}

func runSet1Ch8() {
	blockSize := 16
	bestLine := ""
	bestCount := 0

	eachLine("data/set1/8.txt", func(line string, lineNum int) {
		lineBytes := hexToBin(line)
		totalDupCount := findBlockDuplicates(genBlocks(lineBytes, blockSize))

		if totalDupCount > bestCount {
			bestCount = totalDupCount
			bestLine = line
		}
	})

	fmt.Printf("%d %s\n", bestCount, bestLine)
}

func toHex(sBytes []byte) string {
	return fmt.Sprintf("%02x", sBytes)
}

func loadFile(fn string) *os.File {
	file, err := os.Open(fn)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	return file
}

func readFileToMemory(filePath string) []byte {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("error reading file: %s", err)
	}
	return data
}

func eachLine(fn string, cb func(string, int)) {
	file := loadFile(fn)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading line %d: %v", lineNumber-1, err)
		}
		cb(line, lineNumber)
	}

	// Final check for any errors that might have occurred
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error scanning file: %v", err)
	}
}
