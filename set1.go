package main

import (
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
	for i := 0; i < len(ba); i++ {
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

type score struct {
	score    float64
	key      string
	hexKey   string
	asciiMsg string
}

// score input Hex string based on chracter frequency
func scoreHexStr(inputHex string, b byte) *score {
	hexByte := fmt.Sprintf("%02x", b)
	hexKey := strings.Repeat(hexByte, len(inputHex)/2)

	hexMsg := runXOR(inputHex, hexKey)

	bytes, err := hex.DecodeString(hexMsg)
	if err != nil {
		return nil
	}

	asciiMsg := string(bytes)

	if isReadableText(asciiMsg) {
		s := scoreText(asciiMsg)
		return &score{s, string(b), hexKey, asciiMsg}
	}
	return nil
}

// enumerate all the printable characters in ascii and score each character
// against the ciphertext
func scoreLoop(inputHex string) {
	for b := byte(32); b <= 126; b++ {
		if s := scoreHexStr(inputHex, b); s != nil {
			fmt.Printf("%2.2f %s %s %s\n", s.score, s.key, s.hexKey, s.asciiMsg)
		}
	}
}

// same as scoreLoop but only prints the key with the best score
func scoreLoopBest(inputHex string) string {
	key := ""
	bestScore := 0.0
	for b := byte(32); b <= 126; b++ {
		if s := scoreHexStr(inputHex, b); s != nil {
			if s.score > bestScore {
				bestScore = s.score
				key = s.key
			}
		}
	}
	return key
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
	for i := 0; i < len(a); i++ {
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

	for i := 0; i < len(s); i++ {
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
		end := i + kSize
		if end > len(cipherBytes) {
			end = len(cipherBytes)
		}
		blocks = append(blocks, cipherBytes[i:end])
	}
	return blocks
}

// given a list of blocks, return another set of blocks that contain
// the nth byte of each block
// [ [ b11, b12] [b21, b22], ...] -> [ [b11, b21, ...], [b12, b22, ...]
func transpose(blocks [][]byte, kSize int) [][]byte {
	tBlocks := [][]byte{}

	for i := 0; i < kSize; i++ { // key index
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

func loadSet1Ch6() []byte {
	content, err := os.ReadFile("data/set1/6.txt")
	if err != nil {
		log.Fatalf("Cannot read file: %s", err)
	}

	contentClean := strings.ReplaceAll(string(content), "\n", "")
	cipherText := strings.ReplaceAll(string(contentClean), "\n", "")
	cipherBytes := getBytesFromBase64(cipherText)

	return cipherBytes
}

// Set1-Part 1: find key size
// make run  | sort -k4,4n
// keysize is 29 for the challenge
func rankKeySizes() {
	cipherBytes := loadSet1Ch6()
	printNormHD(cipherBytes, 4, 40)
}

// Set1-Part 2: with the keysize, now we can find the actual key
func findKeyByTransposing() string {
	cipherBytes := loadSet1Ch6()

	// make run  | cut -c1-20 | grep -E '^[0-9]+' | sort -k1,1nr
	kSize := 29
	blocks := getBlocks(kSize, cipherBytes)
	// for i, value := range blocks {
	// 	fmt.Printf("%d %d\n", i, len(value))
	// }

	tBlocks := transpose(blocks, kSize)
	r := []byte{}
	for _, value := range tBlocks {
		//fmt.Printf("%d %d\n", i, len(value))
		hexValue := hex.EncodeToString(value)
		r = append(r, []byte(scoreLoopBest(hexValue))[0])
	}
	key := string(r)
	return fmt.Sprintf("%s", key)

	// testing
	/*
		fmt.Printf("%d\n", len(cipherBytes))
		s := []byte("aaaabbbbccccdddd")
		nhd := computeBlockHD(s, 4)
		fmt.Printf("%d | %d %d", nhd, s[0], s[1])
	*/
}

func decodePlainText(cipherText, key []byte) []byte {
	plainText := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i++ {
		plainText[i] = cipherText[i] ^ key[i%len(key)]
	}
	return plainText
}
