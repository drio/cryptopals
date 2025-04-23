package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/bits"
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

func scoreText(s string) int {
	// Simple scoring based on common English letter frequencies
	frequencies := map[rune]int{
		'e': 13, 't': 9, 'a': 8, 'o': 7, 'i': 7, 'n': 7,
		's': 6, 'h': 6, 'r': 6, 'd': 4, 'l': 4, 'u': 2,
	}

	score := 0
	for _, r := range strings.ToLower(s) {
		if freq, exists := frequencies[r]; exists {
			score += freq
		}
	}

	return score
}

type score struct {
	score    int
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
			fmt.Printf("%d %s %s %s\n", s.score, s.key, s.hexKey, s.asciiMsg)
		}
	}
}

// same as scoreLoop but only prints the key with the best score
func scoreLoopBest(inputHex string) {
	key := ""
	bestScore := 0
	for b := byte(32); b <= 126; b++ {
		if s := scoreHexStr(inputHex, b); s != nil {
			if s.score > bestScore {
				bestScore = s.score
				key = s.key
			}
		}
	}
	fmt.Printf("%s", key)
}

// encodes a hex string into base64
func hexToBase64(data string) string {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		fmt.Println("Decode error:", err)
		return ""
	}

	sEnc := base64.StdEncoding.EncodeToString([]byte(decoded))
	return sEnc
}

// run xor on a and b
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

	// Step 2:
	if len(aBytes) != len(bBytes) {
		log.Fatalf("Inputs must be of equal length")
	}

	result := make([]byte, len(aBytes))
	for i := 0; i < len(aBytes); i++ {
		result[i] = aBytes[i] ^ bBytes[i]
	}

	// Step 3 (convert to hex) coming next
	return hex.EncodeToString(result)
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
