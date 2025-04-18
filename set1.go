package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/bits"
	"strings"
)

func hamming(a, b string) int {
	if len(a) != len(b) {
		log.Fatalf("different len(): %d ,%d", len(a), len(b))
	}

	ba := []byte(a)
	bb := []byte(b)
	fmt.Printf("-%s\n", ba)
	fmt.Printf("-%s\n", bb)
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

// score input Hex string based on chracter frequency
func scoreHexStr(inputHex string, b byte) string {
	hexByte := fmt.Sprintf("%02x", b)
	hexKey := strings.Repeat(hexByte, len(inputHex)/2)

	hexMsg := runXOR(inputHex, hexKey)

	bytes, err := hex.DecodeString(hexMsg)
	if err != nil {
		return ""
	}

	asciiMsg := string(bytes)
	if isReadableText(asciiMsg) {
		s := scoreText(asciiMsg)
		return (fmt.Sprintf("%d %s %s %s\n", s, string(b), hexKey, asciiMsg))
	}
	return ""
}

func scoreLoop(inputHex string) {
	for b := byte(32); b <= 126; b++ {
		if s := scoreHexStr(inputHex, b); s != "" {
			fmt.Printf("%s", scoreHexStr(inputHex, b))
		}
	}
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
