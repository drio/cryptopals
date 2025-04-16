package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

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
