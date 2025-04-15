package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
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
