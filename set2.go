package main

import (
	"bytes"
	"fmt"
)

// Pad plainText with n bytes based on blockSize using PCKS#7
// Example:
//
//	Padding "YELLOW SUBMARINE" with a blockSize of 20:
//	gives us: "YELLOW SUBMARINE" + "\x04\x04\x04\x04"
func padBlock(plainText []byte, blockSize int) []byte {
	padLen := blockSize - len(plainText)
	numPadBytes := byte(padLen)
	padding := bytes.Repeat([]byte{byte(numPadBytes)}, padLen)
	padded := append(plainText, padding...)

	return padded
}

func runSet2Ch09() {
	i := "YELLOW SUBMARINE"
	bi := []byte(i)
	output := string(padBlock(bi, 20))
	fmt.Printf("input  %x\noutput %x\n", i, output)
}
