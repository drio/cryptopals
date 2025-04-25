package main

import (
	"fmt"
	"log"
	"os"
)

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
