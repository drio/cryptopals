package main

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func runSet1Ch3() {
	inputHex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	for b := byte(32); b <= 126; b++ {
		hexByte := fmt.Sprintf("%02x", b)
		hexKey := strings.Repeat(hexByte, len(inputHex)/2)

		hexMsg := runXOR(inputHex, hexKey)

		bytes, err := hex.DecodeString(hexMsg)
		if err != nil {
			continue
		}

		asciiMsg := string(bytes)
		if isReadableText(asciiMsg) && scoreText(asciiMsg) > 100 {
			fmt.Printf("%s %s %s\n", string(b), hexKey, asciiMsg)
		}
	}
}

func main() {
	runSet1Ch3()
}
