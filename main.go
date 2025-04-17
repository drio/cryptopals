package main

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func scoreHexStr(inputHex string, b byte) string {
	hexByte := fmt.Sprintf("%02x", b)
	hexKey := strings.Repeat(hexByte, len(inputHex)/2)

	hexMsg := runXOR(inputHex, hexKey)

	bytes, err := hex.DecodeString(hexMsg)
	if err != nil {
		return ""
	}

	asciiMsg := string(bytes)
	if isReadableText(asciiMsg) && scoreText(asciiMsg) > 100 {
		return (fmt.Sprintf("%s %s %s\n", string(b), hexKey, asciiMsg))
	}
	return ""
}

func scoreLoop(inputHex string) {
	for b := byte(32); b <= 126; b++ {
		fmt.Printf(scoreHexStr(inputHex, b))
	}
}

func runSet1Ch3() {
	scoreLoop("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
}

func main() {
	runSet1Ch3()
}
