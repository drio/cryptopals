package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func runSet1Ch3() {
	scoreLoop("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
}

func runSet1Ch4() {
	file, err := os.Open("data/set1/4.txt")
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	lineNumber := 1
	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading line %d: %v", lineNumber-1, err)
		}

		line = strings.TrimSuffix(line, "\r")
		scoreLoop(line)
	}

	// Final check for any errors that might have occurred
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error scanning file: %v", err)
	}
}

func runSet1Ch5() {
	stanza := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	fmt.Println(repeatXOR(stanza, "ICE"))
}

func decodePlainText(cipherText, key []byte) []byte {
	plainText := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i++ {
		plainText[i] = cipherText[i] ^ key[i%len(key)]
	}
	return plainText
}

func main() {
	cipherBytes := loadSet1Ch6()
	keyBytes := []byte(findKeyByTransposing())
	plainTextBytes := decodePlainText(cipherBytes, keyBytes)
	fmt.Printf("%s\n", string(plainTextBytes))
}
