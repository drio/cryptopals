package main

import (
	"bufio"
	"fmt"
	"log"
	"strings"
)

func runSet1Ch3() {
	hexCipherText := `1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736`
	cipherTextBytes := hexToBin(hexCipherText)
	score, rKey := scoreLoopBest(cipherTextBytes)
	plainBytes := runXORBytes(cipherTextBytes, rKey)
	plainText := string(plainBytes)
	fmt.Printf("%2.2f %s\n", score, plainText)
}

func runSet1Ch4() {
	file := loadFile("data/set1/4.txt")
	defer file.Close()

	scanner := bufio.NewScanner(file)

	lineNumber := 1
	bestScore := 0.0
	bestPlainText := ""
	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading line %d: %v", lineNumber-1, err)
		}

		hexCipherText := strings.TrimSuffix(line, "\r")
		cipherTextBytes := hexToBin(hexCipherText)
		if score, rKey := scoreLoopBest(cipherTextBytes); score > bestScore {
			plainBytes := runXORBytes(cipherTextBytes, rKey)
			bestPlainText = string(plainBytes)
			bestScore = score
		}
	}

	// Final check for any errors that might have occurred
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error scanning file: %v", err)
	}

	fmt.Printf("%s", bestPlainText)
}

func runSet1Ch5() {
	stanza := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	fmt.Println(repeatXOR(stanza, "ICE"))
}

func runSet1Ch6(part int) {
	cipherBytes := loadFromFileInBase64("data/set1/6.txt")
	// Set1-Part 1: find key size
	// make run  | sort -k4,4n
	// keysize is 29 for the challenge
	if part == 1 {
		printNormHD(cipherBytes, 4, 40)
	} else {
		keySize := 29
		keyBytes := []byte(findKeyByTransposing(cipherBytes, keySize))
		plainTextBytes := runSliceXOR(cipherBytes, keyBytes)
		fmt.Printf("%s\n", string(plainTextBytes))
	}
}

func main() {
	runSet1Ch6(2)
}
