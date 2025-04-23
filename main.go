package main

import (
	"bufio"
	"encoding/hex"
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

func runSet1Ch6Part1() []byte {
	content, err := os.ReadFile("data/set1/6.txt")
	if err != nil {
		log.Fatalf("Cannot read file: %s", err)
	}

	contentClean := strings.ReplaceAll(string(content), "\n", "")
	cipherText := strings.ReplaceAll(string(contentClean), "\n", "")
	cipherBytes := getBytesFromBase64(cipherText)
	return cipherBytes
}

func main() {
	cipherBytes := runSet1Ch6Part1()
	//printNormHD(cipherBytes, 4, 40)
	// make run  | sort -k4,4n

	kSize := 29
	blocks := getBlocks(kSize, cipherBytes)
	// for i, value := range blocks {
	// 	fmt.Printf("%d %d\n", i, len(value))
	// }

	tBlocks := transpose(blocks, kSize)
	for _, value := range tBlocks {
		//fmt.Printf("%d %d\n", i, len(value))
		hexValue := hex.EncodeToString(value)
		scoreLoopBest(hexValue)
	}
	fmt.Printf("\n")
	// make run  | cut -c1-20 | grep -E '^[0-9]+' | sort -k1,1nr

	// testing
	/*
		fmt.Printf("%d\n", len(cipherBytes))
		s := []byte("aaaabbbbccccdddd")
		nhd := computeBlockHD(s, 4)
		fmt.Printf("%d | %d %d", nhd, s[0], s[1])
	*/
}
