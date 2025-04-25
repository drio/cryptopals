package main

import (
	"fmt"
)

func runSet1Ch3() {
	hexCipherText := `1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736`
	cipherTextBytes := hexToBin(hexCipherText)
	score, rKey := scoreLoopBest(cipherTextBytes)
	plainBytes := runXORBytes(cipherTextBytes, rKey)
	plainText := string(plainBytes)
	fmt.Printf("%2.2f %s\n", score, plainText)
}

// func runSet1Ch4() {
// 	file, err := os.Open("data/set1/4.txt")
// 	if err != nil {
// 		log.Fatalf("Error opening file: %v", err)
// 	}
// 	defer file.Close()
//
// 	scanner := bufio.NewScanner(file)
//
// 	lineNumber := 1
// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		lineNumber++
// 		if err := scanner.Err(); err != nil {
// 			log.Fatalf("Error reading line %d: %v", lineNumber-1, err)
// 		}
//
// 		line = strings.TrimSuffix(line, "\r")
// 		scoreLoop(line)
// 	}
//
// 	// Final check for any errors that might have occurred
// 	if err := scanner.Err(); err != nil {
// 		log.Fatalf("Error scanning file: %v", err)
// 	}
// }

func runSet1Ch5() {
	stanza := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	fmt.Println(repeatXOR(stanza, "ICE"))
}

func runSet1Ch6() {
	cipherBytes := loadSet1Ch6()
	keyBytes := []byte(findKeyByTransposing())
	plainTextBytes := decodePlainText(cipherBytes, keyBytes)
	fmt.Printf("%s\n", string(plainTextBytes))
}

func main() {
	runSet1Ch3()
}
