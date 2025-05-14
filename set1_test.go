package main

import (
	"bufio"
	"encoding/hex"
	"log"
	"strings"
	"testing"
)

func TestSet1Challenge01(t *testing.T) {
	t.Run("Convert Hex to Base64", func(t *testing.T) {
		input := `49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d`
		expect := `SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t`

		got := hexToBase64(input)
		if got != expect {
			t.Errorf("wrong hex to base64 for %s\ngot %s\nexpected: %s", input, got, expect)
		}
	})

	t.Run("HexToBase64 Alternative Test", func(t *testing.T) {
		i := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		result := hexToBase64(i)
		expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
		if result != expected {
			t.Errorf("%s expected %s", result, expected)
		}
	})
}

func TestSet1Challenge02(t *testing.T) {
	t.Run("Fixed XOR with Bytes", func(t *testing.T) {
		one := hexToBin(`1c0111001f010100061a024b53535009181c`)
		two := hexToBin(`686974207468652062756c6c277320657965`)
		expect := `746865206b696420646f6e277420706c6179`

		got := hex.EncodeToString(runXORBytes(one, two))
		if got != expect {
			t.Errorf("wrong xor inputs %s %s\ngot %s\nexpected: %s", one, two, got, expect)
		}
	})

	t.Run("Fixed XOR with Strings", func(t *testing.T) {
		input1 := "1c0111001f010100061a024b53535009181c"
		input2 := "686974207468652062756c6c277320657965"
		expected := "746865206b696420646f6e277420706c6179"

		result := runXOR(input1, input2)
		if result != expected {
			t.Errorf("Expected %s, but got %s", expected, result)
		}
	})
}

func TestSet1Challenge03(t *testing.T) {
	t.Run("Single Byte XOR Cipher", func(t *testing.T) {
		inputHex := `1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736`
		_, bestKeyBytes := scoreLoopBest(hexToBin(inputHex))
		gotKeyHex := string(bestKeyBytes[0])
		expect := `X`

		if gotKeyHex != expect {
			t.Errorf("wrong key for plaintext\n%s\ngot %s\nexpected: %s", inputHex, gotKeyHex, expect)
		}
	})
}

func TestSet1Challenge04(t *testing.T) {
	t.Run("Detect Single-Character XOR", func(t *testing.T) {
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

		expect := "Now that the party is jumping\n"
		if bestPlainText != expect {
			t.Errorf("\nexpected:\n%s\ngot:\n%s", expect, bestPlainText)
		}
	})
}

func TestSet1Challenge05(t *testing.T) {
	t.Run("Implement Repeating-Key XOR", func(t *testing.T) {
		stanza := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

		plainTextHex := repeatXOR(stanza, "ICE")
		expect := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

		if plainTextHex != expect {
			t.Errorf("\nexpected:\n%s\ngot:\n%s", expect, plainTextHex)
		}
	})
}

func TestSet1Challenge06(t *testing.T) {
	t.Run("Break Repeating-Key XOR", func(t *testing.T) {
		cipherBytes := loadFromFileInBase64("data/set1/6.txt")
		keySize := 29
		keyBytes := []byte(findKeyByTransposing(cipherBytes, keySize))
		plainTextBytes := runSliceXOR(cipherBytes, keyBytes)

		expect := readFileToMemory("data/set1/output6.txt")
		if string(plainTextBytes) != string(expect) {
			t.Errorf("the plaintext does not match data/set1/output6.txt\n")
		}
	})
}

func TestHammingDistance(t *testing.T) {
	t.Run("Compute Hamming Distance", func(t *testing.T) {
		input1 := "this is a test"
		input2 := "wokka wokka!!!"
		expected := 37

		result := hamming(input1, input2)
		if result != expected {
			t.Errorf("Expected %d, but got %d", expected, result)
		}
	})
}

func TestComputeBlockHD(t *testing.T) {
	t.Run("Normal Cases", func(t *testing.T) {
		testCases := []struct {
			data     []byte
			keySize  int
			expected float64
		}{
			{[]byte("one one one one"), 4, 0},
			{[]byte("aaaabbbbaaaaaaaa"), 4, 16},
			{[]byte("one two tres cuatro"), 4, 25},
		}

		for _, tc := range testCases {
			result := computeBlockHD(tc.data, tc.keySize)
			// The exact value might vary, so we'll just check if it's a reasonable result
			if result.sumHD < 0.0 {
				t.Errorf("Normalized Hamming Distance should not be negative, got %2.2f", result)
			}
			if result.sumHD != tc.expected {
				t.Errorf("input %s keySize=%d should be %2.2f but got %2.2f", tc.data, tc.keySize, tc.expected, result)
			}
		}
	})

	t.Run("Edge Cases", func(t *testing.T) {
		// Test with edge cases
		var emptyData []byte
		result := computeBlockHD(emptyData, 4)
		if result.sumHD != 0.0 {
			t.Errorf("Expected 0 for empty data, got %2.2f", result.sumHD)
		}

		shortData := []byte("short")
		result = computeBlockHD(shortData, 10)
		if result.sumHD != 0.0 {
			t.Errorf("Expected 0 when keySize is larger than data length, got %2.2f", result.sumHD)
		}
	})
}
