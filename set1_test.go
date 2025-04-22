package main

import (
	"testing"
)

func TestComputeBlockHD(t *testing.T) {
	// Test normal cases in a loop
	testCases := []struct {
		data     []byte
		keySize  int
		expected int
	}{
		{[]byte("one one one one"), 4, 0},
		{[]byte("aaaabbbbaaaaaaaa"), 4, 16},
		{[]byte("one two tres cuatro"), 4, 25},
	}

	for _, tc := range testCases {
		result := computeBlockHD(tc.data, tc.keySize)
		// The exact value might vary, so we'll just check if it's a reasonable result
		if result < 0 {
			t.Errorf("Normalized Hamming Distance should not be negative, got %d", result)
		}
		if result != tc.expected {
			t.Errorf("input %s keySize=%d should be %d but got %d", tc.data, tc.keySize, tc.expected, result)
		}
	}

	// Test with edge cases
	var emptyData []byte
	zeroKeySize := computeBlockHD(emptyData, 4)
	if zeroKeySize != 0 {
		t.Errorf("Expected 0 for empty data, got %d", zeroKeySize)
	}

	shortData := []byte("short")
	smallKeySize := computeBlockHD(shortData, 10)
	if smallKeySize != 0 {
		t.Errorf("Expected 0 when keySize is larger than data length, got %d", smallKeySize)
	}
}

func TestHexToBase64(t *testing.T) {
	i := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	result := hexToBase64(i)
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if result != expected {
		t.Errorf("%s expected %s", result, expected)
	}

}

func TestRunXOR(t *testing.T) {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"

	result := runXOR(input1, input2)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

func TestHammingDistance(t *testing.T) {
	input1 := "this is a test"
	input2 := "wokka wokka!!!"
	expected := 37

	result := hamming(input1, input2)
	if result != expected {
		t.Errorf("Expected %d, but got %d", expected, result)
	}
}
