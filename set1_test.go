package main

import (
	"testing"
)

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
