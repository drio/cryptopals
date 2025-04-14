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
