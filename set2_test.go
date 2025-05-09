package main

import (
	"bytes"
	"fmt"
	"log"
	"testing"
)

func TestSet09(t *testing.T) {
	expect := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	got := padPCKS7([]byte("YELLOW SUBMARINE"), 20)
	if len(got) != len(expect) {
		t.Errorf("wrong size, expecting %d and got %d", 20, len(got))
	}

	if string(got) != string(expect) {
		t.Errorf("wrong bytes")
	}
}

func testPadPKCS7AlignedInput() {
	input := []byte("0123456789ABCDEF") // 16 bytes
	expected := append(input, bytes.Repeat([]byte{0x10}, 16)...)

	padded := padPCKS7(input, 16)

	if !bytes.Equal(padded, expected) {
		log.Fatalf("PKCS#7 padding failed.\nExpected: %v\nGot:      %v",
			expected, padded)
	} else {
		fmt.Println("PKCS#7 padding test passed for aligned input.")
	}
}

func TestUnpadPKCS7_Valid(t *testing.T) {
	data := append([]byte("ICE ICE BABY"), []byte{0x04, 0x04, 0x04, 0x04}...)
	expected := []byte("ICE ICE BABY")

	unpadded := unpadPKCS7(data)
	if !bytes.Equal(unpadded, expected) {
		t.Errorf("Unpad failed.\nExpected: %v\nGot: %v", expected, unpadded)
	}
}

func TestUnpadPKCS7_Invalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic due to invalid padding, but got none")
		}
	}()

	data := append([]byte("ICE ICE BABY"), []byte{0x01, 0x02, 0x03, 0x04}...)
	_ = unpadPKCS7(data) // Should panic
}

func TestEncryptDecryptCBC_Set10(t *testing.T) {
	plainText := []byte(`This is a very important secret and should never shared with anyone`)
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16) // 16 zero bytes

	cipherText := encryptCBC(plainText, key, iv)
	result := decryptCBC(cipherText, key, iv)
	padRemoved := unpadPKCS7(result)

	if !bytes.Equal(padRemoved, plainText) {
		t.Errorf("CBC encryption/decryption failed.\nExpected: %s\nGot:      %s", plainText, padRemoved)
	}
}
