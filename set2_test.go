package main

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestSet09_PKCS7Padding(t *testing.T) {
	t.Run("Basic padding test", func(t *testing.T) {
		expect := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
		got := padPCKS7([]byte("YELLOW SUBMARINE"), 20)
		if len(got) != len(expect) {
			t.Errorf("wrong size, expecting %d and got %d", 20, len(got))
		}

		if string(got) != string(expect) {
			t.Errorf("wrong bytes")
		}
	})

	t.Run("Aligned input padding", func(t *testing.T) {
		input := []byte("0123456789ABCDEF") // 16 bytes
		expected := append(input, bytes.Repeat([]byte{0x10}, 16)...)

		padded := padPCKS7(input, 16)

		if !bytes.Equal(padded, expected) {
			t.Errorf("PKCS#7 padding failed.\nExpected: %v\nGot: %v",
				expected, padded)
		}
	})
}

func TestUnpadPKCS7(t *testing.T) {
	t.Run("Valid padding", func(t *testing.T) {
		data := append([]byte("ICE ICE BABY"), []byte{0x04, 0x04, 0x04, 0x04}...)
		expected := []byte("ICE ICE BABY")

		unpadded := unpadPKCS7(data)
		if !bytes.Equal(unpadded, expected) {
			t.Errorf("Unpad failed.\nExpected: %v\nGot: %v", expected, unpadded)
		}
	})

	t.Run("Invalid padding", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic due to invalid padding, but got none")
			}
		}()

		data := append([]byte("ICE ICE BABY"), []byte{0x01, 0x02, 0x03, 0x04}...)
		_ = unpadPKCS7(data) // Should panic
	})
}

func TestEncryptDecryptCBC_Set10(t *testing.T) {
	t.Run("CBC Encryption and Decryption", func(t *testing.T) {
		plainText := []byte(`This is a very important secret and should never shared with anyone`)
		key := []byte("YELLOW SUBMARINE")
		iv := make([]byte, 16) // 16 zero bytes

		cipherText := encryptCBC(plainText, key, iv)
		result := decryptCBC(cipherText, key, iv)
		padRemoved := unpadPKCS7(result)

		if !bytes.Equal(padRemoved, plainText) {
			t.Errorf("CBC encryption/decryption failed.\nExpected: %s\nGot: %s", plainText, padRemoved)
		}
	})
}

func TestGenRandSlice(t *testing.T) {
	t.Run("Length is within range", func(t *testing.T) {
		min, max := 5, 10
		for range 100 {
			slice := genRandSlice(min, max)
			length := len(slice)

			if length < min || length > max {
				t.Errorf("Generated slice length %d is outside the range [%d, %d]", length, min, max)
			}
		}
	})

	t.Run("Zero min value", func(t *testing.T) {
		min, max := 0, 5
		for range 20 {
			slice := genRandSlice(min, max)
			length := len(slice)

			// Since min=0, we expect lengths from 0 to max
			if length < min || length > max {
				t.Errorf("Generated slice length %d is outside the range [%d, %d]", length, min, max)
			}
		}

		// Test specific case where we want to ensure we can get empty slices
		found := false
		for range 50 {
			slice := genRandSlice(0, 3)
			if len(slice) == 0 {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Could not generate an empty slice with min=0 after multiple attempts")
		}
	})

	t.Run("Randomness check", func(t *testing.T) {
		min, max := 20, 20 // Fixed length for comparison
		slice1 := genRandSlice(min, max)
		slice2 := genRandSlice(min, max)
		if bytes.Equal(slice1, slice2) {
			// The chance of getting identical random sequences is astronomically low
			t.Errorf("Two consecutive random slices are identical, which suggests the RNG isn't working properly")
		}
	})
}

func TestGenRandomAESKey(t *testing.T) {
	t.Run("Key length check", func(t *testing.T) {
		key := genRandomAESKey()
		if len(key) != 16 {
			t.Errorf("Generated AES key length %d is not 16 bytes", len(key))
		}
	})

	t.Run("Multiple keys are different", func(t *testing.T) {
		// Generate multiple keys and ensure they're all different
		numKeys := 100
		keys := make([][]byte, numKeys)
		
		for i := 0; i < numKeys; i++ {
			keys[i] = genRandomAESKey()
		}
		
		// Check that all keys are different from each other
		for i := 0; i < numKeys; i++ {
			for j := i + 1; j < numKeys; j++ {
				if bytes.Equal(keys[i], keys[j]) {
					t.Errorf("Keys %d and %d are identical, which suggests a problem with randomness", i, j)
					return
				}
			}
		}
	})

	t.Run("Cipher validation", func(t *testing.T) {
		// Test that the generated key works with AES cipher
		key := genRandomAESKey()
		_, err := aes.NewCipher(key)
		if err != nil {
			t.Errorf("Generated key is not valid for AES: %v", err)
		}
	})
}
