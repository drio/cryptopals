# Cryptopals Set 1: Basics

## [1. Convert hex to base64](https://cryptopals.com/sets/1/challenges/1)

> The string:  
> `49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d`  
> Should produce:  
> `SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t`  
> Make that happen. You’ll need this code later.

---

## [2. Fixed XOR](https://cryptopals.com/sets/1/challenges/2)

> XOR two equal-length buffers.  
> Input:  
> `1c0111001f010100061a024b53535009181c`  
> XOR with:  
> `686974207468652062756c6c277320657965`  
> Output:  
> `746865206b696420646f6e277420706c6179`

---

## [3. Single-byte XOR cipher](https://cryptopals.com/sets/1/challenges/3)

> The hex string:  
> `1b37373331363f78151b7f2b783431333d78397828372d36...`  
> ... was XOR’d against a single byte.  
> Find the key and decrypt the message.

---

## [4. Detect single-character XOR](https://cryptopals.com/sets/1/challenges/4)

> One string in this file is encrypted with single-byte XOR.  
> Detect which one, and decrypt it.

---

## [5. Implement repeating-key XOR](https://cryptopals.com/sets/1/challenges/5)

> Encrypt the following using repeating-key XOR with key `"ICE"`:  
> ```
> Burning 'em, if you ain't quick and nimble  
> I go crazy when I hear a cymbal  
> ```

---

## [6. Break repeating-key XOR](https://cryptopals.com/sets/1/challenges/6)

> The file is base64-encoded and encrypted with repeating-key XOR.  
> Steps:
> 1. Guess keysize using normalized Hamming distance.
> 2. Transpose blocks.
> 3. Solve each block as single-byte XOR.
> 4. Recover key and decrypt.

---

## [7. AES in ECB mode](https://cryptopals.com/sets/1/challenges/7)

The Base64-encoded content in this file has been encrypted via AES-128 in ECB
mode under the key `"YELLOW SUBMARINE".`

(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW
SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

---

## [8. Detect AES in ECB mode](https://cryptopals.com/sets/1/challenges/8)


In [this file](https://cryptopals.com/static/challenge-data/8.txt) are a bunch
of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic;
the same 16 byte plaintext block will always produce the same 16 byte
ciphertext.
