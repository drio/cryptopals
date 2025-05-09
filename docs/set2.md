# Cryptopals Set 2: Block Crypto

## [9. Implement PKCS#7 padding](https://cryptopals.com/sets/2/challenges/9)

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of
plaintext into ciphertext. But we almost never want to transform a single
block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a
plaintext that is an even multiple of the blocksize. The most popular padding
scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes
of padding to the end of the block. For instance, p `"YELLOW SUBMARINE"` ...
padded to 20 bytes would be:

`"YELLOW SUBMARINE\x04\x04\x04\x04"`

---

## [10. Implement CBC mode](https://cryptopals.com/sets/2/challenges/10)

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
messages, despite the fact that a block cipher natively only transforms
individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before
the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block,
is added to a "fake 0th ciphertext block" called the initialization vector, or
IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making
it encrypt instead of decrypt (verify this by decrypting whatever you encrypt
to test), and using your XOR function from the previous exercise to combine
them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW
SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

### drio notes

We are still working with the AES-128 algorithm, but now we are using a
different mode. Before, we used ECB mode; now we are using CBC mode. ECB is
weak because blocks with the same plaintext yield the same ciphertext. You can
leverage that to build an attack (we'll see that in later challenges).

In this challenge, we are changing the mode. The key difference is that in CBC
mode, each plaintext block is XORed with the previous ciphertext block before
encryption. Because there is no "previous block" for the first block, we start
with an initialization vector (IV).


```
Cᵢ = AES-ECB-Encrypt(Pᵢ XOR Cᵢ₋₁)
For the first block: C₀ = AES-Encrypt(P₀ XOR IV)
```


---

## [11. An ECB/CBC detection oracle](https://cryptopals.com/sets/2/challenges/11)

> Write a function that encrypts data under ECB or CBC, randomly.  
> It should:
> - Append 5–10 random bytes before and after the input
> - Use a random AES key
> - Choose ECB or CBC at random
> Detect which mode was used by analyzing the ciphertext.

---

## [12. Byte-at-a-time ECB decryption (Simple)](https://cryptopals.com/sets/2/challenges/12)

> Given an oracle that appends an unknown string to your input and encrypts
> it under ECB, recover the unknown string.  
> You control the input and can make many requests to the oracle.

---

## [13. ECB cut-and-paste](https://cryptopals.com/sets/2/challenges/13)

> Create a profile for a user encoded as a query string.  
> Then, encrypt the profile using AES-ECB.  
> Craft a ciphertext that decrypts to a profile with `admin=true`.

---

## [14. Byte-at-a-time ECB decryption (Harder)](https://cryptopals.com/sets/2/challenges/14)

> Like challenge 12, but now the oracle also prepends a random-length random
> prefix.  
> You don’t know the length of the prefix.  
> Recover the unknown string using ECB decryption.

---

## [15. PKCS#7 padding validation](https://cryptopals.com/sets/2/challenges/15)

> Write a function that takes a padded block and verifies that the padding is
> valid PKCS#7.  
> If the padding is invalid, return an error.

---

## [16. CBC bitflipping attacks](https://cryptopals.com/sets/2/challenges/16)

> Create an encryption oracle that:
> - Prefixes your input with `"comment1=cooking%20MCs;userdata="`
> - Suffixes it with `";comment2=%20like%20a%20pound%20of%20bacon"`
> - Sanitizes `;` and `=` in your input
> - Encrypts the result with AES-CBC
>  
> Use a bit-flipping attack to get the decrypted plaintext to include:
> `";admin=true;"`

