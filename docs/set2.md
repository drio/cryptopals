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

### Drio notes

Cryptographic padding and unpadding might seem simple at first, but there are a
lot of subtleties. I'm starting to realize that crypto code is full of this
kind of detail — which is exactly why people say: "don’t roll your own crypto."

To be clear, I think that phrase should really mean: go ahead and write your
own — learn from it — then throw it away and use a well-tested, bulletproof
implementation.

In this case, you’ll need to write an unpad function that runs after
decryption. But be careful: it’s not enough to just read the last byte and chop
off that many bytes. You must verify that all of the last N bytes (where N is
the last byte) actually match the value N. If they don’t, the data is malformed
— and potentially dangerous to process.


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

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a
function that generates a random key and encrypts under it.

The function should look like:

```
encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
```

Under the hood, have the function append 5-10 bytes (count chosen randomly)
before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC
the other half (just use random IVs each time for CBC). Use rand(2) to decide
which to use.

Detect the block cipher mode the function is using each time. You should end up
with a piece of code that, pointed at a block box that might be encrypting ECB
or CBC, tells you which one is happening.

### Drio notes

So we have implemented AES encryption in both, ECB and CBC modes.

- ECB -> encrypts each block independently: same plaintext blocks yield same ciphertext blocks.
- CBC -> XORs each block with the previous ciphertext block (or IV) before encryption.
    -> No leaking

What is this challenge asking?

1. Simulate a `function oracle(input []bytes)`:
    1. randomly decides if to encrypt in ECB or CBC mode.
    2. prepends and appends 5-10 random bytes to your input
    3. it uses a new random key (and IV for CBC) every time.
2. Run the oracle with a "crafted" input. 
    1. Analyze the ciphertext returned.
    2. Was this ECB or CBC?

The second part could be done like so:

```go
func isECBorCBC() string {
    input := bytes.Repeat([]byte("A"), 128)
    cipherText := oracle(input)

    numDups := countDuplicateBlocks(cipherText, 16)

    if numDups > 0 {
        return "ECB"
    } else {
        return "CBC"
    }
}
```

## [12. Byte-at-a-time ECB decryption (Simple)](https://cryptopals.com/sets/2/challenges/12)


Copy your oracle function to a new function that encrypts buffers under ECB
mode using a consistent but unknown key (for instance, assign a single random
key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE
ENCRYPTING, the following string:

```
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
```

Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string
by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key) It turns out: you can
decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

1. Feed identical bytes of your-string to the function 1 at a time --- start
   with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size
of the cipher. You know it, but do this step anyway.

2. Detect that the function is using ECB. You already know, but do this step anyways.

3. Knowing the block size, craft an input block that is exactly 1 byte short
   (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about
what the oracle function is going to put in that last byte position.

4. Make a dictionary of every possible last byte by feeding different strings
   to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering
the first block of each invocation.

5. Match the output of the one-byte-short input to one of the entries in your
   dictionary. You've now discovered the first byte of unknown-string.

6. Repeat for the next byte.

Congratulations.

This is the first challenge we've given you whose solution will break real
crypto. Lots of people know that when you encrypt something in ECB mode, you
can see penguins through it. Not so many of them can decrypt the contents of
those ciphertexts, and now you can. If our experience is any guideline, this
attack will get you code execution in security tests about once a year.

### Drio comments

Ok, this is pretty cool.

We have that base64 encoded text (I can't wait to decrypt it!) that is 
the plaintext we want to get to when we break the cipher.

`AES-128-ECB(your-string || unknown-string, random-key)`

We control the `your-string`. 

Steps: 

1. Modify the Oracle function from the previous step so it 
appends an input that you pass to the plaintext. Then encodes it using 
ECB. 

2. Detect the block size. How? 
Call the Oracle with a variable input length. Check the length of the 
output. As soon as the output length increases, the difference between
the ciphertext and the plaintext gives you the block size.

3. Confirm we are using ECB mode. If so, we should see duplicates in the
ciphertext blocks.

4. Recover the unknown-string (US). The fun part.

Decrypt the first block of plaintext.

Step 1: get the block0 of the output from the oracle.

```
your-string = A*15
ciphertext = Oracle(your-string, plaintext)
block0 = cipherText[0:16]
```

Step 2: build a map of all the possible first blocks for
        constrains of A*15 + byte, where byte is any value
        from 0 to 255.

```
for b in 0..255:
   plaintext = "A"*15 + byte(b)
   ciphertext = oracle(plaintext)
   dict[ciphertex[0:16]] = b
```

Step 3: match the dict keys against block0, one of the 
keys will match. If so, the value returned by the dict
is the first byte of the plaintext.

When you are done with a block, do the same for the next block
until there are no more blocks to work with.





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

