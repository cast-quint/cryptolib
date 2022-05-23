# Cryptolib

A basic implementation of 5 encryption algorithms, with a demo.
Developed in the spring of 2022, as an assignment for my [Introduction to Information Security Systems](https://www.csd.uoc.gr/~hy457/) class.

## Ciphers: 
- One Time Pad
- Rail Fence cipher
- Beaufort cipher
- Affine cipher
- Feistel cipher

Each cipher has a demo function which encrypts and decrypts a plaintext
using the appropriate functions.

## OTP
The OTP demo demonstrates the dangers of reusing the pad.
Given 2 words encrypted with the same key and a wordlist,
the demo successfully cracks the pad and prints the plaintexts.
The given cyphertexts are:
- ```[0xe9 0x3a 0xe9 0xc5 0xfc 0x73 0x55 0xd5] ("networks")```
- ```[0xf4 0x3a 0xfe 0xc7 0xe1 0x68 0x4a 0xdf] ("security")```

To enable this behaviour, use the ```-c``` option.

## Building
```
cd cryptolib
make
```

## Usage
```
./demo [-c]
```

## Cleaning
```
make clean
```

