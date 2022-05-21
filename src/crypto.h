/*
 * Dimitrios Koropoulis 3967
 * csd3967@csd.uoc.gr
 * CS457 - Spring 2022
 * crypto.h
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdlib.h>
#include <stdint.h>

/* One Time Pad */
uint8_t* generate_key(size_t size);

void print_hex(const char* plaintext, const uint8_t* bytes, const size_t size);

uint8_t* otp_encr(const uint8_t* data, const uint8_t* key, const size_t data_size);
uint8_t* otp_decr(const uint8_t* data, const uint8_t* key, const size_t data_size);
void otp_word_decryption(void);
void otp_demo(int find_words);

/* Rail Fence */
uint8_t* rail_fence_encr(const uint8_t* data, size_t n);
uint8_t* rail_fence_decr(const uint8_t* data, size_t n);
void  rail_fence_demo(void);

/* Beaufort */
uint8_t* beaufort_encr(const uint8_t* data, const uint8_t* key);
uint8_t* beaufort_decr(const uint8_t* data, const uint8_t* key);
void  beaufort_demo(void);

uint8_t* affine_encr(const uint8_t* data);
uint8_t* affine_decr(const uint8_t* data);
void  affine_demo(void);

/* Feistel */
uint8_t* feistel_encr(const uint8_t* data, const size_t data_size);
uint8_t* feistel_decr(const uint8_t* data, const size_t data_size);
void feistel_demo(void);

#endif /* CRYPTO_H */

