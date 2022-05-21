/*
 * Dimitrios Koropoulis - 3967
 * csd3967@csd.uoc.gr
 * CS457 - Spring 2022
 * crypto.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <stdbool.h>

#define MOD(x, m) ((x % m + m) % m)

#define DEMO_DELIM    "======================="
#define OTP_INPUT     "Don't reuse keys kids!"
#define OTP_WORD_SIZE 8
#define OTP_WORDLIST  "./wordlist.txt"

#define RF_ADJUST_ROW(d, r) (d ? r--: r++)

const char BF_TABLE[26][26] = {
    {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'},
    {'B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A'},
    {'C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B'},
    {'D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C'},
    {'E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D'},
    {'F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E'},
    {'G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F'},
    {'H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G'},
    {'I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H'},
    {'J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I'},
    {'K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J'},
    {'L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K'},
    {'M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L'},
    {'N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M'},
    {'O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N'},
    {'P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O'},
    {'Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P'},
    {'R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q'},
    {'S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R'},
    {'T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S'},
    {'U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T'},
    {'V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U'},
    {'W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V'},
    {'X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W'},
    {'Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X'},
    {'Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y'}
};

#define AF_A   11
#define AF_AIN 19
#define AF_B   19
#define AF_M   26

#define FEIS_N          4
#define FEIS_BLOCK_SIZE 16
#define FEIS_HALF_BLOCK 8

void print_hex(const char* msg, const uint8_t* bytes, const size_t size) {

    printf("%s ", msg);
    for (size_t i = 0; i < size; ++i) {
        printf("%02x ", (unsigned char)bytes[i]);
    }
    printf("\n");

    return;
}

uint8_t* generate_key(size_t size) {

    FILE* f = NULL;
    uint8_t* key = NULL;

    f = fopen("/dev/urandom", "r");
    if (!f) {
       perror("fopen");
       exit(EXIT_FAILURE);
    }

    key = malloc(size);
    fread(key, 1, size, f);

    fclose(f);

    return key;
}

uint8_t* otp_encr(const uint8_t* data, const uint8_t* key, const size_t data_size) {

    uint8_t *data_enc = NULL;

    if (!data) {
        fprintf(stderr, "%s: %s\n", __func__, "NULL plaintext!");
        exit(EXIT_FAILURE);
    }

    if (!key) {
        fprintf(stderr, "%s: %s\n", __func__, "NULL key!");
        exit(EXIT_FAILURE);
    }

    data_enc = malloc(data_size);
    for (size_t i = 0; i < data_size; ++i) {
        data_enc[i] = data[i] ^ key[i];
    }

    return data_enc;
}

uint8_t* otp_decr(const uint8_t* data, const uint8_t* key, const size_t data_size) {
    return otp_encr(data, key, data_size);
}

static bool search_wordlist(char* filename, char* word) {

    FILE* wordlist = NULL;
    char curr[OTP_WORD_SIZE + 2];
    bool res = false;

    wordlist = fopen(filename, "r");
    if (!wordlist) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    while (!feof(wordlist)) {
        fgets(curr, OTP_WORD_SIZE + 2, wordlist);
        curr[OTP_WORD_SIZE] = 0;

        if (strcmp(curr, word) == 0) {
            res = true;
            break;
        }
    }

    fclose(wordlist);
    return res;
}

void otp_word_decryption(void) {

    /*
     * assuming k(w) is the result of XORing word w with key k AND len(k) >= len(w) = 8
     *
     * it is true that:
     *
     * [+] k(w1) ^ k(w2) == w1 ^ w2 (Reuse of one-time-pad)
     *
     * and:
     *
     * [+] (w1 ^ w2) ^ w2 == w1
     * [+] (w1 ^ w2) ^ w1 == w2
     *
     * so we just need to iterate through all 8-byte alphanumeric words in the wordlist
     * and perform: res <- (w1 ^ w2) ^ cw, where cw is the current word.
     *
     * if res is a printable word, there is a chance that is is either w1 or w2.
     * So we search the wordlist for a match. If found, we have sucessfuly found both words.
     */

    bool is_printable = true;
    bool found = false;

    FILE *wordlist = NULL;

    char xword[OTP_WORD_SIZE + 1];
    char temp[OTP_WORD_SIZE + 1];

    char curr_word[OTP_WORD_SIZE + 2];

    const char word1[OTP_WORD_SIZE + 1] = {0xe9, 0x3a, 0xe9, 0xc5, 0xfc, 0x73, 0x55, 0xd5, 0x00};
    const char word2[OTP_WORD_SIZE + 1] = {0xf4, 0x3a, 0xfe, 0xc7, 0xe1, 0x68, 0x4a, 0xdf, 0x00};

    wordlist = fopen(OTP_WORDLIST, "r");
    if (!wordlist) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < OTP_WORD_SIZE; i++) {
        xword[i] = word1[i] ^ word2[i];
    }
    xword[OTP_WORD_SIZE] = '\0';

    printf("\nDecrypting using %s, please be patient ...\n", OTP_WORDLIST);
    while (!feof(wordlist)) {

        /* read (OTP_WORD_SIZE + '\n' + '\0') bytes*/
        fgets(curr_word, OTP_WORD_SIZE + 2, wordlist);
        curr_word[OTP_WORD_SIZE] = '\0';


        is_printable = true;
        for (int i = 0; i < OTP_WORD_SIZE; i++) {

            temp[i] = xword[i] ^ curr_word[i];
            if (!isalnum(temp[i])) {
                is_printable = false;
                break;
            }
        }

        if (!is_printable) continue;

        temp[OTP_WORD_SIZE] = '\0';
        found = search_wordlist(OTP_WORDLIST, temp);

        if (found) break;
    }

    if (found) {
        printf("=== DECRYPTED WORDS ===\n[*] %s\n[*] %s\n", curr_word, temp);
    }

    fclose(wordlist);

    return;
}

int otp_demo(int find_words) {

    const uint8_t *plaintext = (uint8_t*)OTP_INPUT;
    const size_t data_size = strlen((char*)plaintext);
    const uint8_t *key = generate_key(data_size);

    uint8_t *cypher = NULL;
    uint8_t *decoded = NULL;

    puts("=== ONE TIME PAD DEMO ===");

    cypher = otp_encr(plaintext, key, data_size);
    decoded = otp_decr(cypher, key, data_size);

    printf("input: \"%s\"\n\n", plaintext);
    print_hex("input (bytes):", plaintext, data_size);
    print_hex("random key:   ", key, data_size);
    print_hex("cyphertext:   ", cypher, data_size);

    print_hex("\ndecoded:      ", decoded, data_size);

    printf("\ndecoded: \"");
    for (size_t i = 0; i < data_size; ++i) {
        printf("%c", decoded[i]);
    }
    printf("\"\n");

    if (find_words) {
        otp_word_decryption();
    }

    free(cypher);
    free(decoded);
    free((void*)key);

    puts(DEMO_DELIM);

    return 0;
}

char* rail_fence_encr(const char* data, size_t fence_count) {

    /* current direction; 0: down, 1: up */
    int dir = 1;
    size_t row = 0;
    size_t data_size = strlen(data);
    char* encoded = malloc(data_size + 1);

    if (!data) {
        fprintf(stderr, "%s: %s\n", __func__, "NULL data!");
        exit(EXIT_FAILURE);
    }

    /* initialization */
    char matrix[fence_count][data_size];
    for (size_t i = 0; i < fence_count; i++) {
        for (size_t j = 0; j < data_size; j++) {
            matrix[i][j] = 0;
        }
    }

    /* populate the matrix */
    for (size_t j = 0; j < data_size; j++) {
        if (row == 0 || row == fence_count - 1) {
            dir = !dir;
        }

        matrix[row][j] = data[j];
        RF_ADJUST_ROW(dir, row);
    }

    int i = 0;
    for (size_t r = 0; r < fence_count; r++) {
        for (size_t c = 0; c < data_size; c++) {
            if (matrix[r][c] != 0) {
                encoded[i++] = matrix[r][c];
            }
        }
    }

    encoded[data_size] = 0;

    return encoded;
}

char* rail_fence_decr(const char* data, size_t fence_count) {

    int dir = 1; /*1: upwards, 0: downwards*/
    size_t data_size = strlen(data);
    char* decoded = malloc(data_size + 1);
    const char placeholder_char = 0x58;

    if (!data) {
        fprintf(stderr, "%s: %s\n", __func__, "NULL data!");
        exit(EXIT_FAILURE);
    }

    /* initialization */
    char matrix[fence_count][data_size];
    for (size_t r = 0; r < fence_count; r++) {
        for (size_t c = 0; c < data_size; c++) {
            matrix[r][c] = 0;
        }
    }

    /* populate the matrix */
    for (size_t r = 0, c = 0; c < data_size; c++) {
        if (r == 0 || r == fence_count - 1) {
            dir = !dir;
        }

        matrix[r][c] = placeholder_char;
        RF_ADJUST_ROW(dir, r);
    }

    for (size_t i = 0, r = 0; r < fence_count; r++) {
        for (size_t c = 0; c < data_size; c++) {
            if (matrix[r][c] == placeholder_char) {
                matrix[r][c] = data[i++];
            }

        }
    }

    for (size_t i = 0, r = 0, c = 0; c < data_size; c++) {
        if (r == 0 || r == fence_count - 1) {
            dir = !dir;
        }

        decoded[i++] = matrix[r][c];
        RF_ADJUST_ROW(dir, r);
    }

    decoded[data_size] = 0;

    return decoded;
}

void rail_fence_demo(void) {

    const char* plaintext = "Hello World";
    const size_t rail_count = 3;

    char* cyphertext = NULL;
    char* decoded = NULL;

    puts("=== RAIL FENCE DEMO ===");

    cyphertext = rail_fence_encr(plaintext, rail_count);
    decoded = rail_fence_decr(cyphertext, rail_count);

    printf("rails: %lu\n\nplaintext:  \"%s\"\n",rail_count, plaintext);
    printf("cyphertext: \"%s\"\n", cyphertext);
    printf("decoded:    \"%s\"\n", decoded);

    puts(DEMO_DELIM);

    free(cyphertext);
    free(decoded);

    return;
}

char* beaufort_encr(const char* data, const char* keyword) {

    if (!data) {
        fprintf(stderr, "%s: %s\n", __func__, "NULL data!");
        exit(EXIT_FAILURE);
    }

    if (!keyword) {
        fprintf(stderr, "%s: %s\n", __func__, "NULL keyword!");
        exit(EXIT_FAILURE);
    }

    size_t data_size = strlen(data);
    size_t keyword_size = strlen(keyword);
    char key[data_size + 1];
    char *cypher = malloc(data_size + 1);

    if (data_size < keyword_size) {
       key[data_size] = 0;
    } else if (data_size > keyword_size) {
        size_t dif = data_size - keyword_size;

        /* copy keyword to key */
        strncpy(key, keyword, keyword_size + 1);

        for (size_t i = 0; i < dif; i++) {
            key[keyword_size + i] = keyword[i % keyword_size];
        }
        key[keyword_size + dif] = 0;

    } else {
        strncpy(key, keyword, keyword_size + 1);
    }


    for (size_t i = 0; i < data_size; i++) {
        int c = 0;
        int r = 0;

        while (data[i] != BF_TABLE[0][c]) {
            c++;
        }

        while (key[i] != BF_TABLE[r][c]) {
            r++;
        }

        cypher[i] = BF_TABLE[r][0];
    }

    cypher[data_size] = 0;

    return cypher;
}

char* beaufort_decr(const char* data, const char* keyword) {

    return beaufort_encr(data, keyword);
}

void beaufort_demo(void) {

    const char* plaintext = "ATTACKATDAWN";
    const char* keyword = "LEMON";
    char* cypher = NULL;
    char* decoded = NULL;

    puts("=== BEAUFORT DEMO ===");

    printf("keyword:    \"%s\"\n\nplaintext:  \"%s\"\n", keyword, plaintext);

    cypher = beaufort_encr(plaintext, keyword);
    decoded = beaufort_decr(cypher, keyword);

    printf("cyphertext: \"%s\"\n", cypher);
    printf("decoded:    \"%s\"\n", decoded);

    puts(DEMO_DELIM);

    free(cypher);
    free(decoded);

    return;
}

static unsigned ctoi(const char c) {

    if (!isupper(c)) {
        fprintf(stderr, "%s: %s\n", __func__, "not an uppercase character!");
        exit(EXIT_FAILURE);
    }

    return (c - 0x41);
}

static unsigned itoc(const unsigned i) {

    if (i > 26) {
        fprintf(stderr, "%s: %s\n", __func__, "invalid char encoding!");
        exit(EXIT_FAILURE);
    }

    return (i + 0x41);
}



char* affine_encr(const char* data) {

    size_t data_size = strlen(data);
    char* cypher = malloc(data_size + 1);

    for (size_t i = 0; i < data_size; i++) {
        cypher[i] = itoc((AF_A * ctoi(data[i]) + AF_B) % AF_M);
    }

    cypher[data_size] = 0;

    return cypher;
}

char* affine_decr(const char* data) {

    size_t data_size = strlen(data);
    char* decoded = malloc(data_size + 1);

    int f = 0;
    for (size_t i = 0; i < data_size; i++) {
        /*
         * for some reason this sequence of expression produces correct results
         * but when joined into one, i.e there's no 'f' variable, things go fucky.
         * Probably has to do with the expansion of MOD(x, AF_M) and some casting that C does,
         * but I can't be bothered. So it stays as is.
         */

        f = AF_AIN * (ctoi(data[i]) - AF_B);
        decoded[i] = itoc(MOD(f, AF_M));
    }

    decoded[data_size] = 0;
    return decoded;
}

void affine_demo(void) {

    const char* plaintext = "AFFINECIPHER";
    char* cyphertext = NULL;
    char* decoded = NULL;

    puts("=== AFFINE DEMO ===");

    cyphertext = affine_encr(plaintext);
    decoded = affine_decr(cyphertext);
    printf("plaintext:  \"%s\"\n"
           "cyphertext: \"%s\"\n"
           "decoded:    \"%s\"\n",
            plaintext, cyphertext, decoded
          );

    puts(DEMO_DELIM);

    free(cyphertext);
    free(decoded);

    return;
}

static uint8_t* feistel_fun(uint8_t* block, uint8_t* key) {

    uint8_t c = 0;
    uint8_t* funced = malloc(FEIS_HALF_BLOCK);

    for (size_t i = 0; i < FEIS_HALF_BLOCK; ++i) {
        c = block[i] * key[i];
        funced[i] = MOD(c, 256);
    }

    return funced;
}

static uint8_t* feistel_pad(uint8_t* data, size_t data_size) {

    uint8_t* padded_data = NULL;

    if (data_size > 16) {
        puts("feistel cipher: data length is bigger that block size");
        exit(EXIT_FAILURE);
    }

    padded_data = malloc(FEIS_HALF_BLOCK);
    memcpy(padded_data, data, data_size);

    /* if the data size is smaller, zero pad it */
    if (data_size < FEIS_BLOCK_SIZE / 2) {
        size_t diff = (FEIS_BLOCK_SIZE / 2) - data_size;
        for (size_t i = 0; i < diff; i++) {
            padded_data[data_size + i] = 0;
        }
    }

    return padded_data;
}

uint8_t* feistel_encr(const uint8_t* data, const size_t data_size, uint8_t** keys) {

    uint8_t *cyphertext = NULL;
    uint8_t *funced = NULL;

    uint8_t curr_left[FEIS_HALF_BLOCK];
    uint8_t curr_right[FEIS_HALF_BLOCK];

    uint8_t next_left[FEIS_HALF_BLOCK];
    uint8_t next_right[FEIS_HALF_BLOCK];


    cyphertext = feistel_pad((uint8_t*)data,  data_size);

    for (size_t i = 0; i < FEIS_N; ++i) {

        memcpy(curr_left, cyphertext, FEIS_HALF_BLOCK);
        memcpy(curr_right,  cyphertext + FEIS_HALF_BLOCK, FEIS_HALF_BLOCK);

        memcpy(next_left, curr_right, FEIS_HALF_BLOCK);

        funced = feistel_fun(curr_right, keys[i]);

        for (size_t j = 0; j < FEIS_HALF_BLOCK; ++j) {
            next_right[j] = curr_left[j] ^ funced[j];
        }

        memcpy(cyphertext, next_left, FEIS_HALF_BLOCK);
        memcpy(cyphertext + FEIS_HALF_BLOCK, next_right, FEIS_HALF_BLOCK);

        free(funced);
    }

    memcpy(curr_left, cyphertext, FEIS_HALF_BLOCK);
    memcpy(curr_right,  cyphertext + FEIS_HALF_BLOCK, FEIS_HALF_BLOCK);

    memcpy(cyphertext, curr_right, FEIS_HALF_BLOCK);
    memcpy(cyphertext + FEIS_HALF_BLOCK, curr_left, FEIS_HALF_BLOCK);


    return cyphertext;
}

uint8_t* feistel_decr(uint8_t *data, const size_t data_size, uint8_t** keys) {

    uint8_t *reversed_keys[FEIS_N];
    uint8_t *decoded = NULL;
    uint8_t *plaintext = NULL;

    for (int i = 0; i < FEIS_N; ++i) {
        reversed_keys[i] = keys[FEIS_N - i - 1];
    }

    decoded = feistel_encr(data, data_size, reversed_keys);
    plaintext = malloc(data_size + 1);

    memcpy(plaintext, decoded, data_size);
    plaintext[data_size] = 0;

    free(decoded);
    return plaintext;
}

void feistel_demo(void) {

    const char* plaintext = "PraiseTheSun";
    const size_t data_size = strlen(plaintext);
    uint8_t* keys[FEIS_N];

    uint8_t* cyphertext = NULL;
    uint8_t* decoded = NULL;

    puts("=== FEISTEL DEMO ===");

    for (int i = 0; i < FEIS_N; ++i) {
        keys[i] = generate_key(FEIS_HALF_BLOCK);
    }

    cyphertext = feistel_encr((uint8_t*)plaintext, data_size, keys);
    decoded = feistel_decr(cyphertext, FEIS_BLOCK_SIZE, keys);
    decoded[data_size] = 0;

    printf("plaintext:        \"%s\"\n", plaintext);
    print_hex("plaintext (bytes):", (uint8_t*)plaintext, data_size);
    print_hex("cyphertext:       ", cyphertext, FEIS_BLOCK_SIZE);
    print_hex("decoded:          ", decoded, data_size);

    printf("decoded (ascii):  \"%s\"\n", decoded);

    free(cyphertext);
    free(decoded);
    for (int i = 0; i < FEIS_N; ++i) {
        free(keys[i]);
    }

    puts(DEMO_DELIM);

    return;

}



