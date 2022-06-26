/*
 * Copyright (C) 2022 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
This example runs TinyJAMBU cryptography tests on Arduino platforms.
*/

#include <TinyJAMBU.h>

#if defined(ESP8266)
extern "C" void system_soft_wdt_feed(void);
#define crypto_feed_watchdog() system_soft_wdt_feed()
#else
#define crypto_feed_watchdog() do { ; } while (0)
#endif

typedef void (*aead_cipher_encrypt_t)
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);
typedef int (*aead_cipher_decrypt_t)
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

typedef struct
{
    const char *name;               /**< Name of the cipher */
    unsigned key_len;               /**< Length of the key in bytes */
    unsigned nonce_len;             /**< Length of the nonce in bytes */
    unsigned tag_len;               /**< Length of the tag in bytes */
    aead_cipher_encrypt_t encrypt;  /**< AEAD encryption function */
    aead_cipher_decrypt_t decrypt;  /**< AEAD decryption function */

} aead_cipher_t;

aead_cipher_t const tinyjambu_128_cipher = {
    "TinyJAMBU-128",
    TINYJAMBU_128_KEY_SIZE,
    TINYJAMBU_NONCE_SIZE,
    TINYJAMBU_TAG_SIZE,
    tinyjambu_128_aead_encrypt,
    tinyjambu_128_aead_decrypt
};

aead_cipher_t const tinyjambu_192_cipher = {
    "TinyJAMBU-192",
    TINYJAMBU_192_KEY_SIZE,
    TINYJAMBU_NONCE_SIZE,
    TINYJAMBU_TAG_SIZE,
    tinyjambu_192_aead_encrypt,
    tinyjambu_192_aead_decrypt
};

aead_cipher_t const tinyjambu_256_cipher = {
    "TinyJAMBU-256",
    TINYJAMBU_256_KEY_SIZE,
    TINYJAMBU_NONCE_SIZE,
    TINYJAMBU_TAG_SIZE,
    tinyjambu_256_aead_encrypt,
    tinyjambu_256_aead_decrypt
};

#if defined(__AVR__)
#define DEFAULT_PERF_LOOPS 200
#define DEFAULT_PERF_LOOPS_16 200
#define DEFAULT_PERF_HASH_LOOPS 100
#else
#define DEFAULT_PERF_LOOPS 1000
#define DEFAULT_PERF_LOOPS_16 3000
#define DEFAULT_PERF_HASH_LOOPS 1000
#endif

static int PERF_LOOPS = DEFAULT_PERF_LOOPS;
static int PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16;
static int PERF_HASH_LOOPS = DEFAULT_PERF_HASH_LOOPS;
static bool PERF_MASKING = false;

#define MAX_DATA_SIZE 128
#define MAX_TAG_SIZE 32

static unsigned char const key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char const nonce[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char plaintext[MAX_DATA_SIZE];
static unsigned char ciphertext[MAX_DATA_SIZE + MAX_TAG_SIZE];

static unsigned long encrypt_128_time = 0;
static unsigned long encrypt_16_time = 0;
static unsigned long decrypt_128_time = 0;
static unsigned long decrypt_16_time = 0;
static unsigned long encrypt_128_ref = 0;
static unsigned long encrypt_16_ref = 0;
static unsigned long decrypt_128_ref = 0;
static unsigned long decrypt_16_ref = 0;
static unsigned long hash_1024_time = 0;
static unsigned long hash_128_time = 0;
static unsigned long hash_16_time = 0;
static unsigned long hash_1024_ref = 0;
static unsigned long hash_128_ref = 0;
static unsigned long hash_16_ref = 0;

static void print_x(double value)
{
    if (value < 0.005)
        Serial.print(value, 4);
    else
        Serial.print(value);
}

void perfCipherEncrypt128(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    size_t len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt 128 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, 128, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    encrypt_128_time = elapsed;

    if (encrypt_128_ref != 0 && elapsed != 0) {
        print_x(((double)encrypt_128_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (128.0 * PERF_LOOPS));
    Serial.print("us per byte, ");
    Serial.print((128.0 * PERF_LOOPS * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt128(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    size_t clen;
    size_t plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, 128, 0, 0, nonce, key);

    Serial.print("   decrypt 128 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        cipher->decrypt
            (plaintext, &plen, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    decrypt_128_time = elapsed;

    if (decrypt_128_ref != 0 && elapsed != 0) {
        print_x(((double)decrypt_128_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (128.0 * PERF_LOOPS));
    Serial.print("us per byte, ");
    Serial.print((128.0 * PERF_LOOPS * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherEncrypt16(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    size_t len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt  16 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, 16, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    encrypt_16_time = elapsed;

    if (encrypt_16_ref != 0 && elapsed != 0) {
        print_x(((double)encrypt_16_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (16.0 * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((16.0 * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt16(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    size_t clen;
    size_t plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, 16, 0, 0, nonce, key);

    Serial.print("   decrypt  16 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->decrypt
            (plaintext, &plen, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    decrypt_16_time = elapsed;

    if (decrypt_16_ref != 0 && elapsed != 0) {
        print_x(((double)decrypt_16_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (16.0 * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((16.0 * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

bool equal_hex(const char *expected, const unsigned char *actual, unsigned len)
{
    int ch, value;
    while (len > 0) {
        if (expected[0] == '\0' || expected[1] == '\0')
            return false;
        ch = *expected++;
        if (ch >= '0' && ch <= '9')
            value = (ch - '0') * 16;
        else if (ch >= 'A' && ch <= 'F')
            value = (ch - 'A' + 10) * 16;
        else if (ch >= 'a' && ch <= 'f')
            value = (ch - 'a' + 10) * 16;
        else
            return false;
        ch = *expected++;
        if (ch >= '0' && ch <= '9')
            value += (ch - '0');
        else if (ch >= 'A' && ch <= 'F')
            value += (ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f')
            value += (ch - 'a' + 10);
        else
            return false;
        if (actual[0] != value)
            return false;
        ++actual;
        --len;
    }
    return len == 0;
}

void perfCipherSanityCheck(const aead_cipher_t *cipher, const char *sanity_vec)
{
    unsigned count;
    size_t clen;

    Serial.print("   sanity check ... ");

    for (count = 0; count < 23; ++count)
        plaintext[count] = (unsigned char)count;
    for (count = 0; count < 11; ++count)
        plaintext[32 + count] = (unsigned char)count;

    cipher->encrypt
        (ciphertext, &clen, plaintext, 23, plaintext + 32, 11, nonce, key);

    if (equal_hex(sanity_vec, ciphertext, clen))
        Serial.println("ok");
    else
        Serial.println("FAILED");
}

void perfCipher(const aead_cipher_t *cipher, const char *sanity_vec)
{
    crypto_feed_watchdog();
    Serial.print(cipher->name);
    Serial.print(':');
    Serial.println();

    if (sanity_vec)
        perfCipherSanityCheck(cipher, sanity_vec);

    perfCipherEncrypt128(cipher);
    perfCipherDecrypt128(cipher);
    perfCipherEncrypt16(cipher);
    perfCipherDecrypt16(cipher);

    if (encrypt_128_ref != 0) {
        unsigned long ref_avg = encrypt_128_ref + decrypt_128_ref +
                                encrypt_16_ref  + decrypt_16_ref;
        unsigned long time_avg = encrypt_128_time + decrypt_128_time +
                                 encrypt_16_time  + decrypt_16_time;
        Serial.print("   average ... ");
        print_x(((double)ref_avg) / time_avg);
        Serial.print("x");
        if (PERF_MASKING) {
            Serial.print(" = 1 / ");
            print_x(((double)time_avg) / ref_avg);
            Serial.print("x");
        }
        Serial.println();
    }

    Serial.println();
}

void setup()
{
    Serial.begin(9600);
    Serial.println();

    // Run performance tests on the NIST AEAD algorithms.
    //
    // The test vectors are for doing a quick sanity check that the
    // algorithm appears to be working correctly.  The test vector is:
    //      Key = 0001020304...    (up to the key length)
    //      Nonce = 0001020304...  (up to the nonce length)
    //      PT = 000102030405060708090A0B0C0D0E0F10111213141516  (size = 23)
    //      AD = 000102030405060708090A                          (size = 11)
    // Usually this is "Count = 771" in the standard NIST KAT vectors.
    perfCipher(&tinyjambu_128_cipher, "E30F24BBFC434EB18B92A3A4742BBAE61383F62BC9104E976569195FE559BC");
    perfCipher(&tinyjambu_192_cipher, "317B8563AFA9B731FDF1F29FA688D0B0280422844CFEBAEE75CCE206898F65");
    perfCipher(&tinyjambu_256_cipher, "D38B7389554B9C5DD8CA961C42CBE0017B102D0E01B82E91EAB122742F58F9");
}

void loop()
{
}
