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

This example demonstrates how to generate random data using the TinyJAMBU PRNG.

The PRNG is initialized with an initial seed from the system.  Then it will
output 32 bytes from the PRNG every second.  Every 10 seconds it will reseed
the PRNG from the system to refresh the entropy in the PRNG state.

If the user types input at the serial console, then it will feed that
input into the PRNG as additional entropy.

*/

#include <TinyJAMBU.h>

// Determine how to generate random 32-bit words with this platform.
#if defined(ESP8266)

#define init_random() do { ; } while (0)
#define get_random_word() (*((volatile uint32_t *)0x3FF20E44))

#elif defined(ESP32)

// It is variable from one ESP32 SDK to the next which header this
// function is declared in, so we declare it ourselves.
extern uint32_t esp_random(void);
#define init_random() do { ; } while (0)
#define get_random_word() esp_random()

#elif defined(__arm__) && defined(__SAM3X8E__) // Arduino Due

static void init_random()
{
    pmc_enable_periph_clk(ID_TRNG);
    REG_TRNG_CR = TRNG_CR_KEY(0x524E47) | TRNG_CR_ENABLE;
    REG_TRNG_IDR = TRNG_IDR_DATRDY;
}

static uint32_t get_random_word()
{
    // SAM3X8E's TRNG returns a new random word every 84 clock cycles.
    // If the TRNG is not ready after 100 iterations, assume it has failed.
    int count = 100;
    while ((REG_TRNG_ISR & TRNG_ISR_DATRDY) == 0) {
        if ((--count) <= 0)
            return 0xABADBEEF; // This is a problem!
    }
    return REG_TRNG_ODATA;
}

#else

#warning "Do not know how to generate random numbers on this platform"
#define init_random() do { ; } while (0)
#define get_random_word() 0xDEADBEEFU
#define NO_RANDOM 1

#endif

// Callback from the PRNG to get random entropy from the system.
static size_t get_system_random
    (void *user_data, unsigned char *buf, size_t size)
{
    (void)user_data;
    size_t temp = size;
    while (temp > 0) {
        uint32_t x = get_random_word();
        if (temp >= sizeof(uint32_t)) {
            memcpy(buf, &x, sizeof(uint32_t));
            buf += sizeof(uint32_t);
            temp -= sizeof(uint32_t);
        } else {
            memcpy(buf, &x, temp);
            break;
        }
    }
    return size;
}

static void print_hex(const unsigned char *data, unsigned size)
{
    static const char hexchars[] = "0123456789abcdef";
    while (size > 0) {
        Serial.print(hexchars[(data[0] >> 4) & 0x0F]);
        Serial.print(hexchars[data[0] & 0x0F]);
        Serial.print(' ');
        ++data;
        --size;
    }
    Serial.println();
}

static tinyjambu_prng_state_t prng;

void setup()
{
    Serial.begin(9600);
    Serial.println();
#if defined(NO_RANDOM)
    Serial.println("WARNING: Do not know how to generate random numbers on this platform");
    Serial.println();
#endif

    // Initialize the system random number source.
    init_random();

    // Initialize the PRNG.
    tinyjambu_prng_init(&prng, get_system_random, NULL);
}

void loop()
{
    unsigned count, posn;
    unsigned char data[32];
    unsigned long timer;

    // Every second, output random data.
    for (count = 0; count < 10; ++count) {
        timer = millis();
        while ((millis() - timer) < 1000) {
            posn = 0;
            while (posn < sizeof(data) && Serial.available()) {
                // Read as many characters as we can and feed them
                // into the PRNG as new entropy.
                data[posn++] = (unsigned char)(Serial.read());
            }
            if (posn > 0) {
                tinyjambu_prng_feed(&prng, data, posn);
            }
        }
        tinyjambu_prng_generate(&prng, data, sizeof(data));
        print_hex(data, sizeof(data));
    }

    // Re-seed from the system random number source every 10 seconds.
    Serial.println("reseed");
    tinyjambu_prng_reseed(&prng);
}
