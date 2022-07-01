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

    // Initialize the random number generator.
    if (!tinyjambu_prng_init(&prng, NULL, 0)) {
        Serial.println("WARNING: Do not know how to generate random numbers on this platform");
        Serial.println();
    }
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
