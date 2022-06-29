
Reference code
--------------

This directory contains a modified version of the reference implementation
of TinyJAMBU from the third round of the NIST Lightweight Cryptography
Competition (LWC).

The reference implementation has been modified to generate test vectors
for a two-pass SIV mode.  These vectors are used to validate the SIV
implementation in our library.

Specification of TinyJAMBU-SIV mode
-----------------------------------

The algorithm performs two passes over the data.  In the first pass
the associated data and plaintext are authenticated to produce a
64-bit authentication tag.

The first pass is identical in structure to the regular AEAD mode,
except that the domain separator when absorbing the nonce is 0x90
instead of 0x10.  The ciphertext is discarded.

In the second pass, a new nonce is formed from the first 32 bits of
the original nonce and the 64 bits of the authentication tag.
The original nonce is assumed to be a packet sequence number or a
memory address in little-endian byte order.

The second pass absorbs the nonce using the domain separator of
0xB0 this time.  And then encrypts the plaintext in a similar
manner to the regular AEAD mode.  In this pass, the plaintext is
not incorporated into the state to authenticate it.

The domain separator for encryption in the second pass is 0xD0
instead of 0x50 for the first pass.
