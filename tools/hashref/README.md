
Reference code
--------------

This directory contains reference code for the TinyJAMBU-Hash and
TinyJAMBU-HMAC algorithms, based on the reference implementation of
TinyJAMBU-AEAD from the third round of the NIST Lightweight Cryptography
Competition (LWC).

Motivation
----------

If a device's key pair is being encrypted with a passphrase, then there
needs to be some method to hash the passphrase with a salt to produce a
uniform key value for encrypting the pair.  Without a hash algorithm,
implementors might be tempted to use the passphrase directly as a key.

TinyJAMBU's native lack of a hashing mode makes it difficult to drop into
existing session protocols like TLS or Noise.  The design of session
protocols usually assume the presence of a hash algorithm to expand a
limited amount of session key material into larger amounts via a KDF.

Specification of the hashing mode
---------------------------------

The hash uses the MDPH construction, similar to the Romulus-H submission
to the third round of the NIST Lightweight Cryptography Competition (LWC).
TinyJAMBU-256 is operated as a tweakable block cipher with an increased
number of rounds.

1. Pad the input to a multiple of 128 bits by adding a 1 bit and enough
   zero bits to reach a multiple of 128.
2. Split the padded input up into 128-bit blocks M[1], M[2], ..., M[m].
3. Set L = R = 0 where L and R are 128 bit values for the internal hash state.
4. For i = 1 to m - 1 do (L, R) = Compress(L, R, M[i])
5. (L, R) = Compress(L ^ 2, R, M[m])
6. The hash output is L || R.

The compression function is as follows:

    Compress(L, R, M):
        K = R || M
        L' = Encrypt(K, L) ^ L
        R' = Encrypt(K, L ^ 1) ^ L ^ 1
        return (L', R')

Encrypt(K, P) is an invocation of the TinyJAMBU-256 permutation with 256-bit
key K and 128-bit state input P for 2560 rounds.

In the AEAD construction, the TinyJAMBU-256 permutation is invoked with 1280
rounds to process 32 bit blocks of plaintext.  This expands to 5120 rounds for
each 128 bits of plaintext, which we divide evenly between the two calls to
Encrypt.

Security
--------

This construction is experimental and a full security analysis has not
been done yet.

The TinyJAMBU specification makes the following claims for the security
level of the AEAD mode:

* TinyJAMBU-256 encryption - 224-bit.
* TinyJAMBU-256 authentication - 64-bit.

It is possible that this construction is no better than TinyJAMBU-256
authentication, so the security level may only be 64-bit.  At best it
is 224-bit.

This construction is vulnerable to length extension attacks just like SHA256.
Use of a HMAC-style mode for keyed hashing and key derivation is recommended.
This directory also contains reference code for TinyJAMBU-HMAC.
