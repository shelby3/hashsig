#ifndef _HASHSIG
#define _HASHSIG

/*
One-time use hash-based signatures employing 2-bit Winternitz chunks and the
BLAKE2 cryptographic hash functions.

TODO: invent a 128-bit BLAKE2 variant to double the throughput for 128-bit case.
*/

#include "../cmacros/c11types.h"
#include "../cmacros/export.h"

/*
Inputs the private key seed and the message of 'bits' length.
Outputs (bits/2 + ⌈log₂(3×bits÷2)÷2⌉) signature keys, each of 'bits' length.
*/

uint32* EXPORT
hashsig128_sign(const uint32*const key, const uint32*const msg, uint32*const sig/*= NULL*/); // 128 bits

uint32* EXPORT
hashsig256_sign(const uint32*const key, const uint32*const msg, uint32*const sig/*= NULL*/); // 256 bits

/*
Inputs the signature keys and outputs the public keys, each of 'bits' length.
If verify, the input hash of the public key is compared, else it is output.
*/

bool EXPORT
hashsig128_keys(uint32*const key, const uint32*const msg, uint32*const sig, const bool verify/*= true*/); // 128 bits

bool EXPORT
hashsig256_keys(uint32*const key, const uint32*const msg, uint32*const sig, const bool verify/*= true*/); // 256 bits

#include "../cmacros/variadic.h"

#define   hashsig128_sign_2(a, b   ) a, b, NULL
#define   hashsig128_sign_3(a, b, c) a, b,    c
#define   hashsig128_sign(...) VARIADIC(hashsig128_sign, NUMARG3(__VA_ARGS__), __VA_ARGS__)

#define   hashsig256_sign_2(a, b   ) a, b, NULL
#define   hashsig256_sign_3(a, b, c) a, b,    c
#define   hashsig256_sign(...) VARIADIC(hashsig256_sign, NUMARG3(__VA_ARGS__), __VA_ARGS__)

#define   hashsig128_keys_3(a, b, c   ) a, b, c, true
#define   hashsig128_keys_4(a, b, c, d) a, b, c,    d
#define   hashsig128_keys(...) VARIADIC(hashsig128_keys, NUMARG4(__VA_ARGS__), __VA_ARGS__)

#define   hashsig256_keys_3(a, b, c   ) a, b, c, true
#define   hashsig256_keys_4(a, b, c, d) a, b, c,    d
#define   hashsig256_keys(...) VARIADIC(hashsig256_keys, NUMARG4(__VA_ARGS__), __VA_ARGS__)

#endif