#ifndef _BLAKE
#define _BLAKE

/*
BLAKE2s outputs up to a 256-bit cryptographic hash.
BLAKE2b outputs up to a 512-bit cryptographic hash.

For optimized implementations[1]:
  BLAKE2s is (e.g. 1.64x) faster than BLAKE2b for 64 byte input (e.g. on Sandy Bridge)[2].
  BLAKE2b is (e.g. 1.40x) faster than BLAKE2s for longer input (e.g. 1536 bytes on Sandy Bridge)[2].

A prospectively faster 128-bit downscaled variant of BLAKE2s was not invented because:
  * functionality (but not speedup) already supported by length setting for BLAKE2s’ output
  * security would be unvetted
  * improbable yet unclear if unavailable 16-bit word SIMD gather and permute instruction[3] would
    reduce the SIMD registers available[4] for parallel instances especially if both 128-bit lanes
    of each ymm register are employed, or if the performance would be significantly less than the
    expected 100% speedup of double parallel instances[5][6][7], given SSE3 and AVX have similar
    performance[8][9]; and the fastest 'avxicc' employs only instructions[10] which also have
    16-word variants[3].

 [1] Typically SIMD (e.g. SSE or AVX) optimized, thus 32-bit or 64-bit CPU mode is often irrelevant.
 [2] BLAKE2: simpler, smaller, fast as MD5, §3.1 Why BLAKE2 is fast in software, https://blake2.net/blake2.pdf#page=14
 [3] http://www.intel.ph/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
 [4] Implementing BLAKE with AVX, AVX2, and XOP, §5.1 Optimizing message loads, http://eprint.iacr.org/2012/275.pdf#page=9
 [5] Implementing BLAKE with AVX, AVX2, and XOP, §5.2 Tree hashing, http://eprint.iacr.org/2012/275.pdf#page=9
 [6] Boring cryptography Google group: benchmarking parallel hash functions, https://groups.google.com/forum/#!topic/boring-crypto/VWLhJjgO1v0
 [7] BLAKE2: simpler, smaller, fast as MD5, §3.2 64-bit CPUs, https://blake2.net/blake2.pdf#page=14
 [8] https://github.com/floodyberry/blake2s-opt#i7-4770k
 [9] http://bench.cr.yp.to/impl-hash/blake2s.html
[10] https://github.com/floodyberry/supercop/blob/master/crypto_hash/blake2s/avxicc/blake2s.s
*/

#include "../cmacros/c11types.h"
#include "../cmacros/export.h"

typedef struct {
  uint32 h[8];       // hash
  uint32 padding[8]; // unused padding to SIZEOF(h)*2 from &h, for optional use by applications
	uint32 t[2];       // total (8-bit) bytes processed (value embedded in each block as processed); carry overflow of t[0] stored in t[1]
	uint32 f[2];       // ~f[0] is 0 for final block processed (value embedded in each block as processed), otherwise 0
  uint32 queued[16]; // buffer of queued input
  uint8  bytes;      // quantity of (8-bit) bytes queued
} blake2s_state;

typedef struct {
  uint64 h[8];
  uint64 padding[8];
  uint64 t[2];
  uint64 f[2];
  uint64 queued[16];
  uint8  bytes;
} blake2b_state;

blake2s_state* EXPORT
blake2s_init(blake2s_state* state, const uint8 len/*final hash length 1-32 (8-bit) bytes*/, const uint32* key, const uint8 keylen/*key length 0-32 (8-bit) bytes*/);

blake2b_state*
blake2b_init(blake2b_state* state, const uint8 len/*final hash length 1-64 (8-bit) bytes*/, const uint64* key, const uint8 keylen/*key length 0-64 (8-bit) bytes*/);

/*
Compared to the reference implementations, this implementation imposes some
constraints to improve efficiency by reducing copying and premature conversion
to and from little-endian.

To avoid copying of data to 'state->queued', the input 'bytes' should be a
multiple of 'SIZEOF(in[16])'.

Error on invocation if the accumulated sum of 'bytes' for prior invocations:

1. sum != 0 && sum % SIZEOF(in[16]) == 0 && bytes == 0
2. (sum + bytes) / SIZEOF(in[16]) > (sum + bytes) / SIZEOF(in[16]) && (sum + bytes) % SIZEOF(*in) != 0

In non-convoluted, less abstruse english, to avoid these errors respectively:

1. Other than first invocation, never invoke with zero 'bytes'.
2. Always 'bytes' should be a multiple of SIZEOF(*in), unless the current
   (including 'bytes') or eventually succeeding accumulated sum will be
   precisely 'SIZEOF(in[16])' or final before accumulating to the next multiple
   of 'SIZEOF(in[16])'.
*/

blake2s_state* EXPORT
blake2s(blake2s_state*const state, const uint32* in, size_t bytes/*input length in (8-bit) bytes*/, const bool final, const bool padded/*'in' padded to 64 bytes*/);

blake2b_state*
blake2b(blake2b_state*const state, const uint64* in, size_t bytes/*input length in (8-bit) bytes*/, const bool final, const bool padded/*'in' padded to 128 bytes*/);

#include "../cmacros/variadic.h"

#define blake2s_init_1(a         ) a, 32, NULL, 0
#define blake2s_init_2(a, b      ) a,  b, NULL, 0
#define blake2s_init_4(a, b, c, d) a,  b,    c, d
#define blake2s_init(...) VARIADIC(blake2s_init, NUMARG4(__VA_ARGS__), __VA_ARGS__)

#define blake2s_3(a, b, c      ) a,  b, c, true, false
#define blake2s_4(a, b, c, d   ) a,  b, c,    d, false
#define blake2s_5(a, b, c, d, e) a,  b, c,    d,     e
#define blake2s(...) VARIADIC(blake2s, NUMARG5(__VA_ARGS__), __VA_ARGS__)

#define blake2b_init_1(a         ) a, 64, NULL, 0
#define blake2b_init_2(a, b      ) a,  b, NULL, 0
#define blake2b_init_4(a, b, c, d) a,  b,    c, d
#define blake2b_init(...) VARIADIC(blake2b_init, NUMARG4(__VA_ARGS__), __VA_ARGS__)

#define blake2b_3(a, b, c      ) a,  b, c, true, false
#define blake2b_4(a, b, c, d   ) a,  b, c,    d, false
#define blake2b_5(a, b, c, d, e) a,  b, c,    d,     e
#define blake2b(...) VARIADIC(blake2b, NUMARG5(__VA_ARGS__), __VA_ARGS__)

#define blake2_init(a, ...) _Generic((a),                                                                                          \
                                     blake2s_state*: blake2s_init,                                                                 \
                                     blake2b_state*: blake2b_init)(VARIADIC2(blake2s_init, NUMARG4(a, __VA_ARGS__), a, __VA_ARGS__))

#define      blake2(a, ...) _Generic((a),                                                                                          \
                                     blake2s_state*:      blake2s,                                                                 \
                                     blake2b_state*:      blake2b)(VARIADIC2(blake2s,      NUMARG5(a, __VA_ARGS__), a, __VA_ARGS__))

/*
Functions for nesting 1 or more invocations of the hash function H(x), e.g. a
nesting of 3 is H(H(H(x))).
*/

void EXPORT
blake2s_nested(uint32 n/*number of invocations*/, uint32*const out, const uint32* in,
               size_t bytes/*input/output length 1-32 (8-bit) bytes*/,
               const uint32* key, const uint8 keylen/*key length 0-32 (8-bit) bytes*/);

void
blake2b_nested(uint64 n/*number of invocations*/, uint64*const out, const uint64* in,
               size_t bytes/*input/output length 1-64 (8-bit) bytes*/,
               const uint64* key, const uint8 keylen/*key length 0-64 (8-bit) bytes*/);

#define blake2s_nested_3(a, b, c         ) a, b, c, 32, NULL, 0
#define blake2s_nested_4(a, b, c, d      ) a, b, c,  d, NULL, 0
#define blake2s_nested_6(a, b, c, d, e, f) a, b, c,  d,    e, f
#define blake2s_nested(...) VARIADIC(blake2s_nested, NUMARG6(__VA_ARGS__), __VA_ARGS__)

#define blake2b_nested_3(a, b, c         ) a, b, c, 64, NULL, 0
#define blake2b_nested_4(a, b, c, d      ) a, b, c,  d, NULL, 0
#define blake2b_nested_6(a, b, c, d, e, f) a, b, c,  d,    e, f
#define blake2b_nested(...) VARIADIC(blake2b_nested, NUMARG6(__VA_ARGS__), __VA_ARGS__)

#define blake2_nested(a, ...) _Generic((a),                                                                                        \
                                       uint32_t: blake2s_nested,                                                                   \
                                       uint64_t: blake2b_nested)(VARIADIC2(blake2s_nested, NUMARG6(a, __VA_ARGS__), a, __VA_ARGS__))


/*
BLAKE requires conversions to and from little-endian byte strings for portable I/O.
*/

#include "../byteio/byteio.h"

/******************************** UNIT TESTS *********************************/
bool EXPORT
blake2s_selftest();

bool
blake2b_selftest();

#endif