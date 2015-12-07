/*
Reference implementations:
  SHA-3 proposal BLAKE, §2 Specification, https://131002.net/blake/blake.pdf#page=8
  The BLAKE2 Cryptographic Hash and MAC, §D.2 blake2s.c, https://tools.ietf.org/html/draft-saarinen-blake2-06#page-20
  https://github.com/floodyberry/blake2b-opt
    * https://github.com/floodyberry/blake2b-opt/blob/master/app/extensions/blake2b/blake2b_ref-3264.inc
    * https://github.com/floodyberry/blake2b-opt/blob/master/app/extensions/blake2b/impl.c
*/

#include "blake.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/******************************** UNIT TESTS *********************************/
// Deterministic sequences (Fibonacci generator).
static void
selftest_seq(uint8* out, size_t len, uint32 seed) {
  uint32 a = /*prime*/0xDEAD4BAD * seed, b = 1;

  for (size_t i = 0; i < len; i++) {
    uint32 t = a + b; a = b; b = t;
    out[i] = (t >> 24) & 0xFF;
  }
}

bool EXPORT
blake2s_selftest() {
#define HASH_SZ 32
#define INPUT_MAX 1024
    const size_t md_len[4] = {HASH_SZ*4/8, HASH_SZ*5/8, HASH_SZ*7/8,     HASH_SZ};
    const size_t in_len[6] = {0,           3,           HASH_SZ*2,       HASH_SZ*2+1, 255, INPUT_MAX};

    blake2s_state state, md;
    uint32 _in[INPUT_MAX/SIZEOF(*md.h)], _key[HASH_SZ/SIZEOF(*md.h)];
    const uint32 *p_in, *p_key;

    uint8 in[INPUT_MAX], key[HASH_SZ];
    size_t outlen, inlen;
    bool hash_md = false;

    assert(blake2s_init(&state) == &state); // hash of message digest ('md') hashes

    for (size_t i = 0; i < 4; i++) {
      if (hash_md) {
        hash_md = false;
        assert(blake2s(&state, md.h, outlen, /*not final*/false) == &state);
      }
      outlen = md_len[i];
      for (size_t j = 0; j < 6; j++) {
        if (hash_md) {
          hash_md = false;
          assert(blake2s(&state, md.h, outlen, /*not final*/false) == &state);
        }
        inlen = in_len[j];

        selftest_seq(in, inlen, inlen);    // unkeyed hash
        p_in = frombytes(_in, in, inlen);
        assert(blake2s_init(&md, outlen) == &md);
        assert(blake2s(&md, p_in, inlen) == &md);
        assert(blake2s(&state, md.h, outlen, /*not final*/false) == &state);

        selftest_seq(key, outlen, outlen); // keyed hash
        p_key = frombytes(_key, key, outlen);
        assert(blake2s_init(&md, outlen, p_key, outlen) == &md);
        assert(blake2s(&md, p_in, inlen) == &md);
        hash_md = true;
      }
    }

    // Grand hash of hash results.
    const uint8 result[HASH_SZ] = {
      0x6A, 0x41, 0x1F, 0x08, 0xCE, 0x25, 0xAD, 0xCD,
      0xFB, 0x02, 0xAB, 0xA6, 0x41, 0x45, 0x1C, 0xEC,
      0x53, 0xC5, 0x98, 0xB2, 0x4F, 0x4F, 0xC7, 0x87,
      0xFB, 0xDC, 0x88, 0x79, 0x7F, 0x4C, 0x1D, 0xFE
    };

    // Finalize and compare the hash of hashes.
    assert(blake2s(&state, md.h, outlen) == &state);
    uint8 buf[SIZEOF(result)];
    const uint8 *p_buf;
    p_buf = tobytes(state.h, buf, SIZEOF(result));
    for (size_t i = 0; i < SIZEOF(result); i++)
      if (p_buf[i] != result[i]) return false;

    return true;
}

bool // do not EXPORT so EMSCRIPTEN will discard (if not invoked from a C/C++ or specifically exported by the build), since 64-bit arithmetic is emulated
blake2b_selftest() {
#undef HASH_SZ
#undef INPUT_MAX
#define HASH_SZ 64
#define INPUT_MAX 1024
    const size_t md_len[4] = {HASH_SZ*5/16, HASH_SZ*8/16, HASH_SZ*12/16, HASH_SZ};
    const size_t in_len[6] = {0,            3,            HASH_SZ*2,     HASH_SZ*2+1, 255, INPUT_MAX};

    blake2b_state state, md;
    uint64 _in[INPUT_MAX/SIZEOF(*md.h)], _key[HASH_SZ/SIZEOF(*md.h)];
    const uint64 *p_in, *p_key;

    uint8 in[INPUT_MAX], key[HASH_SZ];
    size_t outlen, inlen;
    bool hash_md = false;

    assert(blake2b_init(&state, 32) == &state); // hash of message digest ('md') hashes

    for (size_t i = 0; i < 4; i++) {
      if (hash_md) {
        hash_md = false;
        assert(blake2b(&state, md.h, outlen, /*not final*/false) == &state);
      }
      outlen = md_len[i];
      for (size_t j = 0; j < 6; j++) {
        if (hash_md) {
          hash_md = false;
          assert(blake2b(&state, md.h, outlen, /*not final*/false) == &state);
        }
        inlen = in_len[j];

        selftest_seq(in, inlen, inlen);    // unkeyed hash
        p_in = frombytes(_in, in, inlen);
        assert(blake2b_init(&md, outlen) == &md);
        assert(blake2b(&md, p_in, inlen) == &md);
        assert(blake2b(&state, md.h, outlen, /*not final*/false) == &state);

        selftest_seq(key, outlen, outlen); // keyed hash
        p_key = frombytes(_key, key, outlen);
        assert(blake2b_init(&md, outlen, p_key, outlen) == &md);
        assert(blake2b(&md, p_in, inlen) == &md);
        hash_md = true;
      }
    }

    // Grand hash of hash results.
    const uint8 result[HASH_SZ/2] = {
      0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD,
      0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29, 0xDA, 0x56,
      0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73,
      0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC, 0xD4, 0x75
    };

    // Finalize and compare the hash of hashes.
    assert(blake2b(&state, md.h, outlen) == &state);
    uint8 buf[SIZEOF(result)];
    const uint8 *p_buf;
    p_buf = tobytes(state.h, buf, SIZEOF(result));
    for (size_t i = 0; i < SIZEOF(result); i++)
      if (p_buf[i] != result[i]) return false;

    return true;
}
/****************************** END UNIT TESTS *******************************/


void EXPORT
blake2s_nested(uint32 n/*number of invocations*/, uint32*const out, const uint32* in,
               size_t bytes/*input/output length 1-32 (8-bit) bytes*/,
               const uint32* key, const uint8 keylen/*key length 0-32 (8-bit) bytes*/) {
  // Alternate between two hash states, to use the prior output as an input without copying
  blake2s_state state1, state2;
  if (n >= 1) {
    // Pad hash outputs with 0
    memset((uint8*)(&state1.h) + bytes, 0, (SIZEOF(state1.h) + SIZEOF(state1.padding)) * CHAR_BIT/8 - bytes); // [CHAR_BIT]
    if (n > 1)
      memset(&state2.padding, 0, SIZEOF(state2.padding) * CHAR_BIT/8);                                        // [CHAR_BIT]
    // Copy input to a hash ouput because this is more efficient than if blake2() does the paddding
    memcpy(&state1.h, in, bytes);
    in = (const uint32*)&state1.h;
    blake2s_state* state = &state2;
    blake2_init(state, bytes, key, keylen);
    blake2(state, in, bytes, /*final*/true, /*zero padded*/true);
    while (--n > 0) {
      in = (const uint32*)&state2.h;
      memset((uint8*)(&state2.h) + bytes, 0, SIZEOF(state2.h) * CHAR_BIT/8 - bytes);   // Pad hash outputs with 0
      state = &state1;
      blake2_init(state, bytes);
      blake2(state, in, bytes, /*final*/true, /*zero padded*/true);
      if (--n > 0) {
        in = (const uint32*)&state1.h;
        memset((uint8*)(&state1.h) + bytes, 0, SIZEOF(state1.h) * CHAR_BIT/8 - bytes); // Pad hash outputs with 0
        state = &state2;
        blake2_init(state, bytes);
        blake2(state, in, bytes, /*final*/true, /*zero padded*/true);
      }
    }
    memcpy(out, state->h, bytes);
  } else if (in != out) {
    memcpy(out, in, bytes);
  }
}

void // do not EXPORT so EMSCRIPTEN will discard (if not invoked from a C/C++ or specifically exported by the build), because 64-bit arithmetic is emulated
blake2b_nested(uint64 n/*number of invocations*/, uint64*const out, const uint64* in,
               size_t bytes/*input/output length 1-64 (8-bit) bytes*/,
               const uint64* key, const uint8 keylen/*key length 0-64 (8-bit) bytes*/) {
  // Alternate between two hash states, to use the prior output as an input without copying
  blake2b_state state1, state2;
  if (n >= 1) {
    // Pad hash outputs with 0
    memset((uint8*)(&state1.h) + bytes, 0, (SIZEOF(state1.h) + SIZEOF(state1.padding)) * CHAR_BIT/8 - bytes); // [CHAR_BIT]
    if (n > 1)
      memset(&state2.padding, 0, SIZEOF(state2.padding) * CHAR_BIT/8);                                        // [CHAR_BIT]
    // Copy input to a hash ouput because this is more efficient than if blake2() does the paddding
    memcpy(&state1.h, in, bytes);
    in = (const uint64*)&state1.h;
    blake2b_state* state = &state2;
    blake2_init(state, bytes, key, keylen);
    blake2(state, in, bytes, /*final*/true, /*zero padded*/true);
    while (--n > 0) {
      in = (const uint64*)&state2.h;
      memset((uint8*)(&state2.h) + bytes, 0, SIZEOF(state2.h) * CHAR_BIT/8 - bytes);   // Pad hash outputs with 0
      state = &state1;
      blake2_init(state, bytes);
      blake2(state, in, bytes, /*final*/true, /*zero padded*/true);
      if (--n > 0) {
        in = (const uint64*)&state1.h;
        memset((uint8*)(&state1.h) + bytes, 0, SIZEOF(state1.h) * CHAR_BIT/8 - bytes); // Pad hash outputs with 0
        state = &state2;
        blake2_init(state, bytes);
        blake2(state, in, bytes, /*final*/true, /*zero padded*/true);
      }
    }
    memcpy(out, state->h, bytes);
  } else if (in != out) {
    memcpy(out, in, bytes);
  }
}


#undef blake2s_init
#undef blake2s
#undef blake2b_init
#undef blake2b

static const uint8 b2_sigma[12][16] = { // 10 or 12 rounds for BLAKE2s or b
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

#define ROTR32(x, bits) ((uint32)(x) >> (bits) | (x) << (32 - (bits))) // logical (not arithematic) right shift >> requires unsigned operand

#define G(m, r, i, a, b, c, d)    \
  a += b + m[b2_sigma[r][2*i+0]]; \
  d = ROTR32(d ^ a, 16);          \
  c += d;                         \
  b = ROTR32(b ^ c, 12);          \
  a += b + m[b2_sigma[r][2*i+1]]; \
  d = ROTR32(d ^ a,  8);          \
  c += d;                         \
  b = ROTR32(b ^ c,  7)

#define H (state->h)
#define T (state->t)
#define F (state->f)

static void
b2s_block(blake2s_state*const state, const uint32 blk[16]) {
  uint32 v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15;
   v0 = H[0];
   v1 = H[1];
   v2 = H[2];
   v3 = H[3];
   v4 = H[4];
   v5 = H[5];
   v6 = H[6];
   v7 = H[7];
   v8 = 0x6a09e667;        // IV[0]
   v9 = 0xbb67ae85;        // IV[1]
  v10 = 0x3c6ef372;        // IV[2]
  v11 = 0xa54ff53a;        // IV[3]
  v12 = 0x510e527f ^ T[0]; // IV[4] ^ t0
  v13 = 0x9b05688c ^ T[1]; // IV[5] ^ t1
  v14 = 0x1f83d9ab ^ F[0]; // IV[6] ^ f0
  v15 = 0x5be0cd19 ^ F[1]; // IV[7] ^ f1

  for (uint8 r = 0; r < 10; r++) {
    G(blk, r, 0, v0, v4,  v8, v12);
    G(blk, r, 1, v1, v5,  v9, v13);
    G(blk, r, 2, v2, v6, v10, v14);
    G(blk, r, 3, v3, v7, v11, v15);
    G(blk, r, 4, v0, v5, v10, v15);
    G(blk, r, 5, v1, v6, v11, v12);
    G(blk, r, 6, v2, v7,  v8, v13);
    G(blk, r, 7, v3, v4,  v9, v14);
  }

  H[0] ^= (v0 ^  v8);
  H[1] ^= (v1 ^  v9);
  H[2] ^= (v2 ^ v10);
  H[3] ^= (v3 ^ v11);
  H[4] ^= (v4 ^ v12);
  H[5] ^= (v5 ^ v13);
  H[6] ^= (v6 ^ v14);
  H[7] ^= (v7 ^ v15);
}

#define BLK_SZ SIZEOF(state->queued)

blake2s_state* EXPORT
blake2s_init(blake2s_state* state, const uint8 len/*final hash length 1-32 (8-bit) bytes*/, const uint32* key, const uint8 keylen/*key length 0-32 (8-bit) bytes*/) {
  if (len == 0 || len > BLK_SZ/2 || keylen > BLK_SZ/2) return NULL;

  if (state == NULL) state = malloc(sizeof(*state));
  T[0] = 0;
  T[1] = 0;
  F[0] = 0;
  F[1] = 0;

  H[0] = 0x6a09e667 ^ 0x01010000 ^ len ^ ((uint16)keylen << 8);// IV[0] ^ (Fanout and Maximal depth) ^ (Digest (output hash) byte length) ^ (Key length left-shifted by 8 bits)
  H[1] = 0xbb67ae85;                                           // IV[1]
  H[2] = 0x3c6ef372;                                           // IV[2]
  H[3] = 0xa54ff53a;                                           // IV[3]
  H[4] = 0x510e527f;                                           // IV[4]
  H[5] = 0x9b05688c;                                           // IV[5]
  H[6] = 0x1f83d9ab;                                           // IV[6]
  H[7] = 0x5be0cd19;                                           // IV[7]

  if (keylen == 0) state->bytes = 0;
  else {
    state->bytes = BLK_SZ;
    // Pad key with trailing zeros
    memset((uint8*)state->queued + keylen, 0, (BLK_SZ - keylen) * CHAR_BIT/8); // [CHAR_BIT] http://stackoverflow.com/questions/9727465/will-a-char-always-always-always-have-8-bits#9727562 ; http://stackoverflow.com/questions/284519/can-i-allocate-a-specific-number-of-bits-in-c#287442
    memcpy(state->queued, key, keylen * CHAR_BIT/8);                           // [CHAR_BIT]
  }
  return state;
}

blake2s_state* EXPORT
blake2s(blake2s_state*const state, const uint32* in, size_t bytes/*input length in (8-bit) bytes*/, const bool final, const bool padded/*'in' padded to 64 bytes*/) {
  if (~F[0] == 0) return NULL;                                  // Error: already final?

  if (state->bytes > 0) {
    // Process queued input
    if (state->bytes < BLK_SZ) {
      // Merge unqueued input into up to BLK_SZ of queued input
      const void*const _in = in;
      uint8 c;
      if (bytes <= BLK_SZ - state->bytes) c = bytes;
      else {
        c = BLK_SZ - state->bytes;
        // 'bytes' will be > 0 below, so must update 'in'
        if (c % SIZEOF(*in) != 0) return NULL;                  // Error: unaligned?
        in += c / SIZEOF(*in);
      }
      bytes -= c;
      memcpy((uint8*)state->queued + state->bytes, _in, c * CHAR_BIT/8);       // [CHAR_BIT]
      state->bytes += c;
    }
    if (bytes > 0) { // input buffer not entirely queued?
      // Process queued input separately from processing of unqueued input
      T[0] += BLK_SZ;
      if (T[0] < BLK_SZ) T[1]++; // carry overflow
      b2s_block(state, state->queued);
    } else {
      // Point input buffer at queued input to process it
      in = state->queued;
      bytes = state->bytes;
    }
    state->bytes = 0;
  }

  // Process input buffer
  // All but the final block
  while (bytes > BLK_SZ || (bytes == BLK_SZ && !final)) {
    T[0] += BLK_SZ;
    if (T[0] < BLK_SZ) T[1]++; // carry overflow
    b2s_block(state, in);
    in += 16;
    bytes -= BLK_SZ;
  }

  if (final) {
    // Final block
    F[0] = ~F[0];
    if (bytes < BLK_SZ) {
      if (bytes == 0 && (T[0] != 0 || T[1] != 0)) return NULL;  // Error: nothing to process?
      if (!padded) {
        // Pad with trailing zeros
        memset((uint8*)state->queued + bytes, 0, (BLK_SZ - bytes) * CHAR_BIT/8); // [CHAR_BIT]
        if (in != state->queued) {
          memcpy(state->queued, in, bytes * CHAR_BIT/8);                         // [CHAR_BIT]
          in = state->queued;
        }
      }
    }
    T[0] += bytes;
    if (T[0] < bytes) T[1]++; // carry overflow
    b2s_block(state, in);
  } else if (bytes > 0) {
    // Not final so queue partial block
    state->bytes = bytes;
    if (in != state->queued) memcpy(state->queued, in, bytes * CHAR_BIT/8);    // [CHAR_BIT]
  }
  return state;
}

#define ROTR64(x, bits) ((uint64)(x) >> (bits) | (x) << (64 - (bits))) // logical (not arithematic) right shift >> requires unsigned operand

#undef G
#define G(m, r, i, a, b, c, d)    \
  a += b + m[b2_sigma[r][2*i+0]]; \
  d = ROTR64(d ^ a, 32);          \
  c += d;                         \
  b = ROTR64(b ^ c, 24);          \
  a += b + m[b2_sigma[r][2*i+1]]; \
  d = ROTR64(d ^ a, 16);          \
  c += d;                         \
  b = ROTR64(b ^ c, 63)

static void
b2b_block(blake2b_state*const state, const uint64 blk[16]) {
  uint64 v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15;
   v0 = H[0];
   v1 = H[1];
   v2 = H[2];
   v3 = H[3];
   v4 = H[4];
   v5 = H[5];
   v6 = H[6];
   v7 = H[7];
   v8 = 0x6a09e667f3bcc908;        // IV[0]
   v9 = 0xbb67ae8584caa73b;        // IV[1]
  v10 = 0x3c6ef372fe94f82b;        // IV[2]
  v11 = 0xa54ff53a5f1d36f1;        // IV[3]
  v12 = 0x510e527fade682d1 ^ T[0]; // IV[4] ^ t0
  v13 = 0x9b05688c2b3e6c1f ^ T[1]; // IV[5] ^ t1
  v14 = 0x1f83d9abfb41bd6b ^ F[0]; // IV[6] ^ f0
  v15 = 0x5be0cd19137e2179 ^ F[1]; // IV[7] ^ f1

  for (uint8 r = 0; r < 12; r++) {
    G(blk, r, 0, v0, v4,  v8, v12);
    G(blk, r, 1, v1, v5,  v9, v13);
    G(blk, r, 2, v2, v6, v10, v14);
    G(blk, r, 3, v3, v7, v11, v15);
    G(blk, r, 4, v0, v5, v10, v15);
    G(blk, r, 5, v1, v6, v11, v12);
    G(blk, r, 6, v2, v7,  v8, v13);
    G(blk, r, 7, v3, v4,  v9, v14);
  }

  H[0] ^= (v0 ^  v8);
  H[1] ^= (v1 ^  v9);
  H[2] ^= (v2 ^ v10);
  H[3] ^= (v3 ^ v11);
  H[4] ^= (v4 ^ v12);
  H[5] ^= (v5 ^ v13);
  H[6] ^= (v6 ^ v14);
  H[7] ^= (v7 ^ v15);
}

blake2b_state* // do not EXPORT so EMSCRIPTEN will discard (if not invoked from a C/C++ or specifically exported by the build), because 64-bit arithmetic is emulated
blake2b_init(blake2b_state* state, const uint8 len/*final hash length 1-64 (8-bit) bytes*/, const uint64* key, const uint8 keylen/*key length 0-64 (8-bit) bytes*/) {
  if (len == 0 || len > BLK_SZ/2 || keylen > BLK_SZ/2) return NULL;

  if (state == NULL) state = malloc(sizeof(*state));
  T[0] = 0;
  T[1] = 0;
  F[0] = 0;
  F[1] = 0;

  H[0] = 0x6a09e667f3bcc908 ^ 0x01010000 ^ len ^ ((uint16)keylen << 8);// IV[0] ^ (Fanout and Maximal depth) ^ (Digest (output hash) byte length) ^ (Key length left-shifted by 8 bits)
  H[1] = 0xbb67ae8584caa73b;                                           // IV[1]
  H[2] = 0x3c6ef372fe94f82b;                                           // IV[2]
  H[3] = 0xa54ff53a5f1d36f1;                                           // IV[3]
  H[4] = 0x510e527fade682d1;                                           // IV[4]
  H[5] = 0x9b05688c2b3e6c1f;                                           // IV[5]
  H[6] = 0x1f83d9abfb41bd6b;                                           // IV[6]
  H[7] = 0x5be0cd19137e2179;                                           // IV[7]

  if (keylen == 0) state->bytes = 0;
  else {
    state->bytes = BLK_SZ;
    // Pad key with trailing zeros
    memset((uint8*)state->queued + keylen, 0, (BLK_SZ - keylen) * CHAR_BIT/8); // [CHAR_BIT] http://stackoverflow.com/questions/9727465/will-a-char-always-always-always-have-8-bits#9727562 ; http://stackoverflow.com/questions/284519/can-i-allocate-a-specific-number-of-bits-in-c#287442
    memcpy(state->queued, key, keylen * CHAR_BIT/8);                           // [CHAR_BIT]
  }
  return state;
}

blake2b_state* // do not EXPORT so EMSCRIPTEN will discard (if not invoked from a C/C++ or specifically exported by the build), because 64-bit arithmetic is emulated
blake2b(blake2b_state*const state, const uint64* in, size_t bytes/*input length in (8-bit) bytes*/, const bool final, const bool padded/*'in' padded to 128 bytes*/) {
  if (~F[0] == 0) return NULL;                                  // Error: already final?

  if (state->bytes > 0) {
    // Process queued input
    if (state->bytes < BLK_SZ) {
      // Merge unqueued input into up to BLK_SZ of queued input
      const void*const _in = in;
      uint8 c;
      if (bytes <= BLK_SZ - state->bytes) c = bytes;
      else {
        c = BLK_SZ - state->bytes;
        // 'bytes' will be > 0 below, so must update 'in'
        if (c % SIZEOF(*in) != 0) return NULL;                  // Error: unaligned?
        in += c / SIZEOF(*in);
      }
      bytes -= c;
      memcpy((uint8*)state->queued + state->bytes, _in, c * CHAR_BIT/8);       // [CHAR_BIT]
      state->bytes += c;
    }
    if (bytes > 0) { // input buffer not entirely queued?
      // Process queued input separately from processing of unqueued input
      T[0] += BLK_SZ;
      if (T[0] < BLK_SZ) T[1]++; // carry overflow
      b2b_block(state, state->queued);
    } else {
      // Point input buffer at queued input to process it
      in = state->queued;
      bytes = state->bytes;
    }
    state->bytes = 0;
  }

  // Process input buffer
  // All but the final block
  while (bytes > BLK_SZ || (bytes == BLK_SZ && !final)) {
    T[0] += BLK_SZ;
    if (T[0] < BLK_SZ) T[1]++; // carry overflow
    b2b_block(state, in);
    in += 16;
    bytes -= BLK_SZ;
  }

  if (final) {
    // Final block
    F[0] = ~F[0];
    if (bytes < BLK_SZ) {
      if (bytes == 0 && (T[0] != 0 || T[1] != 0)) return NULL;  // Error: nothing to process?
      if (!padded) {
        // Pad with trailing zeros
        memset((uint8*)state->queued + bytes, 0, (BLK_SZ - bytes) * CHAR_BIT/8); // [CHAR_BIT]
        if (in != state->queued) {
          memcpy(state->queued, in, bytes * CHAR_BIT/8);                         // [CHAR_BIT]
          in = state->queued;
        }
      }
    }
    T[0] += bytes;
    if (T[0] < bytes) T[1]++; // carry overflow
    b2b_block(state, in);
  } else if (bytes > 0) {
    // Not final so queue partial block
    state->bytes = bytes;
    if (in != state->queued) memcpy(state->queued, in, bytes * CHAR_BIT/8);    // [CHAR_BIT]
  }
  return state;
}