#include "hashsig.h"
#include "../blake/blake.h"
#include "../winternitz/winternitz.h"
#include <stdlib.h>
#include <string.h>

#undef hashsig128_sign
#undef hashsig128_keys
#undef hashsig256_sign
#undef hashsig256_keys

typedef struct {
  blake2s_state state1, state2;
  uint32*       key;
  uint32*       sig;
} b2s_key_state;

#define BYTES 16 // 128-bit

static b2s_key_state*
next_sig_key128(b2s_key_state*const state, const uint32 n) {
  // Pad hash outputs with 0
  memset((uint8*)state->key + BYTES, 0, SIZEOF(state->state1.h) * CHAR_BIT/8 - BYTES); // [CHAR_BIT]
  // Next private key
  blake2s_state*const b2state = state->key == &state->state1.h[0] ? &state->state2 : &state->state1;
  blake2s_init(b2state, BYTES, state->key, BYTES); // faster alterative to keying the hash function would be to XOR the input key to the result of the hash,
  blake2s(b2state, state->key, BYTES, /*final*/true, /*zero padded*/true);              // but this speed isn't necessary and the security would be unvetted
  state->key = &b2state->h[0];
  // Next signature key
  blake2s_nested(n, state->sig, state->key, BYTES);
  state->sig += 1;
  return state;
}

uint32* EXPORT
hashsig128_sign(const uint32*const key, const uint32*const msg, uint32* sig) {
  if (sig == NULL) {
    sig = malloc((BYTES*8/2 + /*⌈log₂(3×BYTES×8÷2)÷2⌉*/4) * BYTES);
    if (sig == NULL) return sig;
  }
  b2s_key_state state;
  state.sig = sig; // do not use tagged initialization, because it will 0 initialize the entire struct: http://en.cppreference.com/w/c/language/struct_initialization
  // Pad hash outputs with 0
  memset(&state.state1.padding, 0, SIZEOF(state.state1.padding) * CHAR_BIT/8);         // [CHAR_BIT] http://stackoverflow.com/questions/9727465/will-a-char-always-always-always-have-8-bits#9727562 ; http://stackoverflow.com/questions/284519/can-i-allocate-a-specific-number-of-bits-in-c#287442
  memset(&state.state2.padding, 0, SIZEOF(state.state2.padding) * CHAR_BIT/8);         // [CHAR_BIT]
  // Copy key input to a hash ouput because this is more efficient than if blake2() does the padding
  state.key = &state.state1.h[0];
  memcpy(state.key, key, BYTES);
  if (winternitz(/*sign*/true, &state, (winternitz_callback*)next_sig_key128, msg, BYTES*8, /*2 bit chunks*/2) == NULL)
    return NULL;
  return sig;
}

static uint32*
next_public_key128(uint32*const sig, const uint32 n) {
  blake2s_nested(n, sig, sig, BYTES);
  return sig + 1;
}

bool EXPORT
hashsig128_keys(uint32*const key, const uint32*const msg, uint32*const sig, const bool verify/*= true*/) {
  // Compute the public keys
  const uint32*const nextsig = winternitz(/*verify*/false, sig, (winternitz_callback*)next_public_key128, msg, BYTES*8, /*2 bit chunks*/2);
  if (nextsig == NULL) return false;
  // Hash the public keys
  blake2s_state state;
  size_t bytes = (nextsig - sig) * SIZEOF(*sig) * CHAR_BIT/8; // [CHAR_BIT]
  blake2s_init(&state, bytes); // [CHAR_BIT]
  blake2s(&state, sig, bytes);
  // Verify the hash of the public keys matches?
  if (verify)
    return memcmp(key, &state.h, BYTES) == 0;
  else
    memcpy(key, &state.h, BYTES); // output the hash of the public keys
  return true;
}

#undef BYTES
#define BYTES 32 // 256-bit

static b2s_key_state*
next_sig_key256(b2s_key_state*const state, const uint32 n) {
  // Pad hash outputs with 0
  memset((uint8*)state->key + BYTES, 0, SIZEOF(state->state1.h) * CHAR_BIT/8 - BYTES); // [CHAR_BIT]
  // Next private key
  blake2s_state*const b2state = state->key == &state->state1.h[0] ? &state->state2 : &state->state1;
  blake2s_init(b2state, BYTES, state->key, BYTES); // faster alterative to keying the hash function would be to XOR the input key to the result of the hash,
  blake2s(b2state, state->key, BYTES, /*final*/true, /*zero padded*/true);              // but this speed isn't necessary and the security would be unvetted
  state->key = &b2state->h[0];
  // Next signature key
  blake2s_nested(n, state->sig, state->key, BYTES);
  state->sig += 1;
  return state;
}

uint32* EXPORT
hashsig256_sign(const uint32*const key, const uint32*const msg, uint32* sig) {
  if (sig == NULL) {
    sig = malloc((BYTES*8/2 + /*⌈log₂(3×BYTES×8÷2)÷2⌉*/5) * BYTES);
    if (sig == NULL) return sig;
  }
  b2s_key_state state;
  state.sig = sig; // do not use tagged initialization, because it will 0 initialize the entire struct: http://en.cppreference.com/w/c/language/struct_initialization
  // Pad hash outputs with 0
  memset(&state.state1.padding, 0, SIZEOF(state.state1.padding) * CHAR_BIT/8);         // [CHAR_BIT] http://stackoverflow.com/questions/9727465/will-a-char-always-always-always-have-8-bits#9727562 ; http://stackoverflow.com/questions/284519/can-i-allocate-a-specific-number-of-bits-in-c#287442
  memset(&state.state2.padding, 0, SIZEOF(state.state2.padding) * CHAR_BIT/8);         // [CHAR_BIT]
  // Copy key input to a hash ouput because this is more efficient than if blake2() does the padding
  state.key = &state.state1.h[0];
  memcpy(state.key, key, BYTES);
  if (winternitz(/*sign*/true, &state, (winternitz_callback*)next_sig_key256, msg, BYTES*8, /*2 bit chunks*/2) == NULL)
    return NULL;
  return sig;
}

static uint32*
next_public_key256(uint32*const sig, const uint32 n) {
  blake2s_nested(n, sig, sig, BYTES);
  return sig + 1;
}

bool EXPORT
hashsig256_keys(uint32*const key, const uint32*const msg, uint32*const sig, const bool verify/*= true*/) {
  // Compute the public keys
  const uint32*const nextsig = winternitz(/*verify*/false, sig, (winternitz_callback*)next_public_key256, msg, BYTES*8, /*2 bit chunks*/2);
  if (nextsig == NULL) return false;
  // Hash the public keys
  blake2s_state state;
  size_t bytes = (nextsig - sig) * SIZEOF(*sig) * CHAR_BIT/8; // [CHAR_BIT]
  blake2s_init(&state, bytes); // [CHAR_BIT]
  blake2s(&state, sig, bytes);
  // Verify the hash of the public keys matches?
  if (verify)
    return memcmp(key, &state.h, BYTES) == 0;
  else
    memcpy(key, &state.h, BYTES); // output the hash of the public keys
  return true;
}