#include "byteio.h"
#include "../cmacros/effectful.h"
#include <stdlib.h>

#undef uint16_tobytes
#undef uint16_frombytes
#undef uint32_tobytes
#undef uint32_frombytes
#undef uint64_tobytes
#undef uint64_frombytes

static bool is_lilend = false; // whether the running platform is little-endian
bool EXPORT is_lilendian() { return is_lilend; }

/*
http://stackoverflow.com/questions/10678607/possible-to-initialize-static-variable-by-calling-function#10678726
http://stackoverflow.com/questions/2053029/how-exactly-does-attribute-constructor-work
*/
__attribute__((constructor))
static void init_lilend() {
  uint8 data[4] = {1, 0, 0, 0};
  is_lilend = *(uint32*)data == 1;
}

const uint8* EXPORT
uint16_tobytes(const uint16*restrict in, uint8*restrict out, size_t bytes/*output length*/) {
  if (is_lilend) return (const uint8*)in;
  if (out == NULL) out = malloc(bytes * CHAR_BIT/8); // [CHAR_BIT] http://stackoverflow.com/questions/9727465/will-a-char-always-always-always-have-8-bits#9727562 ; http://stackoverflow.com/questions/284519/can-i-allocate-a-specific-number-of-bits-in-c#287442
  while (bytes >= SIZEOF(*in)) {
    out[0] = *in & 0xff;
    out[1] = *in >> 8;
    in++;
    out += SIZEOF(*in);
    bytes -= SIZEOF(*in);
  }
  if (bytes > 0) {
    out[0] = *in & 0xff;
  }
  return out;
}

const uint16* EXPORT
uint16_frombytes(uint16*restrict out, const uint8*restrict in, size_t bytes/*input length*/) {
  if (is_lilend) return (const uint16*)in;
  if (out == NULL) out = malloc((bytes + PADDING(bytes, SIZEOF(*out))) * CHAR_BIT/8); // [CHAR_BIT]
  while (bytes >= SIZEOF(*out)) {
    *out = (uint16)in[1] << 8 | in[0];
    out++;
    in += SIZEOF(*out);
    bytes -= SIZEOF(*out);
  }
  if (bytes > 0) *out = in[0];
  return out;
}

const uint8* EXPORT
uint32_tobytes(const uint32*restrict in, uint8*restrict out, size_t bytes/*output length*/) {
  if (is_lilend) return (const uint8*)in;
  if (out == NULL) out = malloc(bytes * CHAR_BIT/8); // [CHAR_BIT]
  while (bytes >= SIZEOF(*in)) {
    out[0] = *in       & 0xff;
    out[1] = *in >>  8 & 0xff;
    out[2] = *in >> 16 & 0xff;
    out[3] = *in >> 24;
    in++;
    out += SIZEOF(*in);
    bytes -= SIZEOF(*in);
  }
  if (bytes > 0) {
    out[0] = *in & 0xff;
    if (--bytes > 0) {
      out[1] = *in >> 8 & 0xff;
      if (--bytes > 0)
        out[2] = *in >> 16 & 0xff;
    }
  }
  return out;
}

const uint32* EXPORT
uint32_frombytes(uint32*restrict out, const uint8*restrict in, size_t bytes/*input length*/) {
  if (is_lilend) return (const uint32*)in;
  if (out == NULL) out = malloc((bytes + PADDING(bytes, SIZEOF(*out))) * CHAR_BIT/8); // [CHAR_BIT]
  while (bytes >= SIZEOF(*out)) {
    *out = (((uint32)in[3] << 8 | in[2]) << 8 | in[1]) << 8 | in[0];
    out++;
    in += SIZEOF(*out);
    bytes -= SIZEOF(*out);
  }
  if (bytes > 0) {
    if (bytes == 3) *out = ((uint32)in[2] << 8 | in[1]) << 8 | in[0];
    else if (bytes == 2) *out = (uint32)in[1] << 8 | in[0];
    else *out = in[0];
  }
  return out;
}

const uint8* EXPORT
uint64_tobytes(const uint64*restrict in, uint8*restrict out, size_t bytes/*output length*/) {
  if (is_lilend) return (const uint8*)in;
  if (out == NULL) out = malloc(bytes * CHAR_BIT/8); // [CHAR_BIT]
  while (bytes >= SIZEOF(*in)) {
    out[0] = *in       & 0xff;
    out[1] = *in >>  8 & 0xff;
    out[2] = *in >> 16 & 0xff;
    out[3] = *in >> 24 & 0xff;
    out[4] = *in >> 32 & 0xff;
    out[5] = *in >> 40 & 0xff;
    out[6] = *in >> 48 & 0xff;
    out[7] = *in >> 56;
    in++;
    out += SIZEOF(*in);
    bytes -= SIZEOF(*in);
  }
  if (bytes > 0) {
    out[0] = *in & 0xff;
    if (--bytes > 0) {
      out[1] = *in >> 8 & 0xff;
      if (--bytes > 0) {
        out[2] = *in >> 16 & 0xff;
        if (--bytes > 0) {
          out[3] = *in >> 24 & 0xff;
          if (--bytes > 0) {
            out[4] = *in >> 32 & 0xff;
            if (--bytes > 0) {
              out[5] = *in >> 40 & 0xff;
              if (--bytes > 0)
                out[6] = *in >> 48 & 0xff;
            }
          }
        }
      }
    }
  }
  return out;
}

const uint64* EXPORT
uint64_frombytes(uint64*restrict out, const uint8*restrict in, size_t bytes/*input length*/) {
  if (is_lilend) return (const uint64*)in;
  if (out == NULL) out = malloc((bytes + PADDING(bytes, SIZEOF(*out))) * CHAR_BIT/8); // [CHAR_BIT]
  while (bytes >= SIZEOF(*out)) {
    *out = ((((((uint64)in[7] << 8 | in[6]) << 8 | in[5]) << 8 | in[4]) << 8 | in[3] << 8 | in[2]) << 8 | in[1]) << 8 | in[0];
    out++;
    in += SIZEOF(*out);
    bytes -= SIZEOF(*out);
  }
  switch(bytes) {
  case 7: *out = ((((((uint64)in[6] << 8 | in[5]) << 8 | in[4]) << 8 | in[3]) << 8 | in[2]) << 8 | in[1]) << 8 | in[0]; break;
  case 6: *out = (((((uint64)in[5] << 8 | in[4]) << 8 | in[3]) << 8 | in[2]) << 8 | in[1]) << 8 | in[0]; break;
  case 5: *out = ((((uint64)in[4] << 8 | in[3]) << 8 | in[2]) << 8 | in[1]) << 8 | in[0]; break;
  case 4: *out = (((uint64)in[3] << 8 | in[2]) << 8 | in[1]) << 8 | in[0]; break;
  case 3: *out = ((uint64)in[2] << 8 | in[1]) << 8 | in[0]; break;
  case 2: *out = (uint64)in[1] << 8 | in[0]; break;
  case 1: *out = in[0]; break;
  default: break;
  }
  return out;
}