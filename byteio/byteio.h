#ifndef _BYTEIO
#define _BYTEIO

#include "../cmacros/c11types.h"
#include "../cmacros/export.h"

/*
Conversion to and from little-endian byte strings.

If the running platform is little-endian, the input buffer is returned (as no conversion is required).
Else the conversion is copied to the output buffer.
If the output buffer is not supplied (i.e. is NULL), it is created with 'malloc'.
*/

const uint8* EXPORT
uint16_tobytes(const uint16*restrict in, uint8*restrict out, size_t bytes/*output length*/);

const uint16* EXPORT
uint16_frombytes(uint16*restrict out, const uint8*restrict in, size_t bytes/*input length*/);

const uint8* EXPORT
uint32_tobytes(const uint32*restrict in, uint8*restrict out, size_t bytes/*output length*/);

const uint32* EXPORT
uint32_frombytes(uint32*restrict out, const uint8*restrict in, size_t bytes/*input length*/);

const uint8* EXPORT
uint64_tobytes(const uint64*restrict in, uint8*restrict out, size_t bytes/*output length*/);

const uint64* EXPORT
uint64_frombytes(uint64*restrict out, const uint8*restrict in, size_t bytes/*input length*/);

/*
The output buffer defaults to NULL if not provided.
Generic function name supported on the non-uint8 type, except where said type
is unavailable because the argument for output buffer was not provided.
*/

#include "../cmacros/variadic.h"

#define   uint16_tobytes_2(a,    c) a, NULL, c
#define   uint16_tobytes_3(a, b, c) a,    b, c
#define   uint16_tobytes(...) VARIADIC(  uint16_tobytes, NUMARG3(__VA_ARGS__), __VA_ARGS__)

#define uint16_frombytes_2(   b, c) NULL, b, c
#define uint16_frombytes_3(a, b, c)    a, b, c
#define uint16_frombytes(...) VARIADIC(uint16_frombytes, NUMARG3(__VA_ARGS__), __VA_ARGS__)

#define   uint32_tobytes_2(a,    c) a, NULL, c
#define   uint32_tobytes_3(a, b, c) a,    b, c
#define   uint32_tobytes(...) VARIADIC(  uint32_tobytes, NUMARG3(__VA_ARGS__), __VA_ARGS__)

#define uint32_frombytes_2(   b, c) NULL, b, c
#define uint32_frombytes_3(a, b, c)    a, b, c
#define uint32_frombytes(...) VARIADIC(uint32_frombytes, NUMARG3(__VA_ARGS__), __VA_ARGS__)

#define   uint64_tobytes_2(a,    c) a, NULL, c
#define   uint64_tobytes_3(a, b, c) a,    b, c
#define   uint64_tobytes(...) VARIADIC(  uint64_tobytes, NUMARG3(__VA_ARGS__), __VA_ARGS__)

#define uint64_frombytes_2(   b, c) NULL, b, c
#define uint64_frombytes_3(a, b, c)    a, b, c
#define uint64_frombytes(...) VARIADIC(uint64_frombytes, NUMARG3(__VA_ARGS__), __VA_ARGS__)

#if defined(__clang__) || !defined(__GNUC__) // http://en.cppreference.com/mwiki/index.php?title=c/language/generic&oldid=81817#Notes
// [+0] converts any array argument to pointer to avoid mismatch error, because http://en.cppreference.com/mwiki/index.php?title=c/language/generic&oldid=81817#Notes
#define   tobytes(a, ...) _Generic((a+0),                                                                                               \
                                         uint16*: uint16_tobytes,                                                                       \
                                         uint32*: uint32_tobytes,                                                                       \
                                         uint64*: uint64_tobytes,                                                                       \
                                   const uint16*: uint16_tobytes,                                                                       \
                                   const uint32*: uint32_tobytes,                                                                       \
                                   const uint64*: uint64_tobytes)  (VARIADIC2(  uint32_tobytes, NUMARG3(a, __VA_ARGS__), a, __VA_ARGS__))

#define frombytes(a, ...) _Generic((a+0),                                                                                               \
                                         uint16*: uint16_frombytes,                                                                     \
                                         uint32*: uint32_frombytes,                                                                     \
                                         uint64*: uint64_frombytes,                                                                     \
                                   const uint16*: uint16_frombytes,                                                                     \
                                   const uint32*: uint32_frombytes,                                                                     \
                                   const uint64*: uint64_frombytes)(VARIADIC2(uint32_frombytes, NUMARG3(a, __VA_ARGS__), a, __VA_ARGS__))
#else
#define   tobytes(a, ...) _Generic((a),                                                                                                 \
                                         uint16*: uint16_tobytes,                                                                       \
                                         uint32*: uint32_tobytes,                                                                       \
                                         uint64*: uint64_tobytes)  (VARIADIC2(  uint32_tobytes, NUMARG3(a, __VA_ARGS__), a, __VA_ARGS__))

#define frombytes(a, ...) _Generic((a),                                                                                                 \
                                         uint16*: uint16_frombytes,                                                                     \
                                         uint32*: uint32_frombytes,                                                                     \
                                         uint64*: uint64_frombytes)(VARIADIC2(uint32_frombytes, NUMARG3(a, __VA_ARGS__), a, __VA_ARGS__))
#endif

/*
Whether the running platform is little-endian.
*/

bool EXPORT is_lilendian();

#endif