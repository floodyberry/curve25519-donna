/*
 * Public Domain by Andrew M <liquidsun@gmail.com>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * SSE2 version which parallelizes across ops where possible, otherwise
 * inside ops
 *
 * Because of wildly varying compiler performance, this version is not 
 * intended to be linked against! It should be used to generate the .s
 * to link against (currently icc creates the most efficient code)
 */

#include <string.h>

#define AGGRESSIVE_INLINING

#if defined(_MSC_VER)
  #if defined(AGGRESSIVE_INLINING)
    #undef OPTIONAL_INLINE
    #define OPTIONAL_INLINE __forceinline
  #endif
  typedef unsigned char uint8_t;
  typedef unsigned int uint32_t;
  typedef signed int int32_t;
  typedef unsigned __int64 uint64_t;
  #define MM16 __declspec(align(16))
#else
  #include <stdint.h>
  #if defined(AGGRESSIVE_INLINING)
    #undef OPTIONAL_INLINE
    #define OPTIONAL_INLINE __attribute__((always_inline))
  #endif
  #define MM16 __attribute__((aligned(16)))
#endif

#include <emmintrin.h>
typedef __m128i xmmi;

typedef union packedelem8_t {
  unsigned char u[16];
  xmmi v;
} packedelem8;

typedef union packedelem32_t {
  uint32_t u[4];
  xmmi v;
} packedelem32;

typedef union packedelem64_t {
  uint64_t u[2];
  xmmi v;
} packedelem64;

/* 10 elements + an extra 2 to fit in 3 xmm registers */
typedef uint32_t bignum25519sse2[10+2];
typedef packedelem32 packed32bignum25519sse2[5];
typedef packedelem64 packed64bignum25519sse2[10];

static const packedelem32 MM16 sse2_bot32bitmask = {{0xffffffff, 0x00000000, 0xffffffff, 0x00000000}};
static const packedelem32 MM16 sse2_top32bitmask = {{0x00000000, 0xffffffff, 0x00000000, 0xffffffff}};
static const packedelem32 MM16 sse2_top64bitmask = {{0x00000000, 0x00000000, 0xffffffff, 0xffffffff}};
static const packedelem32 MM16 sse2_bot64bitmask = {{0xffffffff, 0xffffffff, 0x00000000, 0x00000000}};

/* reduction masks */
static const packedelem64 MM16 packedmask26 = {{0x03ffffff, 0x03ffffff}};
static const packedelem64 MM16 packedmask25 = {{0x01ffffff, 0x01ffffff}};
static const packedelem32 MM16 packedmask2625 = {{0x3ffffff,0,0x1ffffff,0}};
static const packedelem32 MM16 packedmask26262626 = {{0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff}};
static const packedelem32 MM16 packedmask25252525 = {{0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff}};

/* multipliers */
static const packedelem64 MM16 packednineteen = {{19, 19}};
static const packedelem64 MM16 packednineteenone = {{19, 1}};
static const packedelem64 MM16 packedthirtyeight = {{38, 38}};
static const packedelem64 MM16 packed3819 = {{19*2,19}};
static const packedelem64 MM16 packed9638 = {{19*4,19*2}};

/* 121666,121665 */
static const packedelem64 packed121666121665 = {{121666, 121665}};

/* 2*(2^255 - 19) = 0 mod p */
static const packedelem32 MM16 packed32zeromodp0 = {{0x7ffffda,0x7ffffda,0x3fffffe,0x3fffffe}};
static const packedelem32 MM16 packed32zeromodp1 = {{0x7fffffe,0x7fffffe,0x3fffffe,0x3fffffe}};

/* Copy a bignum to another: out = in */
static inline void OPTIONAL_INLINE
curve25519_copy_sse2(bignum25519sse2 out, const bignum25519sse2 in) {
  xmmi x0,x1,x2;
  x0 = _mm_load_si128((xmmi*)in + 0);
  x1 = _mm_load_si128((xmmi*)in + 1);
  x2 = _mm_load_si128((xmmi*)in + 2);
  _mm_store_si128((xmmi*)out + 0, x0);
  _mm_store_si128((xmmi*)out + 1, x1);
  _mm_store_si128((xmmi*)out + 2, x2);
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static inline void OPTIONAL_INLINE
curve25519_expand_sse2(bignum25519sse2 out, const unsigned char in[32]) {
  #define F(n,start,shift,mask) \
    out[n] = \
      ((((uint32_t) in[start + 0]) | \
      ((uint32_t) in[start + 1]) << 8 | \
      ((uint32_t) in[start + 2]) << 16 | \
      ((uint32_t) in[start + 3]) << 24) >> shift) & mask;

  F(0, 0, 0, 0x3ffffff);
  F(1, 3, 2, 0x1ffffff);
  F(2, 6, 3, 0x3ffffff);
  F(3, 9, 5, 0x1ffffff);
  F(4, 12, 6, 0x3ffffff);
  F(5, 16, 0, 0x1ffffff);
  F(6, 19, 1, 0x3ffffff);
  F(7, 22, 3, 0x1ffffff);
  F(8, 25, 4, 0x3ffffff);
  F(9, 28, 6, 0x1ffffff);
  #undef F

  out[11] = 0;
  out[12] = 0;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static inline void OPTIONAL_INLINE
curve25519_contract_sse2(unsigned char out[32], const bignum25519sse2 in) {
  MM16 bignum25519sse2 f;
  curve25519_copy_sse2(f, in);

  #define carry_pass() \
    f[1] += f[0] >> 26; f[0] &= 0x3ffffff; \
    f[2] += f[1] >> 25; f[1] &= 0x1ffffff; \
    f[3] += f[2] >> 26; f[2] &= 0x3ffffff; \
    f[4] += f[3] >> 25; f[3] &= 0x1ffffff; \
    f[5] += f[4] >> 26; f[4] &= 0x3ffffff; \
    f[6] += f[5] >> 25; f[5] &= 0x1ffffff; \
    f[7] += f[6] >> 26; f[6] &= 0x3ffffff; \
    f[8] += f[7] >> 25; f[7] &= 0x1ffffff; \
    f[9] += f[8] >> 26; f[8] &= 0x3ffffff;

  #define carry_pass_full() \
    carry_pass() \
    f[0] += 19 * (f[9] >> 25); f[9] &= 0x1ffffff;

  #define carry_pass_final() \
    carry_pass() \
    f[9] &= 0x1ffffff;

  carry_pass_full()
  carry_pass_full()

  /* now t is between 0 and 2^255-1, properly carried. */
  /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
  f[0] += 19;
  carry_pass_full()

  /* now between 19 and 2^255-1 in both cases, and offset by 19. */
  f[0] += (1 << 26) - 19;
  f[1] += (1 << 25) - 1;
  f[2] += (1 << 26) - 1;
  f[3] += (1 << 25) - 1;
  f[4] += (1 << 26) - 1;
  f[5] += (1 << 25) - 1;
  f[6] += (1 << 26) - 1;
  f[7] += (1 << 25) - 1;
  f[8] += (1 << 26) - 1;
  f[9] += (1 << 25) - 1;

  /* now between 2^255 and 2^256-20, and offset by 2^255. */
  carry_pass_final()

  #undef carry_pass
  #undef carry_full
  #undef carry_final

  f[1] <<= 2;
  f[2] <<= 3;
  f[3] <<= 5;
  f[4] <<= 6;
  f[6] <<= 1;
  f[7] <<= 3;
  f[8] <<= 4;
  f[9] <<= 6;

  #define F(i, s) \
    out[s+0] |= (unsigned char )(f[i] & 0xff); \
    out[s+1] = (unsigned char )((f[i] >> 8) & 0xff); \
    out[s+2] = (unsigned char )((f[i] >> 16) & 0xff); \
    out[s+3] = (unsigned char )((f[i] >> 24) & 0xff);

  out[0] = 0;
  out[16] = 0;
  F(0,0);
  F(1,3);
  F(2,6);
  F(3,9);
  F(4,12);
  F(5,16);
  F(6,19);
  F(7,22);
  F(8,25);
  F(9,28);
  #undef F
}

/*
 * Maybe swap the contents of two felem arrays (@a and @b), each 5 elements
 * long. Perform the swap iff @swap is non-zero.
 */
static inline void OPTIONAL_INLINE
curve25519_swap_conditional_sse2(bignum25519sse2 a, bignum25519sse2 b, uint32_t iswap) {
  const uint32_t swap = (uint32_t)(-(int32_t)iswap);
  xmmi a0,a1,a2,b0,b1,b2,x0,x1,x2;
  xmmi mask = _mm_cvtsi32_si128(swap);
  mask = _mm_shuffle_epi32(mask, 0);
  a0 = _mm_load_si128((xmmi *)a + 0);
  a1 = _mm_load_si128((xmmi *)a + 1);
  b0 = _mm_load_si128((xmmi *)b + 0);
  b1 = _mm_load_si128((xmmi *)b + 1);
  b0 = _mm_xor_si128(a0, b0);
  b1 = _mm_xor_si128(a1, b1);
  x0 = _mm_and_si128(b0, mask);
  x1 = _mm_and_si128(b1, mask);
  x0 = _mm_xor_si128(x0, a0);
  x1 = _mm_xor_si128(x1, a1);
  a0 = _mm_xor_si128(x0, b0);
  a1 = _mm_xor_si128(x1, b1);
  _mm_store_si128((xmmi *)a + 0, x0);
  _mm_store_si128((xmmi *)a + 1, x1);
  _mm_store_si128((xmmi *)b + 0, a0);
  _mm_store_si128((xmmi *)b + 1, a1);

  a2 = _mm_load_si128((xmmi *)a + 2);
  b2 = _mm_load_si128((xmmi *)b + 2);
  b2 = _mm_xor_si128(a2, b2);
  x2 = _mm_and_si128(b2, mask);
  x2 = _mm_xor_si128(x2, a2);
  a2 = _mm_xor_si128(x2, b2);
  _mm_store_si128((xmmi *)b + 2, a2);
  _mm_store_si128((xmmi *)a + 2, x2);
}

/* interleave two bignums */
static inline void OPTIONAL_INLINE
curve25519_tangle32(packedelem32 *out, const bignum25519sse2 x, const bignum25519sse2 z) {
  xmmi x0,x1,x2,z0,z1,z2;

  x0 = _mm_load_si128((xmmi *)(x + 0));
  x1 = _mm_load_si128((xmmi *)(x + 4));
  x2 = _mm_load_si128((xmmi *)(x + 8));
  z0 = _mm_load_si128((xmmi *)(z + 0));
  z1 = _mm_load_si128((xmmi *)(z + 4));
  z2 = _mm_load_si128((xmmi *)(z + 8));

  out[0].v = _mm_unpacklo_epi32(x0, z0);
  out[1].v = _mm_unpackhi_epi32(x0, z0);
  out[2].v = _mm_unpacklo_epi32(x1, z1);
  out[3].v = _mm_unpackhi_epi32(x1, z1);
  out[4].v = _mm_unpacklo_epi32(x2, z2);
}

/* split a packed bignum in to it's two parts */
static inline void OPTIONAL_INLINE
curve25519_untangle64(bignum25519sse2 x, bignum25519sse2 z, const packedelem64 *in) {
  _mm_store_si128((xmmi *)(x + 0), _mm_unpacklo_epi64(_mm_unpacklo_epi32(in[0].v, in[1].v), _mm_unpacklo_epi32(in[2].v, in[3].v)));
  _mm_store_si128((xmmi *)(x + 4), _mm_unpacklo_epi64(_mm_unpacklo_epi32(in[4].v, in[5].v), _mm_unpacklo_epi32(in[6].v, in[7].v)));
  _mm_store_si128((xmmi *)(x + 8), _mm_unpacklo_epi32(in[8].v, in[9].v)                                                          );
  _mm_store_si128((xmmi *)(z + 0), _mm_unpacklo_epi64(_mm_unpackhi_epi32(in[0].v, in[1].v), _mm_unpackhi_epi32(in[2].v, in[3].v)));
  _mm_store_si128((xmmi *)(z + 4), _mm_unpacklo_epi64(_mm_unpackhi_epi32(in[4].v, in[5].v), _mm_unpackhi_epi32(in[6].v, in[7].v)));
  _mm_store_si128((xmmi *)(z + 8), _mm_unpackhi_epi32(in[8].v, in[9].v)                                                          );
}

/* add two packed bignums */
static inline void OPTIONAL_INLINE
curve25519_add_packed32_sse2(packedelem32 *out, const packedelem32 *r, const packedelem32 *s) {
  out[0].v = _mm_add_epi32(r[0].v, s[0].v);
  out[1].v = _mm_add_epi32(r[1].v, s[1].v);
  out[2].v = _mm_add_epi32(r[2].v, s[2].v);
  out[3].v = _mm_add_epi32(r[3].v, s[3].v);
  out[4].v = _mm_add_epi32(r[4].v, s[4].v);
}

/* subtract two packed bignums */
static inline void OPTIONAL_INLINE
curve25519_sub_packed32_sse2(packedelem32 *out, const packedelem32 *r, const packedelem32 *s) {
  xmmi r0,r1,r2,r3,r4;
  xmmi s0,s1,s2,s3,s4,s5;
  xmmi c1,c2;

  r0 = _mm_add_epi32(r[0].v, packed32zeromodp0.v);
  r1 = _mm_add_epi32(r[1].v, packed32zeromodp1.v);
  r2 = _mm_add_epi32(r[2].v, packed32zeromodp1.v);
  r3 = _mm_add_epi32(r[3].v, packed32zeromodp1.v);
  r4 = _mm_add_epi32(r[4].v, packed32zeromodp1.v);
  r0 = _mm_sub_epi32(r0, s[0].v); // 00 11
  r1 = _mm_sub_epi32(r1, s[1].v); // 22 33
  r2 = _mm_sub_epi32(r2, s[2].v); // 44 55
  r3 = _mm_sub_epi32(r3, s[3].v); // 66 77
  r4 = _mm_sub_epi32(r4, s[4].v); // 88 99

  s0 = _mm_unpacklo_epi64(r0, r2); // 00 44
  s1 = _mm_unpackhi_epi64(r0, r2); // 11 55
  s2 = _mm_unpacklo_epi64(r1, r3); // 22 66
  s3 = _mm_unpackhi_epi64(r1, r3); // 33 77
  s4 = _mm_unpacklo_epi64(_mm_setzero_si128(), r4);  // 00 88
  s5 = _mm_unpackhi_epi64(_mm_setzero_si128(), r4);  // 00 99

  c1 = _mm_srli_epi32(s0, 26); c2 = _mm_srli_epi32(s2, 26); s0 = _mm_and_si128(s0, packedmask26262626.v); s2 = _mm_and_si128(s2, packedmask26262626.v); s1 = _mm_add_epi32(s1, c1); s3 = _mm_add_epi32(s3, c2);
  c1 = _mm_srli_epi32(s1, 25); c2 = _mm_srli_epi32(s3, 25); s1 = _mm_and_si128(s1, packedmask25252525.v); s3 = _mm_and_si128(s3, packedmask25252525.v); s2 = _mm_add_epi32(s2, c1); s4 = _mm_add_epi32(s4, _mm_unpackhi_epi64(_mm_setzero_si128(), c2)); s0 = _mm_add_epi32(s0, _mm_unpacklo_epi64(_mm_setzero_si128(), c2));
  c1 = _mm_srli_epi32(s2, 26); c2 = _mm_srli_epi32(s4, 26); s2 = _mm_and_si128(s2, packedmask26262626.v); s4 = _mm_and_si128(s4, packedmask26262626.v); s3 = _mm_add_epi32(s3, c1); s5 = _mm_add_epi32(s5, c2);
  c1 = _mm_srli_epi32(s3, 25); c2 = _mm_srli_epi32(s5, 25); s3 = _mm_and_si128(s3, packedmask25252525.v); s5 = _mm_and_si128(s5, packedmask25252525.v); s4 = _mm_add_epi32(s4, c1); s0 = _mm_add_epi32(s0, _mm_or_si128(_mm_slli_si128(c1, 8), _mm_srli_si128(_mm_add_epi32(_mm_add_epi32(_mm_slli_epi32(c2, 4), _mm_slli_epi32(c2, 1)), c2), 8)));
  c1 = _mm_srli_epi32(s0, 26); c2 = _mm_srli_epi32(s2, 26); s0 = _mm_and_si128(s0, packedmask26262626.v); s2 = _mm_and_si128(s2, packedmask26262626.v); s1 = _mm_add_epi32(s1, c1); s3 = _mm_add_epi32(s3, c2);

  out[0].v = _mm_unpacklo_epi64(s0, s1); // 00 11
  out[1].v = _mm_unpacklo_epi64(s2, s3); // 22 33
  out[2].v = _mm_unpackhi_epi64(s0, s1); // 44 55
  out[3].v = _mm_unpackhi_epi64(s2, s3); // 66 77
  out[4].v = _mm_unpackhi_epi64(s4, s5); // 88 99
}

/* multiply two packed bignums */
static inline void OPTIONAL_INLINE
curve25519_mul_packed64_sse2(packedelem64 *out, const packedelem64 *r, const packedelem64 *s) {
  xmmi r1,r2,r3,r4,r5,r6,r7,r8,r9;
  xmmi r1_2,r3_2,r5_2,r7_2,r9_2;
  xmmi c1,c2;

  out[0].v = _mm_mul_epu32(r[0].v, s[0].v);
  out[1].v = _mm_add_epi64(_mm_mul_epu32(r[0].v, s[1].v), _mm_mul_epu32(r[1].v, s[0].v));
  r1_2 = _mm_slli_epi32(r[1].v, 1);
  out[2].v = _mm_add_epi64(_mm_mul_epu32(r[0].v, s[2].v), _mm_add_epi64(_mm_mul_epu32(r1_2  , s[1].v), _mm_mul_epu32(r[2].v, s[0].v)));
  out[3].v = _mm_add_epi64(_mm_mul_epu32(r[0].v, s[3].v), _mm_add_epi64(_mm_mul_epu32(r[1].v, s[2].v), _mm_add_epi64(_mm_mul_epu32(r[2].v, s[1].v), _mm_mul_epu32(r[3].v, s[0].v))));
  r3_2 = _mm_slli_epi32(r[3].v, 1);
  out[4].v = _mm_add_epi64(_mm_mul_epu32(r[0].v, s[4].v), _mm_add_epi64(_mm_mul_epu32(r1_2  , s[3].v), _mm_add_epi64(_mm_mul_epu32(r[2].v, s[2].v), _mm_add_epi64(_mm_mul_epu32(r3_2  , s[1].v), _mm_mul_epu32(r[4].v, s[0].v)))));
  out[5].v = _mm_add_epi64(_mm_mul_epu32(r[0].v, s[5].v), _mm_add_epi64(_mm_mul_epu32(r[1].v, s[4].v), _mm_add_epi64(_mm_mul_epu32(r[2].v, s[3].v), _mm_add_epi64(_mm_mul_epu32(r[3].v, s[2].v), _mm_add_epi64(_mm_mul_epu32(r[4].v, s[1].v), _mm_mul_epu32(r[5].v, s[0].v))))));
  r5_2 = _mm_slli_epi32(r[5].v, 1);
  out[6].v = _mm_add_epi64(_mm_mul_epu32(r[0].v, s[6].v), _mm_add_epi64(_mm_mul_epu32(r1_2  , s[5].v), _mm_add_epi64(_mm_mul_epu32(r[2].v, s[4].v), _mm_add_epi64(_mm_mul_epu32(r3_2  , s[3].v), _mm_add_epi64(_mm_mul_epu32(r[4].v, s[2].v), _mm_add_epi64(_mm_mul_epu32(r5_2  , s[1].v), _mm_mul_epu32(r[6].v, s[0].v)))))));
  out[7].v = _mm_add_epi64(_mm_mul_epu32(r[0].v, s[7].v), _mm_add_epi64(_mm_mul_epu32(r[1].v, s[6].v), _mm_add_epi64(_mm_mul_epu32(r[2].v, s[5].v), _mm_add_epi64(_mm_mul_epu32(r[3].v, s[4].v), _mm_add_epi64(_mm_mul_epu32(r[4].v, s[3].v), _mm_add_epi64(_mm_mul_epu32(r[5].v, s[2].v), _mm_add_epi64(_mm_mul_epu32(r[6].v, s[1].v), _mm_mul_epu32(r[7].v  , s[0].v))))))));
  r7_2 = _mm_slli_epi32(r[7].v, 1);
  out[8].v = _mm_add_epi64(_mm_mul_epu32(r[0].v, s[8].v), _mm_add_epi64(_mm_mul_epu32(r1_2  , s[7].v), _mm_add_epi64(_mm_mul_epu32(r[2].v, s[6].v), _mm_add_epi64(_mm_mul_epu32(r3_2  , s[5].v), _mm_add_epi64(_mm_mul_epu32(r[4].v, s[4].v), _mm_add_epi64(_mm_mul_epu32(r5_2  , s[3].v), _mm_add_epi64(_mm_mul_epu32(r[6].v, s[2].v), _mm_add_epi64(_mm_mul_epu32(r7_2  , s[1].v), _mm_mul_epu32(r[8].v, s[0].v)))))))));
  out[9].v = _mm_add_epi64(_mm_mul_epu32(r[0].v, s[9].v), _mm_add_epi64(_mm_mul_epu32(r[1].v, s[8].v), _mm_add_epi64(_mm_mul_epu32(r[2].v, s[7].v), _mm_add_epi64(_mm_mul_epu32(r[3].v, s[6].v), _mm_add_epi64(_mm_mul_epu32(r[4].v, s[5].v), _mm_add_epi64(_mm_mul_epu32(r[5].v, s[4].v), _mm_add_epi64(_mm_mul_epu32(r[6].v, s[3].v), _mm_add_epi64(_mm_mul_epu32(r[7].v, s[2].v), _mm_add_epi64(_mm_mul_epu32(r[8].v, s[1].v), _mm_mul_epu32(r[9].v, s[0].v))))))))));

  r1 = _mm_mul_epu32(r[1].v, packednineteen.v);
  r2 = _mm_mul_epu32(r[2].v, packednineteen.v);
  r1_2 = _mm_slli_epi32(r1, 1);
  r3 = _mm_mul_epu32(r[3].v, packednineteen.v);
  r4 = _mm_mul_epu32(r[4].v, packednineteen.v);
  r3_2 = _mm_slli_epi32(r3, 1);
  r5 = _mm_mul_epu32(r[5].v, packednineteen.v);
  r6 = _mm_mul_epu32(r[6].v, packednineteen.v);
  r5_2 = _mm_slli_epi32(r5, 1);
  r7 = _mm_mul_epu32(r[7].v, packednineteen.v);
  r8 = _mm_mul_epu32(r[8].v, packednineteen.v);
  r7_2 = _mm_slli_epi32(r7, 1);
  r9 = _mm_mul_epu32(r[9].v, packednineteen.v);
  r9_2 = _mm_slli_epi32(r9, 1);

  out[0].v = _mm_add_epi64(out[0].v, _mm_add_epi64(_mm_mul_epu32(r9_2, s[1].v), _mm_add_epi64(_mm_mul_epu32(r8, s[2].v), _mm_add_epi64(_mm_mul_epu32(r7_2, s[3].v), _mm_add_epi64(_mm_mul_epu32(r6, s[4].v), _mm_add_epi64(_mm_mul_epu32(r5_2, s[5].v), _mm_add_epi64(_mm_mul_epu32(r4, s[6].v), _mm_add_epi64(_mm_mul_epu32(r3_2, s[7].v), _mm_add_epi64(_mm_mul_epu32(r2, s[8].v), _mm_mul_epu32(r1_2, s[9].v))))))))));
  out[1].v = _mm_add_epi64(out[1].v, _mm_add_epi64(_mm_mul_epu32(r9  , s[2].v), _mm_add_epi64(_mm_mul_epu32(r8, s[3].v), _mm_add_epi64(_mm_mul_epu32(r7  , s[4].v), _mm_add_epi64(_mm_mul_epu32(r6, s[5].v), _mm_add_epi64(_mm_mul_epu32(r5  , s[6].v), _mm_add_epi64(_mm_mul_epu32(r4, s[7].v), _mm_add_epi64(_mm_mul_epu32(r3  , s[8].v), _mm_mul_epu32(r2, s[9].v)))))))));
  out[2].v = _mm_add_epi64(out[2].v, _mm_add_epi64(_mm_mul_epu32(r9_2, s[3].v), _mm_add_epi64(_mm_mul_epu32(r8, s[4].v), _mm_add_epi64(_mm_mul_epu32(r7_2, s[5].v), _mm_add_epi64(_mm_mul_epu32(r6, s[6].v), _mm_add_epi64(_mm_mul_epu32(r5_2, s[7].v), _mm_add_epi64(_mm_mul_epu32(r4, s[8].v), _mm_mul_epu32(r3_2, s[9].v))))))));
  out[3].v = _mm_add_epi64(out[3].v, _mm_add_epi64(_mm_mul_epu32(r9  , s[4].v), _mm_add_epi64(_mm_mul_epu32(r8, s[5].v), _mm_add_epi64(_mm_mul_epu32(r7  , s[6].v), _mm_add_epi64(_mm_mul_epu32(r6, s[7].v), _mm_add_epi64(_mm_mul_epu32(r5  , s[8].v), _mm_mul_epu32(r4, s[9].v)))))));
  out[4].v = _mm_add_epi64(out[4].v, _mm_add_epi64(_mm_mul_epu32(r9_2, s[5].v), _mm_add_epi64(_mm_mul_epu32(r8, s[6].v), _mm_add_epi64(_mm_mul_epu32(r7_2, s[7].v), _mm_add_epi64(_mm_mul_epu32(r6, s[8].v), _mm_mul_epu32(r5_2, s[9].v))))));
  out[5].v = _mm_add_epi64(out[5].v, _mm_add_epi64(_mm_mul_epu32(r9  , s[6].v), _mm_add_epi64(_mm_mul_epu32(r8, s[7].v), _mm_add_epi64(_mm_mul_epu32(r7  , s[8].v), _mm_mul_epu32(r6, s[9].v)))));
  out[6].v = _mm_add_epi64(out[6].v, _mm_add_epi64(_mm_mul_epu32(r9_2, s[7].v), _mm_add_epi64(_mm_mul_epu32(r8, s[8].v), _mm_mul_epu32(r7_2, s[9].v))));
  out[7].v = _mm_add_epi64(out[7].v, _mm_add_epi64(_mm_mul_epu32(r9  , s[8].v), _mm_mul_epu32(r8, s[9].v)));
  out[8].v = _mm_add_epi64(out[8].v, _mm_mul_epu32(r9_2, s[9].v));

  c1 = _mm_srli_epi64(out[0].v, 26); c2 = _mm_srli_epi64(out[4].v, 26); out[0].v = _mm_and_si128(out[0].v, packedmask26.v); out[4].v = _mm_and_si128(out[4].v, packedmask26.v); out[1].v = _mm_add_epi64(out[1].v, c1); out[5].v = _mm_add_epi64(out[5].v, c2);
  c1 = _mm_srli_epi64(out[1].v, 25); c2 = _mm_srli_epi64(out[5].v, 25); out[1].v = _mm_and_si128(out[1].v, packedmask25.v); out[5].v = _mm_and_si128(out[5].v, packedmask25.v); out[2].v = _mm_add_epi64(out[2].v, c1); out[6].v = _mm_add_epi64(out[6].v, c2);
  c1 = _mm_srli_epi64(out[2].v, 26); c2 = _mm_srli_epi64(out[6].v, 26); out[2].v = _mm_and_si128(out[2].v, packedmask26.v); out[6].v = _mm_and_si128(out[6].v, packedmask26.v); out[3].v = _mm_add_epi64(out[3].v, c1); out[7].v = _mm_add_epi64(out[7].v, c2);
  c1 = _mm_srli_epi64(out[3].v, 25); c2 = _mm_srli_epi64(out[7].v, 25); out[3].v = _mm_and_si128(out[3].v, packedmask25.v); out[7].v = _mm_and_si128(out[7].v, packedmask25.v); out[4].v = _mm_add_epi64(out[4].v, c1); out[8].v = _mm_add_epi64(out[8].v, c2);
                                     c2 = _mm_srli_epi64(out[8].v, 26);                                                     out[8].v = _mm_and_si128(out[8].v, packedmask26.v);                                         out[9].v = _mm_add_epi64(out[9].v, c2);
                                     c2 = _mm_srli_epi64(out[9].v, 25);                                                     out[9].v = _mm_and_si128(out[9].v, packedmask25.v);                                         out[0].v = _mm_add_epi64(out[0].v, _mm_mul_epu32(c2, packednineteen.v));
  c1 = _mm_srli_epi64(out[0].v, 26); c2 = _mm_srli_epi64(out[4].v, 26); out[0].v = _mm_and_si128(out[0].v, packedmask26.v); out[4].v = _mm_and_si128(out[4].v, packedmask26.v); out[1].v = _mm_add_epi64(out[1].v, c1); out[5].v = _mm_add_epi64(out[5].v, c2);
}

/* multiply a bignum */
static void
curve25519_mul_sse2(bignum25519sse2 out, const bignum25519sse2 r, const bignum25519sse2 s) {
  xmmi m01,m23,m45,m67,m89;
  xmmi m0123,m4567;
  xmmi s0123,s4567;
  xmmi s01,s23,s45,s67,s89;
  xmmi s12,s34,s56,s78,s9;
  xmmi r0,r2,r4,r6,r8;
  xmmi r1,r3,r5,r7,r9;
  xmmi r119,r219,r319,r419,r519,r619,r719,r819,r919;
  xmmi c1,c2,c3;

  s0123 = _mm_load_si128((xmmi*)s + 0);
  s01 = _mm_shuffle_epi32(s0123,_MM_SHUFFLE(3,1,2,0));
  s12 = _mm_shuffle_epi32(s0123, _MM_SHUFFLE(2,2,1,1));
  s23 = _mm_shuffle_epi32(s0123,_MM_SHUFFLE(3,3,2,2));
  s4567 = _mm_load_si128((xmmi*)s + 1);
  s34 = _mm_unpacklo_epi64(_mm_srli_si128(s0123,12),s4567);
  s45 = _mm_shuffle_epi32(s4567,_MM_SHUFFLE(3,1,2,0));
  s56 = _mm_shuffle_epi32(s4567, _MM_SHUFFLE(2,2,1,1));
  s67 = _mm_shuffle_epi32(s4567,_MM_SHUFFLE(3,3,2,2));
  s89 = _mm_load_si128((xmmi*)s + 2);
  s78 = _mm_unpacklo_epi64(_mm_srli_si128(s4567,12),s89);
  s89 = _mm_shuffle_epi32(s89,_MM_SHUFFLE(3,1,2,0));
  s9 = _mm_shuffle_epi32(s89, _MM_SHUFFLE(3,3,2,2));

  r0 = _mm_load_si128((xmmi*)r + 0);
  r1 = _mm_shuffle_epi32(r0, _MM_SHUFFLE(1,1,1,1));
  r1 = _mm_add_epi64(r1, _mm_and_si128(r1, sse2_top64bitmask.v));
  r2 = _mm_shuffle_epi32(r0, _MM_SHUFFLE(2,2,2,2));
  r3 = _mm_shuffle_epi32(r0, _MM_SHUFFLE(3,3,3,3));
  r3 = _mm_add_epi64(r3, _mm_and_si128(r3, sse2_top64bitmask.v));
  r0 = _mm_shuffle_epi32(r0, _MM_SHUFFLE(0,0,0,0));
  r4 = _mm_load_si128((xmmi*)r + 1);
  r5 = _mm_shuffle_epi32(r4, _MM_SHUFFLE(1,1,1,1));
  r5 = _mm_add_epi64(r5, _mm_and_si128(r5, sse2_top64bitmask.v));
  r6 = _mm_shuffle_epi32(r4, _MM_SHUFFLE(2,2,2,2));
  r7 = _mm_shuffle_epi32(r4, _MM_SHUFFLE(3,3,3,3));
  r7 = _mm_add_epi64(r7, _mm_and_si128(r7, sse2_top64bitmask.v));
  r4 = _mm_shuffle_epi32(r4, _MM_SHUFFLE(0,0,0,0));
  r8 = _mm_load_si128((xmmi*)r + 2);
  r9 = _mm_shuffle_epi32(r8, _MM_SHUFFLE(3,1,3,1));
  r9 = _mm_add_epi64(r9, _mm_and_si128(r9, sse2_top64bitmask.v));
  r8 = _mm_shuffle_epi32(r8, _MM_SHUFFLE(3,0,3,0));

  m01 = _mm_mul_epu32(r1,s01);
  m23 = _mm_mul_epu32(r1,s23);
  m45 = _mm_mul_epu32(r1,s45);
  m67 = _mm_mul_epu32(r1,s67);
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r3,s01));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r3,s23));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r3,s45));
  m89 = _mm_mul_epu32(r1,s89);
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r5,s01));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r5,s23));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r3,s67));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r7,s01));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r5,s45));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r7,s23));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r9,s01));

  /* shift up */
  m89 = _mm_unpackhi_epi64(m67,_mm_slli_si128(m89,8));
  m67 = _mm_unpackhi_epi64(m45,_mm_slli_si128(m67,8));
  m45 = _mm_unpackhi_epi64(m23,_mm_slli_si128(m45,8));
  m23 = _mm_unpackhi_epi64(m01,_mm_slli_si128(m23,8));
  m01 = _mm_unpackhi_epi64(_mm_setzero_si128(),_mm_slli_si128(m01,8));

  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r0,s01));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r0,s23));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r0,s45));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r0,s67));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r2,s01));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r2,s23));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r4,s23));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r0,s89));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r4,s01));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r2,s45));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r2,s67));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r6,s01));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r4,s45));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r6,s23));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r8,s01));

  r219 = _mm_mul_epu32(r2, packednineteen.v);
  r419 = _mm_mul_epu32(r4, packednineteen.v);
  r619 = _mm_mul_epu32(r6, packednineteen.v);
  r819 = _mm_mul_epu32(r8, packednineteen.v);
  r119 = _mm_shuffle_epi32(r1,_MM_SHUFFLE(0,0,2,2)); r119 = _mm_mul_epu32(r119, packednineteen.v);
  r319 = _mm_shuffle_epi32(r3,_MM_SHUFFLE(0,0,2,2)); r319 = _mm_mul_epu32(r319, packednineteen.v);
  r519 = _mm_shuffle_epi32(r5,_MM_SHUFFLE(0,0,2,2)); r519 = _mm_mul_epu32(r519, packednineteen.v);
  r719 = _mm_shuffle_epi32(r7,_MM_SHUFFLE(0,0,2,2)); r719 = _mm_mul_epu32(r719, packednineteen.v);
  r919 = _mm_shuffle_epi32(r9,_MM_SHUFFLE(0,0,2,2)); r919 = _mm_mul_epu32(r919, packednineteen.v);

  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r919,s12));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r919,s34));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r919,s56));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r919,s78));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r719,s34));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r719,s56));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r719,s78));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r719,s9));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r519,s56));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r519,s78));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r519,s9));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r819,s89));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r319,s78));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r319,s9));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r619,s89));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r919,s9));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r819,s23));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r819,s45));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r819,s67));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r619,s45));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r619,s67));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r419,s67));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r419,s89));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r219,s89));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r119,s9));

  r0 = _mm_unpacklo_epi64(m01, m45);
  r1 = _mm_unpackhi_epi64(m01, m45);
  r2 = _mm_unpacklo_epi64(m23, m67);
  r3 = _mm_unpackhi_epi64(m23, m67);
  r4 = _mm_unpacklo_epi64(m89, m89);
  r5 = _mm_unpackhi_epi64(m89, m89);

  c1 = _mm_srli_epi64(r0, 26); c2 = _mm_srli_epi64(r2, 26); r0 = _mm_and_si128(r0, packedmask26.v); r2 = _mm_and_si128(r2, packedmask26.v); r1 = _mm_add_epi64(r1, c1); r3 = _mm_add_epi64(r3, c2);
  c1 = _mm_srli_epi64(r1, 25); c2 = _mm_srli_epi64(r3, 25); r1 = _mm_and_si128(r1, packedmask25.v); r3 = _mm_and_si128(r3, packedmask25.v); r2 = _mm_add_epi64(r2, c1); r4 = _mm_add_epi64(r4, c2); c3 = _mm_slli_si128(c2, 8);
  c1 = _mm_srli_epi64(r4, 26);                                                                      r4 = _mm_and_si128(r4, packedmask26.v);                             r5 = _mm_add_epi64(r5, c1);
  c1 = _mm_srli_epi64(r5, 25);                                                                      r5 = _mm_and_si128(r5, packedmask25.v);                             r0 = _mm_add_epi64(r0, _mm_unpackhi_epi64(_mm_mul_epu32(c1, packednineteen.v), c3));
  c1 = _mm_srli_epi64(r0, 26); c2 = _mm_srli_epi64(r2, 26); r0 = _mm_and_si128(r0, packedmask26.v); r2 = _mm_and_si128(r2, packedmask26.v); r1 = _mm_add_epi64(r1, c1); r3 = _mm_add_epi64(r3, c2);

  m0123 = _mm_unpacklo_epi32(r0, r1);
  m4567 = _mm_unpackhi_epi32(r0, r1);
  m0123 = _mm_unpacklo_epi64(m0123, _mm_unpacklo_epi32(r2, r3));
  m4567 = _mm_unpacklo_epi64(m4567, _mm_unpackhi_epi32(r2, r3));
  m89 = _mm_unpackhi_epi32(r4, r5);

  _mm_store_si128((xmmi*)out + 0, m0123);
  _mm_store_si128((xmmi*)out + 1, m4567);
  _mm_store_si128((xmmi*)out + 2, m89);
}

typedef struct bignum25519sse2mulprecomp_t {
  xmmi r0,r2,r4,r6,r8;
  xmmi r1,r3,r5,r7,r9;
  xmmi r119,r219,r319,r419,r519,r619,r719,r819,r919;
} bignum25519sse2mulprecomp;

/* precompute a constant to multiply by */
static inline void OPTIONAL_INLINE
curve25519_mul_sse2_precomp(bignum25519sse2mulprecomp *pre, const bignum25519sse2 r) {
  pre->r0 = _mm_load_si128((xmmi*)r + 0);
  pre->r1 = _mm_shuffle_epi32(pre->r0, _MM_SHUFFLE(1,1,1,1));
  pre->r1 = _mm_add_epi64(pre->r1, _mm_and_si128(pre->r1, sse2_top64bitmask.v));
  pre->r2 = _mm_shuffle_epi32(pre->r0, _MM_SHUFFLE(2,2,2,2));
  pre->r3 = _mm_shuffle_epi32(pre->r0, _MM_SHUFFLE(3,3,3,3));
  pre->r3 = _mm_add_epi64(pre->r3, _mm_and_si128(pre->r3, sse2_top64bitmask.v));
  pre->r0 = _mm_shuffle_epi32(pre->r0, _MM_SHUFFLE(0,0,0,0));
  pre->r4 = _mm_load_si128((xmmi*)r + 1);
  pre->r5 = _mm_shuffle_epi32(pre->r4, _MM_SHUFFLE(1,1,1,1));
  pre->r5 = _mm_add_epi64(pre->r5, _mm_and_si128(pre->r5, sse2_top64bitmask.v));
  pre->r6 = _mm_shuffle_epi32(pre->r4, _MM_SHUFFLE(2,2,2,2));
  pre->r7 = _mm_shuffle_epi32(pre->r4, _MM_SHUFFLE(3,3,3,3));
  pre->r7 = _mm_add_epi64(pre->r7, _mm_and_si128(pre->r7, sse2_top64bitmask.v));
  pre->r4 = _mm_shuffle_epi32(pre->r4, _MM_SHUFFLE(0,0,0,0));
  pre->r8 = _mm_load_si128((xmmi*)r + 2);
  pre->r9 = _mm_shuffle_epi32(pre->r8, _MM_SHUFFLE(3,1,3,1));
  pre->r9 = _mm_add_epi64(pre->r9, _mm_and_si128(pre->r9, sse2_top64bitmask.v));
  pre->r8 = _mm_shuffle_epi32(pre->r8, _MM_SHUFFLE(3,0,3,0));

  pre->r219 = _mm_mul_epu32(pre->r2, packednineteen.v);
  pre->r419 = _mm_mul_epu32(pre->r4, packednineteen.v);
  pre->r619 = _mm_mul_epu32(pre->r6, packednineteen.v);
  pre->r819 = _mm_mul_epu32(pre->r8, packednineteen.v);
  pre->r119 = _mm_shuffle_epi32(pre->r1,_MM_SHUFFLE(0,0,2,2)); pre->r119 = _mm_mul_epu32(pre->r119, packednineteen.v);
  pre->r319 = _mm_shuffle_epi32(pre->r3,_MM_SHUFFLE(0,0,2,2)); pre->r319 = _mm_mul_epu32(pre->r319, packednineteen.v);
  pre->r519 = _mm_shuffle_epi32(pre->r5,_MM_SHUFFLE(0,0,2,2)); pre->r519 = _mm_mul_epu32(pre->r519, packednineteen.v);
  pre->r719 = _mm_shuffle_epi32(pre->r7,_MM_SHUFFLE(0,0,2,2)); pre->r719 = _mm_mul_epu32(pre->r719, packednineteen.v);
  pre->r919 = _mm_shuffle_epi32(pre->r9,_MM_SHUFFLE(0,0,2,2)); pre->r919 = _mm_mul_epu32(pre->r919, packednineteen.v);
}


/* multiply a bignum by a pre-computed constant */
static inline void OPTIONAL_INLINE
curve25519_mul_precomp_sse2(bignum25519sse2 out, const bignum25519sse2 s, const bignum25519sse2mulprecomp *r) {
  xmmi m01,m23,m45,m67,m89;
  xmmi m0123,m4567;
  xmmi s0123,s4567;
  xmmi s01,s23,s45,s67,s89;
  xmmi s12,s34,s56,s78,s9;
  xmmi r0,r1,r2,r3,r4,r5;
  xmmi c1,c2,c3;

  s0123 = _mm_load_si128((xmmi*)s + 0);
  s01 = _mm_shuffle_epi32(s0123,_MM_SHUFFLE(3,1,2,0));
  s12 = _mm_shuffle_epi32(s0123, _MM_SHUFFLE(2,2,1,1));
  s23 = _mm_shuffle_epi32(s0123,_MM_SHUFFLE(3,3,2,2));
  s4567 = _mm_load_si128((xmmi*)s + 1);
  s34 = _mm_unpacklo_epi64(_mm_srli_si128(s0123,12),s4567);
  s45 = _mm_shuffle_epi32(s4567,_MM_SHUFFLE(3,1,2,0));
  s56 = _mm_shuffle_epi32(s4567, _MM_SHUFFLE(2,2,1,1));
  s67 = _mm_shuffle_epi32(s4567,_MM_SHUFFLE(3,3,2,2));
  s89 = _mm_load_si128((xmmi*)s + 2);
  s78 = _mm_unpacklo_epi64(_mm_srli_si128(s4567,12),s89);
  s89 = _mm_shuffle_epi32(s89,_MM_SHUFFLE(3,1,2,0));
  s9 = _mm_shuffle_epi32(s89, _MM_SHUFFLE(3,3,2,2));

  m01 = _mm_mul_epu32(r->r1,s01);
  m23 = _mm_mul_epu32(r->r1,s23);
  m45 = _mm_mul_epu32(r->r1,s45);
  m67 = _mm_mul_epu32(r->r1,s67);
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r->r3,s01));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r->r3,s23));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r->r3,s45));
  m89 = _mm_mul_epu32(r->r1,s89);
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r->r5,s01));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r->r5,s23));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r->r3,s67));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r->r7,s01));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r->r5,s45));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r->r7,s23));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r->r9,s01));

  /* shift up */
  m89 = _mm_unpackhi_epi64(m67,_mm_slli_si128(m89,8));
  m67 = _mm_unpackhi_epi64(m45,_mm_slli_si128(m67,8));
  m45 = _mm_unpackhi_epi64(m23,_mm_slli_si128(m45,8));
  m23 = _mm_unpackhi_epi64(m01,_mm_slli_si128(m23,8));
  m01 = _mm_unpackhi_epi64(_mm_setzero_si128(),_mm_slli_si128(m01,8));

  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r->r0,s01));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r->r0,s23));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r->r0,s45));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r->r0,s67));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r->r2,s01));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r->r2,s23));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r->r4,s23));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r->r0,s89));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r->r4,s01));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r->r2,s45));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r->r2,s67));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r->r6,s01));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r->r4,s45));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r->r6,s23));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r->r8,s01));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r->r919,s12));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r->r919,s34));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r->r919,s56));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r->r919,s78));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r->r719,s34));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r->r719,s56));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r->r719,s78));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r->r719,s9));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r->r519,s56));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r->r519,s78));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r->r519,s9));
  m67 = _mm_add_epi64(m67,_mm_mul_epu32(r->r819,s89));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r->r319,s78));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r->r319,s9));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r->r619,s89));
  m89 = _mm_add_epi64(m89,_mm_mul_epu32(r->r919,s9));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r->r819,s23));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r->r819,s45));
  m45 = _mm_add_epi64(m45,_mm_mul_epu32(r->r819,s67));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r->r619,s45));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r->r619,s67));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r->r419,s67));
  m23 = _mm_add_epi64(m23,_mm_mul_epu32(r->r419,s89));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r->r219,s89));
  m01 = _mm_add_epi64(m01,_mm_mul_epu32(r->r119,s9));

  r0 = _mm_unpacklo_epi64(m01, m45);
  r1 = _mm_unpackhi_epi64(m01, m45);
  r2 = _mm_unpacklo_epi64(m23, m67);
  r3 = _mm_unpackhi_epi64(m23, m67);
  r4 = _mm_unpacklo_epi64(m89, m89);
  r5 = _mm_unpackhi_epi64(m89, m89);

  c1 = _mm_srli_epi64(r0, 26); c2 = _mm_srli_epi64(r2, 26); r0 = _mm_and_si128(r0, packedmask26.v); r2 = _mm_and_si128(r2, packedmask26.v); r1 = _mm_add_epi64(r1, c1); r3 = _mm_add_epi64(r3, c2);
  c1 = _mm_srli_epi64(r1, 25); c2 = _mm_srli_epi64(r3, 25); r1 = _mm_and_si128(r1, packedmask25.v); r3 = _mm_and_si128(r3, packedmask25.v); r2 = _mm_add_epi64(r2, c1); r4 = _mm_add_epi64(r4, c2); c3 = _mm_slli_si128(c2, 8);
  c1 = _mm_srli_epi64(r4, 26);                                                                      r4 = _mm_and_si128(r4, packedmask26.v);                             r5 = _mm_add_epi64(r5, c1);
  c1 = _mm_srli_epi64(r5, 25);                                                                      r5 = _mm_and_si128(r5, packedmask25.v);                             r0 = _mm_add_epi64(r0, _mm_unpackhi_epi64(_mm_mul_epu32(c1, packednineteen.v), c3));
  c1 = _mm_srli_epi64(r0, 26); c2 = _mm_srli_epi64(r2, 26); r0 = _mm_and_si128(r0, packedmask26.v); r2 = _mm_and_si128(r2, packedmask26.v); r1 = _mm_add_epi64(r1, c1); r3 = _mm_add_epi64(r3, c2);

  m0123 = _mm_unpacklo_epi32(r0, r1);
  m4567 = _mm_unpackhi_epi32(r0, r1);
  m0123 = _mm_unpacklo_epi64(m0123, _mm_unpacklo_epi32(r2, r3));
  m4567 = _mm_unpacklo_epi64(m4567, _mm_unpackhi_epi32(r2, r3));
  m89 = _mm_unpackhi_epi32(r4, r5);

  _mm_store_si128((xmmi*)out + 0, m0123);
  _mm_store_si128((xmmi*)out + 1, m4567);
  _mm_store_si128((xmmi*)out + 2, m89);
}

/* square a bignum 'count' times */
static void
curve25519_square_times_sse2(bignum25519sse2 r, const bignum25519sse2 in, int count) {
  xmmi m01,m23,m45,m67,m89;
  xmmi r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
  xmmi r0a,r1a,r2a,r3a,r7a,r9a;
  xmmi r0123,r4567;
  xmmi r01,r23,r45,r67,r6x,r89,r8x;
  xmmi r12,r34,r56,r78,r9x;
  xmmi r5619;
  xmmi c1,c2,c3;

  r0123 = _mm_load_si128((xmmi*)in + 0);
  r01 = _mm_shuffle_epi32(r0123,_MM_SHUFFLE(3,1,2,0));
  r23 = _mm_shuffle_epi32(r0123,_MM_SHUFFLE(3,3,2,2));
  r4567 = _mm_load_si128((xmmi*)in + 1);
  r45 = _mm_shuffle_epi32(r4567,_MM_SHUFFLE(3,1,2,0));
  r67 = _mm_shuffle_epi32(r4567,_MM_SHUFFLE(3,3,2,2));
  r89 = _mm_load_si128((xmmi*)in + 2);
  r89 = _mm_shuffle_epi32(r89,_MM_SHUFFLE(3,1,2,0));

  do {
    r12 = _mm_unpackhi_epi64(r01, _mm_slli_si128(r23, 8));
    r0 = _mm_shuffle_epi32(r01, _MM_SHUFFLE(0,0,0,0));
    r0 = _mm_add_epi64(r0, _mm_and_si128(r0, sse2_top64bitmask.v));
    r0a = _mm_shuffle_epi32(r0,_MM_SHUFFLE(3,2,1,2));
    r1 = _mm_shuffle_epi32(r01, _MM_SHUFFLE(2,2,2,2));
    r2 = _mm_shuffle_epi32(r23, _MM_SHUFFLE(0,0,0,0));
    r2 = _mm_add_epi64(r2, _mm_and_si128(r2, sse2_top64bitmask.v));
    r2a = _mm_shuffle_epi32(r2,_MM_SHUFFLE(3,2,1,2));
    r3 = _mm_shuffle_epi32(r23, _MM_SHUFFLE(2,2,2,2));
    r34 = _mm_unpackhi_epi64(r23, _mm_slli_si128(r45, 8));
    r4 = _mm_shuffle_epi32(r45, _MM_SHUFFLE(0,0,0,0));
    r4 = _mm_add_epi64(r4, _mm_and_si128(r4, sse2_top64bitmask.v));
    r56 = _mm_unpackhi_epi64(r45, _mm_slli_si128(r67, 8));
    r5619 = _mm_mul_epu32(r56, packednineteen.v);
    r5 = _mm_shuffle_epi32(r5619, _MM_SHUFFLE(1,1,1,0));
    r6 = _mm_shuffle_epi32(r5619, _MM_SHUFFLE(3,2,3,2));
    r78 = _mm_unpackhi_epi64(r67, _mm_slli_si128(r89, 8));
    r6x = _mm_unpacklo_epi64(r67, _mm_setzero_si128());
    r7 = _mm_shuffle_epi32(r67, _MM_SHUFFLE(2,2,2,2));
    r7 = _mm_mul_epu32(r7, packed3819.v);
    r7a = _mm_shuffle_epi32(r7, _MM_SHUFFLE(3,3,3,2));
    r8x = _mm_unpacklo_epi64(r89, _mm_setzero_si128());
    r8 = _mm_shuffle_epi32(r89, _MM_SHUFFLE(0,0,0,0));
    r8 = _mm_mul_epu32(r8, packednineteen.v);
    r9  = _mm_shuffle_epi32(r89, _MM_SHUFFLE(2,2,2,2));
    r9x  = _mm_slli_epi32(_mm_shuffle_epi32(r89, _MM_SHUFFLE(3,3,3,2)), 1);
    r9 = _mm_mul_epu32(r9, packed3819.v);
    r9a = _mm_shuffle_epi32(r9, _MM_SHUFFLE(2,2,2,2));

    m01 = _mm_mul_epu32(r01, r0);
    m23 = _mm_mul_epu32(r23, r0a);
    m45 = _mm_mul_epu32(r45, r0a);
    m45 = _mm_add_epi64(m45, _mm_mul_epu32(r23, r2));
    r23 = _mm_slli_epi32(r23, 1);
    m67 = _mm_mul_epu32(r67, r0a);
    m67 = _mm_add_epi64(m67, _mm_mul_epu32(r45, r2a));
    m89 = _mm_mul_epu32(r89, r0a);
    m89 = _mm_add_epi64(m89, _mm_mul_epu32(r67, r2a));
    r67 = _mm_slli_epi32(r67, 1);
    m89 = _mm_add_epi64(m89, _mm_mul_epu32(r45, r4));
    r45 = _mm_slli_epi32(r45, 1);

    r1 = _mm_slli_epi32(r1, 1);
    r3 = _mm_slli_epi32(r3, 1);
    r1a = _mm_add_epi64(r1, _mm_and_si128(r1, sse2_bot64bitmask.v));
    r3a = _mm_add_epi64(r3, _mm_and_si128(r3, sse2_bot64bitmask.v));

    m23 = _mm_add_epi64(m23, _mm_mul_epu32(r12, r1));
    m45 = _mm_add_epi64(m45, _mm_mul_epu32(r34, r1a));
    m67 = _mm_add_epi64(m67, _mm_mul_epu32(r56, r1a));
    m67 = _mm_add_epi64(m67, _mm_mul_epu32(r34, r3));
    r34 = _mm_slli_epi32(r34, 1);
    m89 = _mm_add_epi64(m89, _mm_mul_epu32(r78, r1a));
    r78 = _mm_slli_epi32(r78, 1);
    m89 = _mm_add_epi64(m89, _mm_mul_epu32(r56, r3a));
    r56 = _mm_slli_epi32(r56, 1);

    m01 = _mm_add_epi64(m01, _mm_mul_epu32(_mm_slli_epi32(r12, 1), r9));
    m01 = _mm_add_epi64(m01, _mm_mul_epu32(r34, r7));
    m23 = _mm_add_epi64(m23, _mm_mul_epu32(r34, r9));
    m01 = _mm_add_epi64(m01, _mm_mul_epu32(r56, r5));
    m23 = _mm_add_epi64(m23, _mm_mul_epu32(r56, r7));
    m45 = _mm_add_epi64(m45, _mm_mul_epu32(r56, r9));
    m01 = _mm_add_epi64(m01, _mm_mul_epu32(r23, r8));
    m01 = _mm_add_epi64(m01, _mm_mul_epu32(r45, r6));
    m23 = _mm_add_epi64(m23, _mm_mul_epu32(r45, r8));
    m23 = _mm_add_epi64(m23, _mm_mul_epu32(r6x, r6));
    m45 = _mm_add_epi64(m45, _mm_mul_epu32(r78, r7a));
    m67 = _mm_add_epi64(m67, _mm_mul_epu32(r78, r9));
    m45 = _mm_add_epi64(m45, _mm_mul_epu32(r67, r8));
    m67 = _mm_add_epi64(m67, _mm_mul_epu32(r8x, r8));
    m89 = _mm_add_epi64(m89, _mm_mul_epu32(r9x, r9a));

    r0 = _mm_unpacklo_epi64(m01, m45);
    r1 = _mm_unpackhi_epi64(m01, m45);
    r2 = _mm_unpacklo_epi64(m23, m67);
    r3 = _mm_unpackhi_epi64(m23, m67);
    r4 = _mm_unpacklo_epi64(m89, m89);
    r5 = _mm_unpackhi_epi64(m89, m89);

    c1 = _mm_srli_epi64(r0, 26); c2 = _mm_srli_epi64(r2, 26); r0 = _mm_and_si128(r0, packedmask26.v); r2 = _mm_and_si128(r2, packedmask26.v); r1 = _mm_add_epi64(r1, c1); r3 = _mm_add_epi64(r3, c2);
    c1 = _mm_srli_epi64(r1, 25); c2 = _mm_srli_epi64(r3, 25); r1 = _mm_and_si128(r1, packedmask25.v); r3 = _mm_and_si128(r3, packedmask25.v); r2 = _mm_add_epi64(r2, c1); r4 = _mm_add_epi64(r4, c2); c3 = _mm_slli_si128(c2, 8);
    c1 = _mm_srli_epi64(r4, 26);                                                                      r4 = _mm_and_si128(r4, packedmask26.v);                             r5 = _mm_add_epi64(r5, c1);
    c1 = _mm_srli_epi64(r5, 25);                                                                      r5 = _mm_and_si128(r5, packedmask25.v);                             r0 = _mm_add_epi64(r0, _mm_unpackhi_epi64(_mm_mul_epu32(c1, packednineteen.v), c3));
    c1 = _mm_srli_epi64(r0, 26); c2 = _mm_srli_epi64(r2, 26); r0 = _mm_and_si128(r0, packedmask26.v); r2 = _mm_and_si128(r2, packedmask26.v); r1 = _mm_add_epi64(r1, c1); r3 = _mm_add_epi64(r3, c2);

    r01 = _mm_unpacklo_epi64(r0, r1);
    r45 = _mm_unpackhi_epi64(r0, r1);
    r23 = _mm_unpacklo_epi64(r2, r3);
    r67 = _mm_unpackhi_epi64(r2, r3);
    r89 = _mm_unpackhi_epi64(r4, r5);
  } while (--count);

  r0123 = _mm_shuffle_epi32(r23, _MM_SHUFFLE(2,0,3,3));
  r4567 = _mm_shuffle_epi32(r67, _MM_SHUFFLE(2,0,3,3));
  r0123 = _mm_or_si128(r0123, _mm_shuffle_epi32(r01, _MM_SHUFFLE(3,3,2,0)));
  r4567 = _mm_or_si128(r4567, _mm_shuffle_epi32(r45, _MM_SHUFFLE(3,3,2,0)));
  r89 = _mm_shuffle_epi32(r89, _MM_SHUFFLE(3,3,2,0));

  _mm_store_si128((xmmi*)r + 0, r0123);
  _mm_store_si128((xmmi*)r + 1, r4567);
  _mm_store_si128((xmmi*)r + 2, r89);
}

/* square two packed bignums */
static inline void OPTIONAL_INLINE
curve25519_square_packed64_sse2(packedelem64 *out, const packedelem64 *r) {
  xmmi r0,r1,r2,r3;
  xmmi r1_2,r3_2,r4_2,r5_2,r6_2,r7_2;
  xmmi d5,d6,d7,d8,d9;
  xmmi c1,c2;

  r0 = r[0].v;
  r1 = r[1].v;
  r2 = r[2].v;
  r3 = r[3].v;

  out[0].v = _mm_mul_epu32(r0, r0);
  r0 = _mm_slli_epi32(r0, 1);
  out[1].v = _mm_mul_epu32(r0, r1);
  r1_2 = _mm_slli_epi32(r1, 1);
  out[2].v = _mm_add_epi64(_mm_mul_epu32(r0, r2    ), _mm_mul_epu32(r1, r1_2));
  r1 = r1_2;
  out[3].v = _mm_add_epi64(_mm_mul_epu32(r0, r3    ), _mm_mul_epu32(r1, r2  ));
  r3_2 = _mm_slli_epi32(r3, 1);
  out[4].v = _mm_add_epi64(_mm_mul_epu32(r0, r[4].v), _mm_add_epi64(_mm_mul_epu32(r1, r3_2  ), _mm_mul_epu32(r2, r2)));
  r2 = _mm_slli_epi32(r2, 1);
  out[5].v = _mm_add_epi64(_mm_mul_epu32(r0, r[5].v), _mm_add_epi64(_mm_mul_epu32(r1, r[4].v), _mm_mul_epu32(r2, r3)));
  r5_2 = _mm_slli_epi32(r[5].v, 1);
  out[6].v = _mm_add_epi64(_mm_mul_epu32(r0, r[6].v), _mm_add_epi64(_mm_mul_epu32(r1, r5_2  ), _mm_add_epi64(_mm_mul_epu32(r2, r[4].v), _mm_mul_epu32(r3, r3_2  ))));
  r3 = r3_2;
  out[7].v = _mm_add_epi64(_mm_mul_epu32(r0, r[7].v), _mm_add_epi64(_mm_mul_epu32(r1, r[6].v), _mm_add_epi64(_mm_mul_epu32(r2, r[5].v), _mm_mul_epu32(r3, r[4].v))));
  r7_2 = _mm_slli_epi32(r[7].v, 1);
  out[8].v = _mm_add_epi64(_mm_mul_epu32(r0, r[8].v), _mm_add_epi64(_mm_mul_epu32(r1, r7_2  ), _mm_add_epi64(_mm_mul_epu32(r2, r[6].v), _mm_add_epi64(_mm_mul_epu32(r3, r5_2  ), _mm_mul_epu32(r[4].v, r[4].v)))));
  out[9].v = _mm_add_epi64(_mm_mul_epu32(r0, r[9].v), _mm_add_epi64(_mm_mul_epu32(r1, r[8].v), _mm_add_epi64(_mm_mul_epu32(r2, r[7].v), _mm_add_epi64(_mm_mul_epu32(r3, r[6].v), _mm_mul_epu32(r[4].v, r5_2  )))));

  d5 = _mm_mul_epu32(r[5].v, packedthirtyeight.v);
  d6 = _mm_mul_epu32(r[6].v, packednineteen.v);
  d7 = _mm_mul_epu32(r[7].v, packedthirtyeight.v);
  d8 = _mm_mul_epu32(r[8].v, packednineteen.v);
  d9 = _mm_mul_epu32(r[9].v, packedthirtyeight.v);

  r4_2 = _mm_slli_epi32(r[4].v, 1);
  r6_2 = _mm_slli_epi32(r[6].v, 1);
  out[0].v = _mm_add_epi64(out[0].v, _mm_add_epi64(_mm_mul_epu32(d9, r1                   ), _mm_add_epi64(_mm_mul_epu32(d8, r2  ), _mm_add_epi64(_mm_mul_epu32(d7, r3    ), _mm_add_epi64(_mm_mul_epu32(d6, r4_2), _mm_mul_epu32(d5, r[5].v))))));
  out[1].v = _mm_add_epi64(out[1].v, _mm_add_epi64(_mm_mul_epu32(d9, _mm_srli_epi32(r2, 1)), _mm_add_epi64(_mm_mul_epu32(d8, r3  ), _mm_add_epi64(_mm_mul_epu32(d7, r[4].v), _mm_mul_epu32(d6, r5_2  )))));
  out[2].v = _mm_add_epi64(out[2].v, _mm_add_epi64(_mm_mul_epu32(d9, r3                   ), _mm_add_epi64(_mm_mul_epu32(d8, r4_2), _mm_add_epi64(_mm_mul_epu32(d7, r5_2  ), _mm_mul_epu32(d6, r[6].v)))));
  out[3].v = _mm_add_epi64(out[3].v, _mm_add_epi64(_mm_mul_epu32(d9, r[4].v               ), _mm_add_epi64(_mm_mul_epu32(d8, r5_2), _mm_mul_epu32(d7, r[6].v))));
  out[4].v = _mm_add_epi64(out[4].v, _mm_add_epi64(_mm_mul_epu32(d9, r5_2                 ), _mm_add_epi64(_mm_mul_epu32(d8, r6_2), _mm_mul_epu32(d7, r[7].v))));
  out[5].v = _mm_add_epi64(out[5].v, _mm_add_epi64(_mm_mul_epu32(d9, r[6].v               ), _mm_mul_epu32(d8, r7_2  )));
  out[6].v = _mm_add_epi64(out[6].v, _mm_add_epi64(_mm_mul_epu32(d9, r7_2                 ), _mm_mul_epu32(d8, r[8].v)));
  out[7].v = _mm_add_epi64(out[7].v, _mm_mul_epu32(d9, r[8].v));
  out[8].v = _mm_add_epi64(out[8].v, _mm_mul_epu32(d9, r[9].v));

  c1 = _mm_srli_epi64(out[0].v, 26); c2 = _mm_srli_epi64(out[4].v, 26); out[0].v = _mm_and_si128(out[0].v, packedmask26.v); out[4].v = _mm_and_si128(out[4].v, packedmask26.v); out[1].v = _mm_add_epi64(out[1].v, c1); out[5].v = _mm_add_epi64(out[5].v, c2);
  c1 = _mm_srli_epi64(out[1].v, 25); c2 = _mm_srli_epi64(out[5].v, 25); out[1].v = _mm_and_si128(out[1].v, packedmask25.v); out[5].v = _mm_and_si128(out[5].v, packedmask25.v); out[2].v = _mm_add_epi64(out[2].v, c1); out[6].v = _mm_add_epi64(out[6].v, c2);
  c1 = _mm_srli_epi64(out[2].v, 26); c2 = _mm_srli_epi64(out[6].v, 26); out[2].v = _mm_and_si128(out[2].v, packedmask26.v); out[6].v = _mm_and_si128(out[6].v, packedmask26.v); out[3].v = _mm_add_epi64(out[3].v, c1); out[7].v = _mm_add_epi64(out[7].v, c2);
  c1 = _mm_srli_epi64(out[3].v, 25); c2 = _mm_srli_epi64(out[7].v, 25); out[3].v = _mm_and_si128(out[3].v, packedmask25.v); out[7].v = _mm_and_si128(out[7].v, packedmask25.v); out[4].v = _mm_add_epi64(out[4].v, c1); out[8].v = _mm_add_epi64(out[8].v, c2);
                                     c2 = _mm_srli_epi64(out[8].v, 26);                                                     out[8].v = _mm_and_si128(out[8].v, packedmask26.v);                                         out[9].v = _mm_add_epi64(out[9].v, c2);
                                     c2 = _mm_srli_epi64(out[9].v, 25);                                                     out[9].v = _mm_and_si128(out[9].v, packedmask25.v);                                         out[0].v = _mm_add_epi64(out[0].v, _mm_mul_epu32(c2, packednineteen.v));
  c1 = _mm_srli_epi64(out[0].v, 26); c2 = _mm_srli_epi64(out[4].v, 26); out[0].v = _mm_and_si128(out[0].v, packedmask26.v); out[4].v = _mm_and_si128(out[4].v, packedmask26.v); out[1].v = _mm_add_epi64(out[1].v, c1); out[5].v = _mm_add_epi64(out[5].v, c2);
}

/* make [nqx+nqz,nqpqx+nqpqz], [nqpqx-nqpqz,nqx-nqz] from [nqx+nqz,nqpqx+nqpqz], [nqx-nqz,nqpqx-nqpqz] */
static inline void OPTIONAL_INLINE
curve25519_make_nqpq(packedelem64 *primex, packedelem64 *primez, const packedelem32 *pqx, const packedelem32 *pqz) {
  primex[0].v = _mm_shuffle_epi32(pqx[0].v, _MM_SHUFFLE(1,1,0,0));
  primex[1].v = _mm_shuffle_epi32(pqx[0].v, _MM_SHUFFLE(3,3,2,2));
  primex[2].v = _mm_shuffle_epi32(pqx[1].v, _MM_SHUFFLE(1,1,0,0));
  primex[3].v = _mm_shuffle_epi32(pqx[1].v, _MM_SHUFFLE(3,3,2,2));
  primex[4].v = _mm_shuffle_epi32(pqx[2].v, _MM_SHUFFLE(1,1,0,0));
  primex[5].v = _mm_shuffle_epi32(pqx[2].v, _MM_SHUFFLE(3,3,2,2));
  primex[6].v = _mm_shuffle_epi32(pqx[3].v, _MM_SHUFFLE(1,1,0,0));
  primex[7].v = _mm_shuffle_epi32(pqx[3].v, _MM_SHUFFLE(3,3,2,2));
  primex[8].v = _mm_shuffle_epi32(pqx[4].v, _MM_SHUFFLE(1,1,0,0));
  primex[9].v = _mm_shuffle_epi32(pqx[4].v, _MM_SHUFFLE(3,3,2,2));
  primez[0].v = _mm_shuffle_epi32(pqz[0].v, _MM_SHUFFLE(0,0,1,1));
  primez[1].v = _mm_shuffle_epi32(pqz[0].v, _MM_SHUFFLE(2,2,3,3));
  primez[2].v = _mm_shuffle_epi32(pqz[1].v, _MM_SHUFFLE(0,0,1,1));
  primez[3].v = _mm_shuffle_epi32(pqz[1].v, _MM_SHUFFLE(2,2,3,3));
  primez[4].v = _mm_shuffle_epi32(pqz[2].v, _MM_SHUFFLE(0,0,1,1));
  primez[5].v = _mm_shuffle_epi32(pqz[2].v, _MM_SHUFFLE(2,2,3,3));
  primez[6].v = _mm_shuffle_epi32(pqz[3].v, _MM_SHUFFLE(0,0,1,1));
  primez[7].v = _mm_shuffle_epi32(pqz[3].v, _MM_SHUFFLE(2,2,3,3));
  primez[8].v = _mm_shuffle_epi32(pqz[4].v, _MM_SHUFFLE(0,0,1,1));
  primez[9].v = _mm_shuffle_epi32(pqz[4].v, _MM_SHUFFLE(2,2,3,3));
}

/* make [nqx+nqz,nqx-nqz] from [nqx+nqz,nqpqx+nqpqz], [nqx-nqz,nqpqx-nqpqz] */
static inline void OPTIONAL_INLINE
curve25519_make_nq(packedelem64 *nq, const packedelem32 *pqx, const packedelem32 *pqz) {
  nq[0].v = _mm_unpacklo_epi64(pqx[0].v, pqz[0].v);
  nq[1].v = _mm_unpackhi_epi64(pqx[0].v, pqz[0].v);
  nq[2].v = _mm_unpacklo_epi64(pqx[1].v, pqz[1].v);
  nq[3].v = _mm_unpackhi_epi64(pqx[1].v, pqz[1].v);
  nq[4].v = _mm_unpacklo_epi64(pqx[2].v, pqz[2].v);
  nq[5].v = _mm_unpackhi_epi64(pqx[2].v, pqz[2].v);
  nq[6].v = _mm_unpacklo_epi64(pqx[3].v, pqz[3].v);
  nq[7].v = _mm_unpackhi_epi64(pqx[3].v, pqz[3].v);
  nq[8].v = _mm_unpacklo_epi64(pqx[4].v, pqz[4].v);
  nq[9].v = _mm_unpackhi_epi64(pqx[4].v, pqz[4].v);
}

/* compute [x+z,x-z] from [x,z] */
static inline void OPTIONAL_INLINE
curve25519_addsub_packed64_sse2(packedelem64 *r)  {
  packed32bignum25519sse2 x,z,add,sub;

  x[0].v = _mm_unpacklo_epi64(r[0].v, r[1].v);
  z[0].v = _mm_unpackhi_epi64(r[0].v, r[1].v);
  x[1].v = _mm_unpacklo_epi64(r[2].v, r[3].v);
  z[1].v = _mm_unpackhi_epi64(r[2].v, r[3].v);
  x[2].v = _mm_unpacklo_epi64(r[4].v, r[5].v);
  z[2].v = _mm_unpackhi_epi64(r[4].v, r[5].v);
  x[3].v = _mm_unpacklo_epi64(r[6].v, r[7].v);
  z[3].v = _mm_unpackhi_epi64(r[6].v, r[7].v);
  x[4].v = _mm_unpacklo_epi64(r[8].v, r[9].v);
  z[4].v = _mm_unpackhi_epi64(r[8].v, r[9].v);

  curve25519_add_packed32_sse2(add, x, z);
  curve25519_sub_packed32_sse2(sub, x, z);

  r[0].v = _mm_unpacklo_epi64(add[0].v, sub[0].v);
  r[1].v = _mm_unpackhi_epi64(add[0].v, sub[0].v);
  r[2].v = _mm_unpacklo_epi64(add[1].v, sub[1].v);
  r[3].v = _mm_unpackhi_epi64(add[1].v, sub[1].v);
  r[4].v = _mm_unpacklo_epi64(add[2].v, sub[2].v);
  r[5].v = _mm_unpackhi_epi64(add[2].v, sub[2].v);
  r[6].v = _mm_unpacklo_epi64(add[3].v, sub[3].v);
  r[7].v = _mm_unpackhi_epi64(add[3].v, sub[3].v);
  r[8].v = _mm_unpacklo_epi64(add[4].v, sub[4].v);
  r[9].v = _mm_unpackhi_epi64(add[4].v, sub[4].v);
}

/* compute [x,z] * [121666,121665] */
static inline void OPTIONAL_INLINE
curve25519_121665_packed64_sse2(packedelem64 *out, const packedelem64 *in) {
  xmmi c1,c2;

  out[0].v = _mm_mul_epu32(in[0].v, packed121666121665.v);
  out[1].v = _mm_mul_epu32(in[1].v, packed121666121665.v);
  out[2].v = _mm_mul_epu32(in[2].v, packed121666121665.v);
  out[3].v = _mm_mul_epu32(in[3].v, packed121666121665.v);
  out[4].v = _mm_mul_epu32(in[4].v, packed121666121665.v);
  out[5].v = _mm_mul_epu32(in[5].v, packed121666121665.v);
  out[6].v = _mm_mul_epu32(in[6].v, packed121666121665.v);
  out[7].v = _mm_mul_epu32(in[7].v, packed121666121665.v);
  out[8].v = _mm_mul_epu32(in[8].v, packed121666121665.v);
  out[9].v = _mm_mul_epu32(in[9].v, packed121666121665.v);

  c1 = _mm_srli_epi64(out[0].v, 26); c2 = _mm_srli_epi64(out[4].v, 26); out[0].v = _mm_and_si128(out[0].v, packedmask26.v); out[4].v = _mm_and_si128(out[4].v, packedmask26.v); out[1].v = _mm_add_epi64(out[1].v, c1); out[5].v = _mm_add_epi64(out[5].v, c2);
  c1 = _mm_srli_epi64(out[1].v, 25); c2 = _mm_srli_epi64(out[5].v, 25); out[1].v = _mm_and_si128(out[1].v, packedmask25.v); out[5].v = _mm_and_si128(out[5].v, packedmask25.v); out[2].v = _mm_add_epi64(out[2].v, c1); out[6].v = _mm_add_epi64(out[6].v, c2);
  c1 = _mm_srli_epi64(out[2].v, 26); c2 = _mm_srli_epi64(out[6].v, 26); out[2].v = _mm_and_si128(out[2].v, packedmask26.v); out[6].v = _mm_and_si128(out[6].v, packedmask26.v); out[3].v = _mm_add_epi64(out[3].v, c1); out[7].v = _mm_add_epi64(out[7].v, c2);
  c1 = _mm_srli_epi64(out[3].v, 25); c2 = _mm_srli_epi64(out[7].v, 25); out[3].v = _mm_and_si128(out[3].v, packedmask25.v); out[7].v = _mm_and_si128(out[7].v, packedmask25.v); out[4].v = _mm_add_epi64(out[4].v, c1); out[8].v = _mm_add_epi64(out[8].v, c2);
                                     c2 = _mm_srli_epi64(out[8].v, 26);                                                     out[8].v = _mm_and_si128(out[8].v, packedmask26.v);                                         out[9].v = _mm_add_epi64(out[9].v, c2);
                                     c2 = _mm_srli_epi64(out[9].v, 25);                                                     out[9].v = _mm_and_si128(out[9].v, packedmask25.v);                                         out[0].v = _mm_add_epi64(out[0].v, _mm_mul_epu32(c2, packednineteen.v));
  c1 = _mm_srli_epi64(out[0].v, 26); c2 = _mm_srli_epi64(out[4].v, 26); out[0].v = _mm_and_si128(out[0].v, packedmask26.v); out[4].v = _mm_and_si128(out[4].v, packedmask26.v); out[1].v = _mm_add_epi64(out[1].v, c1); out[5].v = _mm_add_epi64(out[5].v, c2);
}

/* compute [sq.x,sqscalar.x-sqscalar.z] * [sq.z,sq.x-sq.z] */
static inline void OPTIONAL_INLINE
curve25519_final_nq(packedelem64 *nq, const packedelem64 *sq, const packedelem64 *sq121665) {
  packed32bignum25519sse2 x, z, sub;
  packed64bignum25519sse2 t, nqa, nqb;

  x[0].v = _mm_or_si128(_mm_unpacklo_epi64(sq[0].v, sq[1].v), _mm_slli_si128(_mm_unpacklo_epi64(sq121665[0].v, sq121665[1].v), 4));
  z[0].v = _mm_or_si128(_mm_unpackhi_epi64(sq[0].v, sq[1].v), _mm_slli_si128(_mm_unpackhi_epi64(sq121665[0].v, sq121665[1].v), 4));
  x[1].v = _mm_or_si128(_mm_unpacklo_epi64(sq[2].v, sq[3].v), _mm_slli_si128(_mm_unpacklo_epi64(sq121665[2].v, sq121665[3].v), 4));
  z[1].v = _mm_or_si128(_mm_unpackhi_epi64(sq[2].v, sq[3].v), _mm_slli_si128(_mm_unpackhi_epi64(sq121665[2].v, sq121665[3].v), 4));
  x[2].v = _mm_or_si128(_mm_unpacklo_epi64(sq[4].v, sq[5].v), _mm_slli_si128(_mm_unpacklo_epi64(sq121665[4].v, sq121665[5].v), 4));
  z[2].v = _mm_or_si128(_mm_unpackhi_epi64(sq[4].v, sq[5].v), _mm_slli_si128(_mm_unpackhi_epi64(sq121665[4].v, sq121665[5].v), 4));
  x[3].v = _mm_or_si128(_mm_unpacklo_epi64(sq[6].v, sq[7].v), _mm_slli_si128(_mm_unpacklo_epi64(sq121665[6].v, sq121665[7].v), 4));
  z[3].v = _mm_or_si128(_mm_unpackhi_epi64(sq[6].v, sq[7].v), _mm_slli_si128(_mm_unpackhi_epi64(sq121665[6].v, sq121665[7].v), 4));
  x[4].v = _mm_or_si128(_mm_unpacklo_epi64(sq[8].v, sq[9].v), _mm_slli_si128(_mm_unpacklo_epi64(sq121665[8].v, sq121665[9].v), 4));
  z[4].v = _mm_or_si128(_mm_unpackhi_epi64(sq[8].v, sq[9].v), _mm_slli_si128(_mm_unpackhi_epi64(sq121665[8].v, sq121665[9].v), 4));

  curve25519_sub_packed32_sse2(sub, x, z);

  t[0].v = _mm_shuffle_epi32(sub[0].v, _MM_SHUFFLE(1,1,0,0));
  t[1].v = _mm_shuffle_epi32(sub[0].v, _MM_SHUFFLE(3,3,2,2));
  t[2].v = _mm_shuffle_epi32(sub[1].v, _MM_SHUFFLE(1,1,0,0));
  t[3].v = _mm_shuffle_epi32(sub[1].v, _MM_SHUFFLE(3,3,2,2));
  t[4].v = _mm_shuffle_epi32(sub[2].v, _MM_SHUFFLE(1,1,0,0));
  t[5].v = _mm_shuffle_epi32(sub[2].v, _MM_SHUFFLE(3,3,2,2));
  t[6].v = _mm_shuffle_epi32(sub[3].v, _MM_SHUFFLE(1,1,0,0));
  t[7].v = _mm_shuffle_epi32(sub[3].v, _MM_SHUFFLE(3,3,2,2));
  t[8].v = _mm_shuffle_epi32(sub[4].v, _MM_SHUFFLE(1,1,0,0));
  t[9].v = _mm_shuffle_epi32(sub[4].v, _MM_SHUFFLE(3,3,2,2));

  nqa[0].v = _mm_unpacklo_epi64(sq[0].v, t[0].v);
  nqb[0].v = _mm_unpackhi_epi64(sq[0].v, t[0].v);
  nqa[1].v = _mm_unpacklo_epi64(sq[1].v, t[1].v);
  nqb[1].v = _mm_unpackhi_epi64(sq[1].v, t[1].v);
  nqa[2].v = _mm_unpacklo_epi64(sq[2].v, t[2].v);
  nqb[2].v = _mm_unpackhi_epi64(sq[2].v, t[2].v);
  nqa[3].v = _mm_unpacklo_epi64(sq[3].v, t[3].v);
  nqb[3].v = _mm_unpackhi_epi64(sq[3].v, t[3].v);
  nqa[4].v = _mm_unpacklo_epi64(sq[4].v, t[4].v);
  nqb[4].v = _mm_unpackhi_epi64(sq[4].v, t[4].v);
  nqa[5].v = _mm_unpacklo_epi64(sq[5].v, t[5].v);
  nqb[5].v = _mm_unpackhi_epi64(sq[5].v, t[5].v);
  nqa[6].v = _mm_unpacklo_epi64(sq[6].v, t[6].v);
  nqb[6].v = _mm_unpackhi_epi64(sq[6].v, t[6].v);
  nqa[7].v = _mm_unpacklo_epi64(sq[7].v, t[7].v);
  nqb[7].v = _mm_unpackhi_epi64(sq[7].v, t[7].v);
  nqa[8].v = _mm_unpacklo_epi64(sq[8].v, t[8].v);
  nqb[8].v = _mm_unpackhi_epi64(sq[8].v, t[8].v);
  nqa[9].v = _mm_unpacklo_epi64(sq[9].v, t[9].v);
  nqb[9].v = _mm_unpackhi_epi64(sq[9].v, t[9].v);

  curve25519_mul_packed64_sse2(nq, nqa, nqb);
}


/*
 * In:  b =   2^5 - 2^0
 * Out: b = 2^250 - 2^0
 */
static inline void OPTIONAL_INLINE
curve25519_pow_two5mtwo0_two250mtwo0_sse2(bignum25519sse2 b) {
  MM16 bignum25519sse2 t0,c;

  /* 2^5  - 2^0 */ /* b */
  /* 2^10 - 2^5 */ curve25519_square_times_sse2(t0, b, 5);
  /* 2^10 - 2^0 */ curve25519_mul_sse2(b, t0, b);
  /* 2^20 - 2^10 */ curve25519_square_times_sse2(t0, b, 10);
  /* 2^20 - 2^0 */ curve25519_mul_sse2(c, t0, b);
  /* 2^40 - 2^20 */ curve25519_square_times_sse2(t0, c, 20);
  /* 2^40 - 2^0 */ curve25519_mul_sse2(t0, t0, c);
  /* 2^50 - 2^10 */ curve25519_square_times_sse2(t0, t0, 10);
  /* 2^50 - 2^0 */ curve25519_mul_sse2(b, t0, b);
  /* 2^100 - 2^50 */ curve25519_square_times_sse2(t0, b, 50);
  /* 2^100 - 2^0 */ curve25519_mul_sse2(c, t0, b);
  /* 2^200 - 2^100 */ curve25519_square_times_sse2(t0, c, 100);
  /* 2^200 - 2^0 */ curve25519_mul_sse2(t0, t0, c);
  /* 2^250 - 2^50 */ curve25519_square_times_sse2(t0, t0, 50);
  /* 2^250 - 2^0 */ curve25519_mul_sse2(b, t0, b);
}

/*
 * z^(p - 2) = z(2^255 - 21)
 */
static inline void OPTIONAL_INLINE
curve25519_recip_sse2(bignum25519sse2 out, const bignum25519sse2 z) {
  MM16 bignum25519sse2 a,t0,b;

  /* 2 */ curve25519_square_times_sse2(a, z, 1); /* a = 2 */
  /* 8 */ curve25519_square_times_sse2(t0, a, 2);
  /* 9 */ curve25519_mul_sse2(b, t0, z); /* b = 9 */
  /* 11 */ curve25519_mul_sse2(a, b, a); /* a = 11 */
  /* 22 */ curve25519_square_times_sse2(t0, a, 1);
  /* 2^5 - 2^0 = 31 */ curve25519_mul_sse2(b, t0, b);
  /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0_sse2(b);
  /* 2^255 - 2^5 */ curve25519_square_times_sse2(b, b, 5);
  /* 2^255 - 21 */ curve25519_mul_sse2(out, b, a);
}


/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   mypublic: the packed little endian x coordinate of the resulting curve point
 *   n: a little endian, 32-byte number
 *   basepoint: a packed little endian point of the curve
 */

static void
curve25519_scalarmult(uint8_t mypublic[32], const uint8_t n[32], const uint8_t basepoint[32]) {
  MM16 bignum25519sse2 q, zmone, nqpqx, nqpqz = {1}, nqx = {1}, nqz = {0};
  uint32_t bit, lastbit;
  packed32bignum25519sse2 qx, qz, pqz, pqx;
  packed64bignum25519sse2 nq, sq, sqscalar, prime, primex, primez, nqpq;
  bignum25519sse2mulprecomp preq;
  size_t i;

  curve25519_expand_sse2(q, basepoint);
  curve25519_copy_sse2(nqpqx, q);
  curve25519_mul_sse2_precomp(&preq, q);

  i = 255;
  lastbit = 0;

  do {
    bit = (n[i/8] >> (i & 7)) & 1;
    curve25519_swap_conditional_sse2(nqx, nqpqx, bit ^ lastbit);    
    curve25519_swap_conditional_sse2(nqz, nqpqz, bit ^ lastbit);
    lastbit = bit;

    curve25519_tangle32(qx, nqx, nqpqx); /* qx = [nqx,nqpqx] */
    curve25519_tangle32(qz, nqz, nqpqz); /* qz = [nqz,nqpqz] */
    
    curve25519_add_packed32_sse2(pqx, qx, qz); /* pqx = [nqx+nqz,nqpqx+nqpqz] */
    curve25519_sub_packed32_sse2(pqz, qx, qz); /* pqz = [nqx-nqz,nqpqx-nqpqz] */

    curve25519_make_nqpq(primex, primez, pqx, pqz); /* primex = [nqx+nqz,nqpqx+nqpqz], primez = [nqpqx-nqpqz,nqx-nqz] */
    curve25519_mul_packed64_sse2(prime, primex, primez); /* prime = [nqx+nqz,nqpqx+nqpqz] * [nqpqx-nqpqz,nqx-nqz] */
    curve25519_addsub_packed64_sse2(prime); /* prime = [prime.x+prime.z,prime.x-prime.z] */
    curve25519_square_packed64_sse2(nqpq, prime); /* nqpq = prime^2 */
    curve25519_untangle64(nqpqx, nqpqz, nqpq);
    curve25519_mul_precomp_sse2(nqpqz, nqpqz, &preq); /* nqpqz = nqpqz * q */

    /* (((sq.x-sq.z)*121665)+sq.x) * (sq.x-sq.z) is equivalent to (sq.x*121666-sq.z*121665) * (sq.x-sq.z) */
    curve25519_make_nq(nq, pqx, pqz); /* nq = [nqx+nqz,nqx-nqz] */
    curve25519_square_packed64_sse2(sq, nq); /* sq = nq^2 */
    curve25519_121665_packed64_sse2(sqscalar, sq); /* sqscalar = sq * [121666,121665] */
    curve25519_final_nq(nq, sq, sqscalar); /* nq = [sq.x,sqscalar.x-sqscalar.z] * [sq.z,sq.x-sq.z] */
    curve25519_untangle64(nqx, nqz, nq);
  } while (i--);

  curve25519_swap_conditional_sse2(nqx, nqpqx, bit);
  curve25519_swap_conditional_sse2(nqz, nqpqz, bit);

  curve25519_recip_sse2(zmone, nqz);
  curve25519_mul_sse2(nqz, nqx, zmone);
  curve25519_contract_sse2(mypublic, nqz);
}

int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);
void curve25519_donna_raw(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);

int
curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint) {
  uint8_t e[32];
  size_t i;

  for (i = 0;i < 32;++i) e[i] = secret[i];
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;
  curve25519_scalarmult(mypublic, e, basepoint);
  return 0;
}

void
curve25519_donna_raw(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint) {
  curve25519_scalarmult(mypublic, secret, basepoint);
}

