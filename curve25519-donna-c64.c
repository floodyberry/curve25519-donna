/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Code released into the public domain.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation.
 */

#define AGGRESSIVE_INLINING

#if defined(__ICC)
  #define COMPILER_INTEL
#endif
#if defined(__PATHCC__)
  #define COMPILER_PATHCC
#endif

#if defined(_MSC_VER)
  #define COMPILER_MSVC
  #include <intrin.h>
  #include <string.h>
  #if defined(AGGRESSIVE_INLINING)
    #undef OPTIONAL_INLINE
    #define OPTIONAL_INLINE __forceinline
  #endif
  typedef unsigned char uint8_t;
  typedef unsigned __int64 uint64_t;
  typedef signed __int64 int64_t;
  struct uint128 {
    uint64_t lo, hi;
  };
  typedef struct uint128 uint128_t;
  #define mul64x64_128(out,a,b) out.lo = _umul128(a,b,&out.hi);
  #define shr128_pair(out,hi,lo,shift) out = __shiftright128(lo, hi, shift);
  #define shr128(out,in,shift) shr128_pair(out, in.hi, in.lo, shift)
  #define add128(a,b) { uint64_t p = a.lo; a.lo += b.lo; a.hi += b.hi + (a.lo < p); }
  #define add128_64(a,b) { uint64_t p = a.lo; a.lo += b; a.hi += (a.lo < p); }
  #define lo128(a) (a.lo)
#elif defined(__GNUC__)
  #include <string.h>
  #include <stdint.h>
  #if defined(AGGRESSIVE_INLINING)
    #undef OPTIONAL_INLINE
    #define OPTIONAL_INLINE __attribute__((always_inline))
  #endif
  #if (defined(COMPILER_INTEL) || defined(COMPILER_PATHCC))
    struct uint128 {
      uint64_t lo, hi;
    };
    typedef struct uint128 uint128_t;
    #define mul64x64_128(out,a,b) __asm__ ("mulq %3" : "=a" (out.lo), "=d" (out.hi) : "a" (a), "rm" (b));
    #define shr128_pair(out,hi,lo,shift) __asm__ ("shrdq %3,%2,%0" : "=r" (lo) : "0" (lo), "r" (hi), "J" (shift)); out = lo;
    #define shr128(out,in,shift) shr128_pair(out,in.hi, in.lo, shift)
    #define add128(a,b) __asm__ ("addq %4,%2; adcq %5,%3" : "=r" (a.hi), "=r" (a.lo) : "1" (a.lo), "0" (a.hi), "rm" (b.lo), "rm" (b.hi) : "cc");
    #define add128_64(a,b) __asm__ ("addq %4,%2; adcq $0,%3" : "=r" (a.hi), "=r" (a.lo) : "1" (a.lo), "0" (a.hi), "rm" (b) : "cc");
    #define lo128(a) (a.lo)
  #else
    #define HAVE_NATIVE_UINT128
    typedef unsigned uint128_t __attribute__((mode(TI)));
    #define mul64x64_128(out,a,b) out = (uint128_t)a * b;
    #define shr128_pair(out,hi,lo,shift) out = (uint64_t)((((uint128_t)hi << 64) | lo) >> shift);
    #define shr128(out,in,shift) out = (uint64_t)(in >> shift);
    #define add128(a,b) a += b;
    #define add128_64(a,b) a += b;
    #define lo128(a) ((uint64_t)a)
  #endif
#else
  unsupported compiler
#endif

typedef uint64_t bignum25519[5];

static uint64_t reduce_mask_51 = 0x0007ffffffffffffull;

/* out = in */
static inline void OPTIONAL_INLINE
curve25519_copy(bignum25519 out, const bignum25519 in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
  out[4] = in[4];
}

/* out = a + b */
static inline void OPTIONAL_INLINE
curve25519_add(bignum25519 out, const bignum25519 a, const bignum25519 b) {
  out[0] = a[0] + b[0];
  out[1] = a[1] + b[1];
  out[2] = a[2] + b[2];
  out[3] = a[3] + b[3];
  out[4] = a[4] + b[4];
}

static const uint64_t two54m152 = (((uint64_t)1) << 54) - 152;
static const uint64_t two54m8 = (((uint64_t)1) << 54) - 8;

/* out = a - b */
static inline void OPTIONAL_INLINE
curve25519_sub(bignum25519 out, const bignum25519 a, const bignum25519 b) {
  out[0] = a[0] + two54m152 - b[0];
  out[1] = a[1] + two54m8 - b[1];
  out[2] = a[2] + two54m8 - b[2];
  out[3] = a[3] + two54m8 - b[3];
  out[4] = a[4] + two54m8 - b[4];
}


/* out = (in * scalar) */
static inline void OPTIONAL_INLINE
curve25519_scalar_product(bignum25519 out, const bignum25519 in, const uint64_t scalar) {
  uint128_t a;
  uint64_t c;

#if defined(HAVE_NATIVE_UINT128)
  a = ((uint128_t) in[0]) * scalar;     out[0] = (uint64_t)a & reduce_mask_51; c = (uint64_t)(a >> 51);
  a = ((uint128_t) in[1]) * scalar + c; out[1] = (uint64_t)a & reduce_mask_51; c = (uint64_t)(a >> 51);
  a = ((uint128_t) in[2]) * scalar + c; out[2] = (uint64_t)a & reduce_mask_51; c = (uint64_t)(a >> 51);
  a = ((uint128_t) in[3]) * scalar + c; out[3] = (uint64_t)a & reduce_mask_51; c = (uint64_t)(a >> 51);
  a = ((uint128_t) in[4]) * scalar + c; out[4] = (uint64_t)a & reduce_mask_51; c = (uint64_t)(a >> 51);
                                        out[0] += c * 19;
#else
  mul64x64_128(a, in[0], scalar)                  out[0] = lo128(a) & reduce_mask_51; shr128(c, a, 51);
  mul64x64_128(a, in[1], scalar) add128_64(a, c)  out[1] = lo128(a) & reduce_mask_51; shr128(c, a, 51);
  mul64x64_128(a, in[2], scalar) add128_64(a, c)  out[2] = lo128(a) & reduce_mask_51; shr128(c, a, 51);
  mul64x64_128(a, in[3], scalar) add128_64(a, c)  out[3] = lo128(a) & reduce_mask_51; shr128(c, a, 51);
  mul64x64_128(a, in[4], scalar) add128_64(a, c)  out[4] = lo128(a) & reduce_mask_51; shr128(c, a, 51);
                                                  out[0] += c * 19;
#endif
}

/* out = a * b */
static inline void OPTIONAL_INLINE
curve25519_mul(bignum25519 out, const bignum25519 a, const bignum25519 b) {
#if !defined(HAVE_NATIVE_UINT128)
  uint128_t mul;
#endif
  uint128_t t[5];
  uint64_t r0,r1,r2,r3,r4,s0,s1,s2,s3,s4,c;

  r0 = b[0];
  r1 = b[1];
  r2 = b[2];
  r3 = b[3];
  r4 = b[4];

  s0 = a[0];
  s1 = a[1];
  s2 = a[2];
  s3 = a[3];
  s4 = a[4];

#if defined(HAVE_NATIVE_UINT128)
  t[0]  =  ((uint128_t) r0) * s0;
  t[1]  =  ((uint128_t) r0) * s1 + ((uint128_t) r1) * s0;
  t[2]  =  ((uint128_t) r0) * s2 + ((uint128_t) r2) * s0 + ((uint128_t) r1) * s1;
  t[3]  =  ((uint128_t) r0) * s3 + ((uint128_t) r3) * s0 + ((uint128_t) r1) * s2 + ((uint128_t) r2) * s1;
  t[4]  =  ((uint128_t) r0) * s4 + ((uint128_t) r4) * s0 + ((uint128_t) r3) * s1 + ((uint128_t) r1) * s3 + ((uint128_t) r2) * s2;
#else
  mul64x64_128(t[0], r0, s0)
  mul64x64_128(t[1], r0, s1) mul64x64_128(mul, r1, s0) add128(t[1], mul)
  mul64x64_128(t[2], r0, s2) mul64x64_128(mul, r2, s0) add128(t[2], mul) mul64x64_128(mul, r1, s1) add128(t[2], mul)
  mul64x64_128(t[3], r0, s3) mul64x64_128(mul, r3, s0) add128(t[3], mul) mul64x64_128(mul, r1, s2) add128(t[3], mul) mul64x64_128(mul, r2, s1) add128(t[3], mul)
  mul64x64_128(t[4], r0, s4) mul64x64_128(mul, r4, s0) add128(t[4], mul) mul64x64_128(mul, r3, s1) add128(t[4], mul) mul64x64_128(mul, r1, s3) add128(t[4], mul) mul64x64_128(mul, r2, s2) add128(t[4], mul)
#endif

  r1 *= 19;
  r2 *= 19;
  r3 *= 19;
  r4 *= 19;

#if defined(HAVE_NATIVE_UINT128)
  t[0] += ((uint128_t) r4) * s1 + ((uint128_t) r1) * s4 + ((uint128_t) r2) * s3 + ((uint128_t) r3) * s2;
  t[1] += ((uint128_t) r4) * s2 + ((uint128_t) r2) * s4 + ((uint128_t) r3) * s3;
  t[2] += ((uint128_t) r4) * s3 + ((uint128_t) r3) * s4;
  t[3] += ((uint128_t) r4) * s4;
#else
  mul64x64_128(mul, r4, s1) add128(t[0], mul) mul64x64_128(mul, r1, s4) add128(t[0], mul) mul64x64_128(mul, r2, s3) add128(t[0], mul) mul64x64_128(mul, r3, s2) add128(t[0], mul)
  mul64x64_128(mul, r4, s2) add128(t[1], mul) mul64x64_128(mul, r2, s4) add128(t[1], mul) mul64x64_128(mul, r3, s3) add128(t[1], mul)
  mul64x64_128(mul, r4, s3) add128(t[2], mul) mul64x64_128(mul, r3, s4) add128(t[2], mul)
  mul64x64_128(mul, r4, s4) add128(t[3], mul)
#endif


                       r0 = lo128(t[0]) & reduce_mask_51; shr128(c, t[0], 51);
  add128_64(t[1], c)   r1 = lo128(t[1]) & reduce_mask_51; shr128(c, t[1], 51);
  add128_64(t[2], c)   r2 = lo128(t[2]) & reduce_mask_51; shr128(c, t[2], 51);
  add128_64(t[3], c)   r3 = lo128(t[3]) & reduce_mask_51; shr128(c, t[3], 51);
  add128_64(t[4], c)   r4 = lo128(t[4]) & reduce_mask_51; shr128(c, t[4], 51);
  r0 +=   c * 19; c = r0 >> 51; r0 = r0 & reduce_mask_51;
  r1 +=   c;      c = r1 >> 51; r1 = r1 & reduce_mask_51;
  r2 +=   c;

  out[0] = r0;
  out[1] = r1;
  out[2] = r2;
  out[3] = r3;
  out[4] = r4;
}

/* out = in^(2 * count) */
static inline void OPTIONAL_INLINE
curve25519_square_times(bignum25519 out, const bignum25519 in, uint64_t count) {
#if !defined(HAVE_NATIVE_UINT128)
  uint128_t mul;
#endif
  uint128_t t[5];
  uint64_t r0,r1,r2,r3,r4,c;
  uint64_t d0,d1,d2,d4,d419;

  r0 = in[0];
  r1 = in[1];
  r2 = in[2];
  r3 = in[3];
  r4 = in[4];

  do {
    d0 = r0 * 2;
    d1 = r1 * 2;
    d2 = r2 * 2 * 19;
    d419 = r4 * 19;
    d4 = d419 * 2;

#if defined(HAVE_NATIVE_UINT128)
    t[0] = ((uint128_t) r0) * r0 + ((uint128_t) d4) * r1 + (((uint128_t) d2) * (r3     ));
    t[1] = ((uint128_t) d0) * r1 + ((uint128_t) d4) * r2 + (((uint128_t) r3) * (r3 * 19));
    t[2] = ((uint128_t) d0) * r2 + ((uint128_t) r1) * r1 + (((uint128_t) d4) * (r3     ));
    t[3] = ((uint128_t) d0) * r3 + ((uint128_t) d1) * r2 + (((uint128_t) r4) * (d419   ));
    t[4] = ((uint128_t) d0) * r4 + ((uint128_t) d1) * r3 + (((uint128_t) r2) * (r2     ));
#else
    mul64x64_128(t[0], r0, r0) mul64x64_128(mul, d4, r1) add128(t[0], mul) mul64x64_128(mul, d2,      r3) add128(t[0], mul)
    mul64x64_128(t[1], d0, r1) mul64x64_128(mul, d4, r2) add128(t[1], mul) mul64x64_128(mul, r3, r3 * 19) add128(t[1], mul)
    mul64x64_128(t[2], d0, r2) mul64x64_128(mul, r1, r1) add128(t[2], mul) mul64x64_128(mul, d4,      r3) add128(t[2], mul)
    mul64x64_128(t[3], d0, r3) mul64x64_128(mul, d1, r2) add128(t[3], mul) mul64x64_128(mul, r4,    d419) add128(t[3], mul)
    mul64x64_128(t[4], d0, r4) mul64x64_128(mul, d1, r3) add128(t[4], mul) mul64x64_128(mul, r2,      r2) add128(t[4], mul)
#endif

                         r0 = lo128(t[0]) & reduce_mask_51; shr128(c, t[0], 51);
    add128_64(t[1], c)   r1 = lo128(t[1]) & reduce_mask_51; shr128(c, t[1], 51);
    add128_64(t[2], c)   r2 = lo128(t[2]) & reduce_mask_51; shr128(c, t[2], 51);
    add128_64(t[3], c)   r3 = lo128(t[3]) & reduce_mask_51; shr128(c, t[3], 51);
    add128_64(t[4], c)   r4 = lo128(t[4]) & reduce_mask_51; shr128(c, t[4], 51);
    r0 +=   c * 19; c = r0 >> 51; r0 = r0 & reduce_mask_51;
    r1 +=   c;      c = r1 >> 51; r1 = r1 & reduce_mask_51;
    r2 +=   c;
  } while(--count);

  out[0] = r0;
  out[1] = r1;
  out[2] = r2;
  out[3] = r3;
  out[4] = r4;
}

static inline void OPTIONAL_INLINE
curve25519_square(bignum25519 out, const bignum25519 in) {
#if !defined(HAVE_NATIVE_UINT128)
  uint128_t mul;
#endif
  uint128_t t[5];
  uint64_t r0,r1,r2,r3,r4,c;
  uint64_t d0,d1,d2,d4,d419;

  r0 = in[0];
  r1 = in[1];
  r2 = in[2];
  r3 = in[3];
  r4 = in[4];

  d0 = r0 * 2;
  d1 = r1 * 2;
  d2 = r2 * 2 * 19;
  d419 = r4 * 19;
  d4 = d419 * 2;

#if defined(HAVE_NATIVE_UINT128)
  t[0] = ((uint128_t) r0) * r0 + ((uint128_t) d4) * r1 + (((uint128_t) d2) * (r3     ));
  t[1] = ((uint128_t) d0) * r1 + ((uint128_t) d4) * r2 + (((uint128_t) r3) * (r3 * 19));
  t[2] = ((uint128_t) d0) * r2 + ((uint128_t) r1) * r1 + (((uint128_t) d4) * (r3     ));
  t[3] = ((uint128_t) d0) * r3 + ((uint128_t) d1) * r2 + (((uint128_t) r4) * (d419   ));
  t[4] = ((uint128_t) d0) * r4 + ((uint128_t) d1) * r3 + (((uint128_t) r2) * (r2     ));
#else
  mul64x64_128(t[0], r0, r0) mul64x64_128(mul, d4, r1) add128(t[0], mul) mul64x64_128(mul, d2,      r3) add128(t[0], mul)
  mul64x64_128(t[1], d0, r1) mul64x64_128(mul, d4, r2) add128(t[1], mul) mul64x64_128(mul, r3, r3 * 19) add128(t[1], mul)
  mul64x64_128(t[2], d0, r2) mul64x64_128(mul, r1, r1) add128(t[2], mul) mul64x64_128(mul, d4,      r3) add128(t[2], mul)
  mul64x64_128(t[3], d0, r3) mul64x64_128(mul, d1, r2) add128(t[3], mul) mul64x64_128(mul, r4,    d419) add128(t[3], mul)
  mul64x64_128(t[4], d0, r4) mul64x64_128(mul, d1, r3) add128(t[4], mul) mul64x64_128(mul, r2,      r2) add128(t[4], mul)
#endif

                        r0 = lo128(t[0]) & reduce_mask_51; shr128(c, t[0], 51);
  add128_64(t[1], c)   r1 = lo128(t[1]) & reduce_mask_51; shr128(c, t[1], 51);
  add128_64(t[2], c)   r2 = lo128(t[2]) & reduce_mask_51; shr128(c, t[2], 51);
  add128_64(t[3], c)   r3 = lo128(t[3]) & reduce_mask_51; shr128(c, t[3], 51);
  add128_64(t[4], c)   r4 = lo128(t[4]) & reduce_mask_51; shr128(c, t[4], 51);
  r0 +=   c * 19; c = r0 >> 51; r0 = r0 & reduce_mask_51;
  r1 +=   c;      c = r1 >> 51; r1 = r1 & reduce_mask_51;
  r2 +=   c;

  out[0] = r0;
  out[1] = r1;
  out[2] = r2;
  out[3] = r3;
  out[4] = r4;
}


/* Take a little-endian, 32-byte number and expand it into polynomial form */
static inline void OPTIONAL_INLINE
curve25519_expand(bignum25519 out, const unsigned char *in) {
  uint64_t t;
  unsigned i;

  #define read51full(n,start,shift) \
    for (t = in[(start)] >> (shift), i = 0; i < (6 + ((shift)/6)); i++) \
      t |= ((uint64_t)in[i+(start)+1] << ((i * 8) + (8 - (shift)))); \
    out[n] = t & 0x7ffffffffffff;
  #define read51(n) read51full(n,(n*51)/8,(n*3)&7)

  read51(0)
  read51(1)
  read51(2)
  read51(3)
  read51(4)

  #undef read51full
  #undef read51
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static inline void OPTIONAL_INLINE
curve25519_contract(unsigned char *out, const bignum25519 input) {
  uint64_t t[5];
  uint64_t f, i;

  t[0] = input[0];
  t[1] = input[1];
  t[2] = input[2];
  t[3] = input[3];
  t[4] = input[4];

  #define curve25519_contract_carry() \
    t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff; \
    t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff; \
    t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff; \
    t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;

  #define curve25519_contract_carry_full() curve25519_contract_carry() \
    t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

  #define curve25519_contract_carry_final() curve25519_contract_carry() \
    t[4] &= 0x7ffffffffffff;

  curve25519_contract_carry_full()
  curve25519_contract_carry_full()

  /* now t is between 0 and 2^255-1, properly carried. */
  /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
  t[0] += 19;
  curve25519_contract_carry_full()

  /* now between 19 and 2^255-1 in both cases, and offset by 19. */
  t[0] += 0x8000000000000 - 19;
  t[1] += 0x8000000000000 - 1;
  t[2] += 0x8000000000000 - 1;
  t[3] += 0x8000000000000 - 1;
  t[4] += 0x8000000000000 - 1;

  /* now between 2^255 and 2^256-20, and offset by 2^255. */
  curve25519_contract_carry_final()

  #define write51full(n,shift) \
    f = ((t[n] >> shift) | (t[n+1] << (51 - shift))); \
    for (i = 0; i < 8; i++, f >>= 8) *out++ = (unsigned char)f;
  #define write51(n) write51full(n,13*n)
  write51(0)
  write51(1)
  write51(2)
  write51(3)

  #undef curve25519_contract_carry
  #undef curve25519_contract_carry_full
  #undef curve25519_contract_carry_final
  #undef write51full
  #undef write51
}

/*
 * Maybe swap the contents of two bignum25519 arrays (@a and @b), each 5 elements
 * long. Perform the swap iff @swap is non-zero.
 */
static inline void OPTIONAL_INLINE
curve25519_swap_conditional(bignum25519 a, bignum25519 b, uint64_t iswap) {
  const uint64_t swap = (uint64_t)(-(int64_t)iswap);
  uint64_t x0,x1,x2,x3,x4;

  x0 = swap & (a[0] ^ b[0]); a[0] ^= x0; b[0] ^= x0;
  x1 = swap & (a[1] ^ b[1]); a[1] ^= x1; b[1] ^= x1;
  x2 = swap & (a[2] ^ b[2]); a[2] ^= x2; b[2] ^= x2;
  x3 = swap & (a[3] ^ b[3]); a[3] ^= x3; b[3] ^= x3;
  x4 = swap & (a[4] ^ b[4]); a[4] ^= x4; b[4] ^= x4;
}

/*
 * In:  b =   2^5 - 2^0
 * Out: b = 2^250 - 2^0
 */
static void
curve25519_pow_two5mtwo0_two250mtwo0(bignum25519 b) {
  bignum25519 t0,c;

  /* 2^5  - 2^0 */ /* b */
  /* 2^10 - 2^5 */ curve25519_square_times(t0, b, 5);
  /* 2^10 - 2^0 */ curve25519_mul(b, t0, b);
  /* 2^20 - 2^10 */ curve25519_square_times(t0, b, 10);
  /* 2^20 - 2^0 */ curve25519_mul(c, t0, b);
  /* 2^40 - 2^20 */ curve25519_square_times(t0, c, 20);
  /* 2^40 - 2^0 */ curve25519_mul(t0, t0, c);
  /* 2^50 - 2^10 */ curve25519_square_times(t0, t0, 10);
  /* 2^50 - 2^0 */ curve25519_mul(b, t0, b);
  /* 2^100 - 2^50 */ curve25519_square_times(t0, b, 50);
  /* 2^100 - 2^0 */ curve25519_mul(c, t0, b);
  /* 2^200 - 2^100 */ curve25519_square_times(t0, c, 100);
  /* 2^200 - 2^0 */ curve25519_mul(t0, t0, c);
  /* 2^250 - 2^50 */ curve25519_square_times(t0, t0, 50);
  /* 2^250 - 2^0 */ curve25519_mul(b, t0, b);
}

/*
 * z^(p - 2) = z(2^255 - 21)
 */
static void
curve25519_recip(bignum25519 out, const bignum25519 z) {
  bignum25519 a,t0,b;

  /* 2 */ curve25519_square_times(a, z, 1); /* a = 2 */
  /* 8 */ curve25519_square_times(t0, a, 2);
  /* 9 */ curve25519_mul(b, t0, z); /* b = 9 */
  /* 11 */ curve25519_mul(a, b, a); /* a = 11 */
  /* 22 */ curve25519_square_times(t0, a, 1);
  /* 2^5 - 2^0 = 31 */ curve25519_mul(b, t0, b);
  /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
  /* 2^255 - 2^5 */ curve25519_square_times(b, b, 5);
  /* 2^255 - 21 */ curve25519_mul(out, b, a);
}


/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   mypublic: the packed little endian x coordinate of the resulting curve point
 *   n: a little endian, 32-byte number
 *   basepoint: a packed little endian point of the curve
 */

static void
curve25519_scalarmult(uint8_t mypublic[32], const uint8_t n[32], const uint8_t basepoint[32]) {
  bignum25519 nqpqx, nqpqz = {1}, nqx = {1}, nqz = {0};
  bignum25519 q, qx, qpqx, qqx, zzz, zmone;
  size_t bit, lastbit;
  unsigned i;

  curve25519_expand(q, basepoint);
  curve25519_copy(nqpqx, q);

  i = 255;
  lastbit = 0;

  do {
    bit = (n[i/8] >> (i & 7)) & 1;
    curve25519_swap_conditional(nqx, nqpqx, bit ^ lastbit);
    curve25519_swap_conditional(nqz, nqpqz, bit ^ lastbit);
    lastbit = bit;

    curve25519_add(qx, nqx, nqz);
    curve25519_sub(nqz, nqx, nqz);
    curve25519_add(qpqx, nqpqx, nqpqz);
    curve25519_sub(nqpqz, nqpqx, nqpqz);
    curve25519_mul(nqpqx, qpqx, nqz);
    curve25519_mul(nqpqz, qx, nqpqz);
    curve25519_add(qqx, nqpqx, nqpqz);
    curve25519_sub(nqpqz, nqpqx, nqpqz);
    curve25519_square(nqpqz, nqpqz);
    curve25519_square(nqpqx, qqx);
    curve25519_mul(nqpqz, nqpqz, q);
    curve25519_square(qx, qx);
    curve25519_square(nqz, nqz);
    curve25519_mul(nqx, qx, nqz);
    curve25519_sub(nqz, qx, nqz);
    curve25519_scalar_product(zzz, nqz, 121665);
    curve25519_add(zzz, zzz, qx);
    curve25519_mul(nqz, nqz, zzz);
  } while (i--);

  curve25519_swap_conditional(nqx, nqpqx, bit);
  curve25519_swap_conditional(nqz, nqpqz, bit);

  curve25519_recip(zmone, nqz);
  curve25519_mul(nqz, nqx, zmone);
  curve25519_contract(mypublic, nqz);
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

