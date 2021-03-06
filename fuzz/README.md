This code fuzzes curve25519-donna (and optionally curve25519-donna-sse2) against the ref10 implementation of
[curve25519](https://github.com/floodyberry/supercop/tree/master/crypto_scalarmult/curve25519/ref10).

# Building

## *nix + PHP

`php build-nix.php (required parameters) (optional parameters)`

Required parameters:

* `--bits=[32,64]`

Optional parameters:

* `--with-sse2`

    Also fuzz against ed25519-donna-sse2

* `--compiler=[gcc,clang,icc]`

    Default: gcc

* `--out=filename`

    Filename to write to. Default is fuzz-curve25519

example:

    php build-nix.php --bits=64 --with-sse2 --compiler=icc 

## Windows

Create a project with access to the curve25519 files.

Add the following files to the project:

* `fuzz/curve25519-ref10.c`
* `fuzz/curve25519-donna.c`
* `fuzz/curve25519-donna-sse2.c` (optional)
* `fuzz-curve25519.c`

If you are also fuzzing against curve25519-donna-sse2, add the `CURVE25519_SSE2` define for `fuzz-curve25519.c` under 
its "Properties/Preprocessor/Preprocessor Definitions" option.

# Running

If everything agrees, the program will only output occasional status dots (every 0x100 passes) 
and a 64bit progress count (every 0x2000 passes):

    fuzzing:  ref10 curve25519 curve25519-sse2
    
    ................................ [0000000000020000]
    ................................ [0000000000040000]
    ................................ [0000000000060000]
    ................................ [0000000000080000]
    ................................ [00000000000a0000]
    ................................ [00000000000c0000]
 
If any of the implementations do not agree with the ref10 implementation, the program will dump
the random data that was used, the data generated by the ref10 implementation, and diffs of the 
curve25519-donna data against the ref10 data.

## Example errors

These are example error dumps (with intentionally introduced errors).

### Curve25519

Random data:

* sk, or Secret Key

Generated data:

* pk, or Public Key
* shared, or Derived Shared Key

#### Public Key Mismatch

    sk:
    0x51,0x24,0xb5,0xdf,0x10,0xbe,0x6e,0xb9,0x34,0x32,0x14,0x2d,0xed,0x34,0x85,0x9f,
    0xd6,0xa5,0xf0,0x19,0x8f,0x12,0xa3,0x3e,0x3e,0xcf,0xf2,0x28,0x44,0xfc,0x63,0xea,


    ref10 pk:
    0x7c,0x1d,0xe7,0x34,0xf8,0x23,0x9c,0x17,0x8e,0x0a,0xa3,0xa8,0xf9,0xe3,0x1a,0x0b,
    0x19,0x65,0x59,0x98,0x41,0x0c,0x08,0x28,0xfc,0xed,0x70,0x76,0x5f,0x4a,0x06,0x0d,


    curve25519 pk diff:
    0xb4,0x1a,0x17,0x34,0x95,0xfa,0xbd,0x62,0x96,0x94,0x04,0xdf,0xf3,0x4b,0x65,0x4b,
    0x06,0x45,0xdf,0x25,0x0a,0x55,0xcc,0x4f,0xe7,0x89,0xf5,0x64,0xd9,0xb5,0x37,0x24,


    curve25519-sse2 pk diff:
    ____,____,____,____,____,____,____,____,____,____,____,____,____,____,____,____,
    ____,____,____,____,____,____,____,____,____,____,____,____,____,____,____,____,


In this case, curve25519 is totally wrong, while curve25519-sse2 matches the reference 
implementation.

#### Derived Shared Key Mismatch

    sk:
    0xaf,0xd1,0x4f,0xce,0x36,0x5d,0x4d,0xb1,0x0d,0xb5,0x1e,0xe8,0x3f,0x35,0x82,0x40,
    0x8d,0x3c,0x98,0x75,0x8a,0x5d,0xd0,0xda,0xe0,0xfe,0x94,0x8e,0x9f,0xd5,0x9f,0x71,


    pk:
    0x45,0x52,0x5b,0xa3,0x3a,0x0d,0xe7,0xaf,0x55,0xeb,0x7e,0x97,0xc8,0xfb,0x32,0x3a,
    0x8d,0xea,0xae,0x04,0x9a,0xc8,0x76,0x75,0xcf,0xa4,0xe3,0x12,0x95,0x03,0xc4,0x2a,


    ref10 shared:
    0x07,0xb8,0x00,0xb1,0x9c,0xbd,0xa0,0x82,0x76,0x98,0xb3,0x02,0x0d,0x59,0xc6,0x13,
    0x27,0xeb,0x5d,0x05,0x74,0x83,0x78,0x64,0x65,0x5b,0xd5,0x41,0xe1,0x32,0xe8,0x0b,


    curve25519 shared diff:
    ____,____,____,____,____,____,____,____,____,____,____,____,____,____,____,____,
    ____,____,____,____,____,____,____,____,____,____,____,____,____,____,____,____,


    curve25519-sse2 shared diff:
    0xa0,0xa1,0x6f,0x72,0xd9,0x9a,0xbb,0xb3,0xef,0xb7,0xb2,____,0xa3,0xd0,0x6a,0x1e,
    0x04,0x46,0x71,0xc8,0x37,0x85,0xea,0x33,0x68,0x0f,0xc2,0xf7,0xed,0xc7,0xea,0x76,

This time curve25519-sse2 is off, while curve25519 matches the reference implementation.