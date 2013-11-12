#ifndef CURVE25519_H
#define CURVE25519_H

typedef unsigned char curve25519_key[32];

void curve25519_donna(curve25519_key mypublic, const curve25519_key secret, const curve25519_key basepoint);
void curve25519_donna_basepoint(curve25519_key mypublic, const curve25519_key secret);
void curve25519_donna_raw(curve25519_key mypublic, const curve25519_key secret, const curve25519_key basepoint);

#if defined(CURVE25519_SSE2)
void curve25519_donna_sse2(curve25519_key mypublic, const curve25519_key secret, const curve25519_key basepoint);
void curve25519_donna_basepoint_sse2(curve25519_key mypublic, const curve25519_key secret);
void curve25519_donna_raw_sse2(curve25519_key mypublic, const curve25519_key secret, const curve25519_key basepoint);
#endif

#endif /* CURVE25519_H */

