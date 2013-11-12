#if defined(_WIN32)
	#include <windows.h>
	#include <wincrypt.h>
	typedef unsigned int uint32_t;
	typedef unsigned __int64 uint64_t;
#else
	#include <stdint.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "curve25519-donna.h"
#include "curve25519-ref10.h"

static void
print_diff(const char *desc, const unsigned char *a, const unsigned char *b, size_t len) {
	size_t p = 0;
	unsigned char diff;
	printf("%s diff:\n", desc);
	while (len--) {
		diff = *a++ ^ *b++;
		if (!diff)
			printf("____,");
		else
			printf("0x%02x,", diff);
		if ((++p & 15) == 0)
			printf("\n");
	}
	printf("\n\n");
}

static void
print_bytes(const char *desc, const unsigned char *bytes, size_t len) {
	size_t p = 0;
	printf("%s:\n", desc);
	while (len--) {
		printf("0x%02x,", *bytes++);
		if ((++p & 15) == 0)
			printf("\n");
	}
	printf("\n\n");
}


/* chacha20/12 prng */
void
prng(unsigned char *out, size_t bytes) {
	static uint32_t state[16];
	static int init = 0;
	uint32_t x[16], t;
	size_t i;

	if (!init) {
	#if defined(_WIN32)
		HCRYPTPROV csp;
		if (!CryptAcquireContext(&csp, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
			printf("CryptAcquireContext failed\n");
			exit(1);
		}
		if (!CryptGenRandom(csp, (DWORD)sizeof(state), (BYTE*)state)) {
			printf("CryptGenRandom failed\n");
			exit(1);
		}
		CryptReleaseContext(csp, 0);
	#else
		FILE *f = NULL;
		f = fopen("/dev/urandom", "rb");
		if (!f) {
			printf("failed to open /dev/urandom\n");
			exit(1);
		}
		if (fread(state, sizeof(state), 1, f) != 1) {
			printf("read error on /dev/urandom\n");
			exit(1);
		}
	#endif
		init = 1;
	}

	while (bytes) {
		for (i = 0; i < 16; i++) x[i] = state[i];

		#define rotl32(x,k) ((x << k) | (x >> (32 - k)))
		#define quarter(a,b,c,d) \
			x[a] += x[b]; t = x[d]^x[a]; x[d] = rotl32(t,16); \
			x[c] += x[d]; t = x[b]^x[c]; x[b] = rotl32(t,12); \
			x[a] += x[b]; t = x[d]^x[a]; x[d] = rotl32(t, 8); \
			x[c] += x[d]; t = x[b]^x[c]; x[b] = rotl32(t, 7);

		for (i = 0; i < 12; i += 2) {
			quarter( 0, 4, 8,12)
			quarter( 1, 5, 9,13)
			quarter( 2, 6,10,14)
			quarter( 3, 7,11,15)
			quarter( 0, 5,10,15)
			quarter( 1, 6,11,12)
			quarter( 2, 7, 8,13)
			quarter( 3, 4, 9,14)
		};

		if (bytes <= 64) {
			memcpy(out, x, bytes);
			bytes = 0;
		} else {
			memcpy(out, x, 64);
			bytes -= 64;
			out += 64;
		}

		/* don't need a nonce, so last 4 words are the counter. 2^136 bytes can be generated */
		if (!++state[12]) if (!++state[13]) if (!++state[14]) ++state[15];
	}
}



int main() {
	#define max_impls 32
	const size_t skmax = 1024;
	static curve25519_key sk[1024][2];
	static curve25519_key pk[max_impls][2];
	static curve25519_key shared[max_impls][2];
	size_t ski, pki, sharedi, i, j;
	uint64_t ctr;

	printf("fuzzing: ");
	printf(" ref10");
	printf(" curve25519");
#if defined(CURVE25519_SSE2)
	printf(" curve25519-sse2");
#endif
	printf("\n\n");

	for (ctr = 0, ski = skmax;;ctr++,ski++) {
		if (ski == skmax) {
			prng((unsigned char *)sk, sizeof(sk));
			ski = 0;
		}

		/* derive two public keys from two secret keys */
		pki = 0;
		crypto_scalarmult_base_ref10(pk[pki][0], sk[ski][0]);
		crypto_scalarmult_base_ref10(pk[pki][1], sk[ski][1]); pki++;
		curve25519_donna_basepoint(pk[pki][0], sk[ski][0]);
		curve25519_donna_basepoint(pk[pki][1], sk[ski][1]); pki++;
	#if defined(CURVE25519_SSE2)
		curve25519_donna_basepoint_sse2(pk[pki][0], sk[ski][0]);
		curve25519_donna_basepoint_sse2(pk[pki][1], sk[ski][1]); pki++;
	#endif

		/* make sure all public keys match */
		for (i = 1; i < pki; i++) {
			for (j = 0; j < 2; j++) {
				if (memcmp(pk[0][j], pk[i][j], 32) != 0) {
					printf("public key mismatch:" "\n\n");
					print_bytes("sk",  sk[ski][j], 32);
					print_bytes("ref10 pk", pk[0][j], 32);
					pki = 1;
					print_diff("curve25519 pk", pk[0][j], pk[pki][j], 32); pki++;
					#if defined(CURVE25519_SSE2)
						print_diff("curve25519-sse2 pk", pk[0][j], pk[pki][j], 32); pki++;
					#endif
					exit(1);
				}
			}
		}

		/* derive the shared secret between the two secret keys */
		sharedi = 0;
		crypto_scalarmult_ref10(shared[sharedi][0], sk[ski][0], pk[sharedi][1]);
		crypto_scalarmult_ref10(shared[sharedi][1], sk[ski][1], pk[sharedi][0]); sharedi++;
		curve25519_donna(shared[sharedi][0], sk[ski][0], pk[sharedi][1]);
		curve25519_donna(shared[sharedi][1], sk[ski][1], pk[sharedi][0]); sharedi++;
	#if defined(CURVE25519_SSE2)
		curve25519_donna_sse2(shared[sharedi][0], sk[ski][0], pk[sharedi][1]);
		curve25519_donna_sse2(shared[sharedi][1], sk[ski][1], pk[sharedi][0]); sharedi++;
	#endif

		/* make sure all shared keys match */
		for (i = 1; i < sharedi; i++) {
			for (j = 0; j < 2; j++) {
				if (memcmp(shared[0][j], shared[i][j], 32) != 0) {
					printf("shared key mismatch:" "\n\n");
					print_bytes("sk",  sk[ski][j], 32);
					print_bytes("pk",  pk[0][j], 32);
					print_bytes("ref10 shared", shared[0][j], 32); sharedi++;
					sharedi = 1;
					print_diff("curve25519 shared", shared[0][j], shared[sharedi][j], 32); sharedi++;
				#if defined(CURVE25519_SSE2)
					print_diff("curve25519-sse2 shared", shared[0][j], shared[sharedi][j], 32); sharedi++;
				#endif
					exit(1);
				}
			}
		}

		if (ctr && (ctr % 0x100 == 0)) {
			printf(".");
			if ((ctr % 0x2000) == 0) {
				printf(" [");
				for (i = 0; i < 8; i++)
					printf("%02x", (unsigned char)(ctr >> ((7 - i) * 8)));
				printf("]\n");
			}
		}
	}
}

