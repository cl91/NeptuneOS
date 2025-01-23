/*
 * Copyright 2017, DornerWorks
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This data was produced by DornerWorks, Ltd. of Grand Rapids, MI, USA under
 * a DARPA SBIR, Contract Number D16PC00107.
 *
 * Approved for Public Release, Distribution Unlimited.
 *
 */

/*
 * md5 crypt implementation
 *
 * original md5 crypt design is from Poul-Henning Kamp
 * this implementation was created based on the code in freebsd
 * at least 32bit int is assumed, key is limited and $1$ prefix is mandatory,
 * on error "*" is returned
 */
#include <strops.h>
#include <printf.h>
#include <types.h>
#include "../crypt_md5.h"

/* public domain md5 implementation based on rfc1321 and libtomcrypt */

static uint32_t rol(uint32_t n, int k)
{
    return (n << k) | (n >> (32 - k));
}
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define G(x,y,z) (y ^ (z & (y ^ x)))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))
#define FF(a,b,c,d,w,s,t) a += F(b,c,d) + w + t; a = rol(a,s) + b
#define GG(a,b,c,d,w,s,t) a += G(b,c,d) + w + t; a = rol(a,s) + b
#define HH(a,b,c,d,w,s,t) a += H(b,c,d) + w + t; a = rol(a,s) + b
#define II(a,b,c,d,w,s,t) a += I(b,c,d) + w + t; a = rol(a,s) + b

static const uint32_t tab[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static void processblock(md5_t *s, const uint8_t *buf)
{
    uint32_t i, W[16], a, b, c, d;

    for (i = 0; i < 16; i++) {
        W[i] = buf[4 * i];
        W[i] |= (uint32_t)buf[4 * i + 1] << 8;
        W[i] |= (uint32_t)buf[4 * i + 2] << 16;
        W[i] |= (uint32_t)buf[4 * i + 3] << 24;
    }

    a = s->h[0];
    b = s->h[1];
    c = s->h[2];
    d = s->h[3];

    i = 0;
    while (i < 16) {
        FF(a, b, c, d, W[i],  7, tab[i]);
        i++;
        FF(d, a, b, c, W[i], 12, tab[i]);
        i++;
        FF(c, d, a, b, W[i], 17, tab[i]);
        i++;
        FF(b, c, d, a, W[i], 22, tab[i]);
        i++;
    }
    while (i < 32) {
        GG(a, b, c, d, W[(5 * i + 1) % 16],  5, tab[i]);
        i++;
        GG(d, a, b, c, W[(5 * i + 1) % 16],  9, tab[i]);
        i++;
        GG(c, d, a, b, W[(5 * i + 1) % 16], 14, tab[i]);
        i++;
        GG(b, c, d, a, W[(5 * i + 1) % 16], 20, tab[i]);
        i++;
    }
    while (i < 48) {
        HH(a, b, c, d, W[(3 * i + 5) % 16],  4, tab[i]);
        i++;
        HH(d, a, b, c, W[(3 * i + 5) % 16], 11, tab[i]);
        i++;
        HH(c, d, a, b, W[(3 * i + 5) % 16], 16, tab[i]);
        i++;
        HH(b, c, d, a, W[(3 * i + 5) % 16], 23, tab[i]);
        i++;
    }
    while (i < 64) {
        II(a, b, c, d, W[7 * i % 16],  6, tab[i]);
        i++;
        II(d, a, b, c, W[7 * i % 16], 10, tab[i]);
        i++;
        II(c, d, a, b, W[7 * i % 16], 15, tab[i]);
        i++;
        II(b, c, d, a, W[7 * i % 16], 21, tab[i]);
        i++;
    }

    s->h[0] += a;
    s->h[1] += b;
    s->h[2] += c;
    s->h[3] += d;
}

static void pad(md5_t *s)
{
    unsigned r = s->len % 64;

    s->buf[r++] = 0x80;
    if (r > 56) {
        memset(s->buf + r, 0, 64 - r);
        r = 0;
        processblock(s, s->buf);
    }
    memset(s->buf + r, 0, 56 - r);
    s->len *= 8;
    s->buf[56] = s->len;
    s->buf[57] = s->len >> 8;
    s->buf[58] = s->len >> 16;
    s->buf[59] = s->len >> 24;
    s->buf[60] = s->len >> 32;
    s->buf[61] = s->len >> 40;
    s->buf[62] = s->len >> 48;
    s->buf[63] = s->len >> 56;
    processblock(s, s->buf);
}

void md5_init(md5_t *s)
{
    s->len = 0;
    s->h[0] = 0x67452301;
    s->h[1] = 0xefcdab89;
    s->h[2] = 0x98badcfe;
    s->h[3] = 0x10325476;
}

void md5_sum(md5_t *s, uint8_t *md)
{
    int i;

    pad(s);
    for (i = 0; i < 4; i++) {
        md[4 * i] = s->h[i];
        md[4 * i + 1] = s->h[i] >> 8;
        md[4 * i + 2] = s->h[i] >> 16;
        md[4 * i + 3] = s->h[i] >> 24;
    }
}

void md5_update(md5_t *s, const void *m, unsigned long len)
{
    const uint8_t *p = m;
    unsigned r = s->len % 64;
    s->len += len;
    if (r) {
        if (len < 64 - r) {
            memcpy(s->buf + r, p, len);
            return;
        }
        memcpy(s->buf + r, p, 64 - r);
        len -= 64 - r;
        p += 64 - r;
        processblock(s, s->buf);
    }
    for (; len >= 64; len -= 64, p += 64) {
        processblock(s, p);
    }
    memcpy(s->buf, p, len);
}
