/* SPDX-License-Identifier: BSD-2-Clause */
/* P-256 public-point check for the fixed, 64-byte x || y wire encoding. */
#ifndef JETSON_P256_POINT_H
#define JETSON_P256_POINT_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Eight little-endian 32-bit limbs. Every operand to add_mod is below p. */
typedef uint32_t p256_field[8];
static const p256_field p256_field_prime = {
    0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xffffffff
};
static const p256_field p256_field_b = {
    0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0,
    0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8
};

static int p256_field_compare(const p256_field a, const p256_field b)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if (a[i] != b[i])
            return a[i] > b[i] ? 1 : -1;
    }
    return 0;
}

static void p256_field_read(p256_field out, const uint8_t in[32])
{
    unsigned int i;
    for (i = 0; i < 8; i++) {
        unsigned int j = 28 - 4 * i;
        out[i] = ((uint32_t)in[j] << 24) | ((uint32_t)in[j + 1] << 16) |
                 ((uint32_t)in[j + 2] << 8) | in[j + 3];
    }
}

static void p256_field_add(p256_field out, const p256_field a, const p256_field b)
{
    p256_field sum;
    uint64_t carry = 0;
    uint64_t borrow = 0;
    unsigned int i;

    for (i = 0; i < 8; i++) {
        uint64_t value = (uint64_t)a[i] + b[i] + carry;
        sum[i] = (uint32_t)value;
        carry = value >> 32;
    }
    if (carry || p256_field_compare(sum, p256_field_prime) >= 0) {
        for (i = 0; i < 8; i++) {
            uint64_t sub = (uint64_t)p256_field_prime[i] + borrow;
            uint64_t value = sum[i];
            sum[i] = (uint32_t)(value - sub);
            borrow = value < sub;
        }
    }
    memcpy(out, sum, sizeof(sum));
}

/* Double-and-add is suitable here because both coordinates are public. */
static void p256_field_mul(p256_field out, const p256_field a, const p256_field b)
{
    p256_field acc = { 0 };
    p256_field addend;
    unsigned int i, bit;

    memcpy(addend, a, sizeof(addend));
    for (i = 0; i < 8; i++) {
        for (bit = 0; bit < 32; bit++) {
            if ((b[i] >> bit) & 1U)
                p256_field_add(acc, acc, addend);
            p256_field_add(addend, addend, addend);
        }
    }
    memcpy(out, acc, sizeof(acc));
}

/* SEC 1 affine public point: y^2 = x^3 - 3x + b (mod p). */
static bool p256_point_is_valid(const uint8_t public_key[64])
{
    p256_field x, y, lhs, rhs, x2, triple_x;
    p256_field minus_triple;
    uint64_t borrow = 0;
    unsigned int i;

    p256_field_read(x, public_key);
    p256_field_read(y, public_key + 32);
    if (p256_field_compare(x, p256_field_prime) >= 0 ||
        p256_field_compare(y, p256_field_prime) >= 0)
        return false;
    p256_field_mul(lhs, y, y);
    p256_field_mul(x2, x, x);
    p256_field_mul(rhs, x2, x);
    p256_field_add(triple_x, x, x);
    p256_field_add(triple_x, triple_x, x);
    if (p256_field_compare(triple_x, (p256_field){ 0 }) == 0) {
        memset(minus_triple, 0, sizeof(minus_triple));
    } else {
        for (i = 0; i < 8; i++) {
            uint64_t sub = (uint64_t)triple_x[i] + borrow;
            uint64_t value = p256_field_prime[i];
            minus_triple[i] = (uint32_t)(value - sub);
            borrow = value < sub;
        }
    }
    p256_field_add(rhs, rhs, minus_triple);
    p256_field_add(rhs, rhs, p256_field_b);
    return p256_field_compare(lhs, rhs) == 0;
}
#endif
