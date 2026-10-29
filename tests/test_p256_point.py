#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the exact PTA point check against Python's independent field math."""
import ctypes
import random
import subprocess
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def encode(x, y):
    return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def expected(x, y):
    return x < P and y < P and (y*y - x*x*x + 3*x - B) % P == 0


def main():
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        (temp / 'check.c').write_text(
            '#include "p256_point.h"\n'
            'int check_point(const unsigned char *p) { return p256_point_is_valid(p); }\n'
        )
        subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror',
                        '-fPIC', '-shared', '-I', str(ROOT / 'pta'),
                        str(temp / 'check.c'), '-o', str(temp / 'check.so')], check=True)
        check = ctypes.CDLL(str(temp / 'check.so')).check_point
        check.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
        check.restype = ctypes.c_int

        def verify(x, y):
            point = (ctypes.c_ubyte * 64).from_buffer_copy(encode(x, y))
            try:
                ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
                reference = True
            except ValueError:
                reference = False
            assert reference == expected(x, y)
            assert bool(check(point)) == reference, f'mismatch for x={x:x}, y={y:x}'

        # Standard generator, its negation, zero/infinity encoding, changed point,
        # and coordinates exactly at or above the field modulus.
        assert expected(GX, GY)
        for x, y in [(GX, GY), (GX, P-GY), (0, 0), (GX, GY ^ 1),
                     (P, GY), (GX, P), (2**256-1, 2**256-1),
                     (P-1, P-1), (0, 1), (1, 0)]:
            verify(x, y)
        # Known multiples generated independently by the cryptography backend.
        for scalar in (2, 3, 7, 255, 65537):
            point = ec.derive_private_key(scalar, ec.SECP256R1()).public_key().public_numbers()
            verify(point.x, point.y)

        # Generate points from public x values and compare many unrelated invalid
        # coordinates against the independent Python modular equation.
        rng = random.Random(0xA77E57)
        valid_count = 0
        for _ in range(300):
            x = rng.randrange(P)
            z = (pow(x, 3, P) - 3*x + B) % P
            y = pow(z, (P + 1)//4, P)  # P == 3 (mod 4)
            if y*y % P == z:
                verify(x, y)
                verify(x, (-y) % P)
                verify(x, (y + 1) % P)
                valid_count += 1
            verify(x, rng.randrange(P))
        assert valid_count > 100
    print('P-256 point validation passed')


if __name__ == '__main__':
    main()
