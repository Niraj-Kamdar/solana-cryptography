# DERIVED FROM https://github.com/bitcoin/bitcoin/blob/1830dd8820fb90bac9aea32000e47d7eb1a99e1b/test/functional/test_framework/secp256k1.py

# Copyright (c) 2022-2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test-only implementation of low-level ed25519 field and group arithmetic

It is designed for ease of understanding, not performance.

WARNING: This code is slow and trivially vulnerable to side channel attacks. Do not use for
anything but tests.

Exports:
* FE: class for ed25519 field elements
* GE: class for ed25519 group elements
* G: the ed25519 generator point
"""

from typing import Any, Union, cast


class FE:
    """Objects of this class represent elements of the field GF(2**255 - 19).

    They are represented internally in numerator / denominator form, in order to delay inversions.
    """

    # The size of the field (also its modulus and characteristic).
    SIZE = 2**255 - 19
    SQRT_M1 = pow(2, (SIZE - 1) // 4, SIZE)

    def __init__(self, a: Union["FE", int] = 0, b: Union["FE", int] = 1):
        """Initialize a field element a/b; both a and b can be ints or field elements."""
        if isinstance(a, FE):
            num = a._num
            den = a._den
        else:
            num = a % FE.SIZE
            den = 1
        if isinstance(b, FE):
            den = (den * b._num) % FE.SIZE
            num = (num * b._den) % FE.SIZE
        else:
            den = (den * b) % FE.SIZE
        assert den != 0
        if num == 0:
            den = 1
        self._num = num
        self._den = den

    def __add__(self, a):
        """Compute the sum of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self._num * a._den + self._den * a._num, self._den * a._den)
        return FE(self._num + self._den * a, self._den)

    def __radd__(self, a):
        """Compute the sum of an integer and a field element."""
        return FE(a) + self

    def __sub__(self, a):
        """Compute the difference of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self._num * a._den - self._den * a._num, self._den * a._den)
        return FE(self._num - self._den * a, self._den)

    def __rsub__(self, a):
        """Compute the difference of an integer and a field element."""
        return FE(a) - self

    def __mul__(self, a):
        """Compute the product of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self._num * a._num, self._den * a._den)
        return FE(self._num * a, self._den)

    def __rmul__(self, a):
        """Compute the product of an integer with a field element."""
        return FE(a) * self

    def __truediv__(self, a):
        """Compute the ratio of two field elements (second may be int)."""
        return FE(self, a)

    def __pow__(self, a):
        """Raise a field element to an integer power."""
        return FE(pow(self._num, a, FE.SIZE), pow(self._den, a, FE.SIZE))

    def __neg__(self):
        """Negate a field element."""
        return FE(-self._num, self._den)

    def __int__(self):
        """Convert a field element to an integer in range 0..p-1. The result is cached."""
        if self._den != 1:
            self._num = (self._num * pow(self._den, -1, FE.SIZE)) % FE.SIZE
            self._den = 1
        return self._num

    def sqrt(self):
        """Compute the square root of a field element if it exists (None otherwise)."""
        v = int(self)
        s = pow(v, (FE.SIZE + 3) // 8, FE.SIZE)
        if s**2 % FE.SIZE == v:
            return FE(s)
        if s**2 % FE.SIZE == (-v) % FE.SIZE:
            return FE(s * FE.SQRT_M1 % FE.SIZE)
        return None

    def is_square(self):
        """Determine if this field element has a square root."""
        # A more efficient algorithm is possible here (Jacobi symbol).
        return self.sqrt() is not None

    def is_even(self):
        """Determine whether this field element, represented as integer in 0..p-1, is even."""
        return int(self) & 1 == 0

    def __eq__(self, a):
        """Check whether two field elements are equal (second may be an int)."""
        if isinstance(a, FE):
            return (self._num * a._den - self._den * a._num) % FE.SIZE == 0
        return (self._num - self._den * a) % FE.SIZE == 0

    def to_bytes(self):
        """Convert a field element to a 32-byte array (LE byte order)."""
        return int(self).to_bytes(32, "little")

    @staticmethod
    def from_bytes(b):
        """Convert a 32-byte array to a field element (LE byte order, no overflow allowed)."""
        v = int.from_bytes(b, "little")
        if v >= FE.SIZE:
            return None
        return FE(v)

    def __str__(self):
        """Convert this field element to a 64 character hex string."""
        return f"{int(self):064x}"

    def __repr__(self):
        """Get a string representation of this field element."""
        return f"FE(0x{int(self):x})"


class GE:
    """Objects of this class represent secp256k1 group elements (curve points or infinity)

    Normal points on the curve have fields:
    * x: the x coordinate (a field element)
    * y: the y coordinate (a field element, satisfying -x^2 + y^2 = 1 -dx^2y^2)

    The point at infinity has field:
    * infinity: True
    """

    # Order of the group (number of points on the curve, plus 1 for infinity)
    ORDER = 2**252 + 27742317777372353535851937790883648493
    COFACTOR = 8
    D = FE(-121665, 121666)

    def __init__(self, x: Any = 0, y: Any = 1):
        """Initialize a group element with specified x and y coordinates, or infinity."""
        # Initialize as point on the curve (and check that it is).
        fx = FE(x)
        fy = FE(y)
        assert -(fx**2) + fy**2 == 1 + GE.D * fx**2 * fy**2
        self.x = fx
        self.y = fy

    def __add__(self, a):
        # Reference: https://en.wikipedia.org/wiki/Twisted_Edwards_curve
        # Check Addition part, we have -1 as prefix
        """Add two group elements together."""
        A = self.x * a.y + self.y * a.x
        B = self.y * a.y + self.x * a.x
        C = GE.D * self.x * self.y * a.x * a.y
        return GE(A / (1 + C), B / (1 - C))

    def __neg__(self):
        return GE(-self.x, self.y)

    @staticmethod
    def mul(*aps):
        """Compute a (batch) scalar group element multiplication.

        GE.mul((a1, p1), (a2, p2), (a3, p3)) is identical to a1*p1 + a2*p2 + a3*p3,
        but more efficient."""
        # Reduce all the scalars modulo order first (so we can deal with negatives etc).
        naps = [(a % (GE.COFACTOR * GE.ORDER), p) for a, p in aps]
        # Start with identity (0, 1)
        r = GE()
        # Iterate over all bit positions, from high to low.
        for i in range(252, -1, -1):  # ℓ is 253 bits
            # Double what we have so far.
            r = r + r
            # Add then add the points for which the corresponding scalar bit is set.
            for a, p in naps:
                if (a >> i) & 1:
                    r += p
        return r

    def __eq__(self, a):
        return self.x == a.x and self.y == a.y

    def __rmul__(self, a: Any):
        """Multiply an integer with a group element."""
        if self == B:
            return FAST_G.mul(a)
        return GE.mul((a, self))

    def to_bytes(self):
        # Encoding/Decoding specified in https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.2
        b = bytearray(self.y.to_bytes())
        if not self.x.is_even():
            b[31] |= 0x80
        return bytes(b)

    @staticmethod
    def from_bytes(b):
        assert len(b) == 32
        sign = b[31] >> 7
        b = bytes(b[:31]) + bytes([b[31] & 0x7F])  # clear bit 255
        y = FE.from_bytes(b)
        if y is None:
            return None  # y >= p, non-canonical
        P = GE.lift_y(y)
        if P is None:
            return None  # x² is not a square
        if sign != (int(P.x) & 1):
            P = -P
        if int(P.x) == 0 and sign == 1:
            return None  # ← the extra rule
        return P

    @staticmethod
    def lift_y(y):
        """Return group element with specified field element as x coordinate (and even y)."""
        fy = FE(y)
        x = ((fy**2 - 1) / (GE.D * fy**2 + 1)).sqrt()  # edcurve equation solve for x
        if x is None:
            return None
        if not x.is_even():
            x = -x
        return GE(x, fy)

    def __str__(self):
        """Convert this group element to a string."""
        return f"({self.x},{self.y})"

    def __repr__(self):
        """Get a string representation for this group element."""
        return f"GE(0x{int(self.x):x},0x{int(self.y):x})"


# The ed25519 generator point
B = cast(GE, GE.lift_y(FE(4, 5)))


class FastGEMul:
    """Table for fast multiplication with a constant group element.

    Speed up scalar multiplication with a fixed point P by using a precomputed lookup table with
    its powers of 2:

        table = [P, 2*P, 4*P, (2^3)*P, (2^4)*P, ..., (2^255)*P]

    During multiplication, the points corresponding to each bit set in the scalar are added up,
    i.e. on average ~128 point additions take place.
    """

    def __init__(self, p):
        self.table = [p]  # table[i] = (2^i) * p
        for _ in range(255):
            p = p + p
            self.table.append(p)

    def mul(self, a):
        result = GE()
        a = a % GE.ORDER
        for bit in range(a.bit_length()):
            if a & (1 << bit):
                result += self.table[bit]
        return result


# Precomputed table with multiples of G for fast multiplication
FAST_G = FastGEMul(B)


if __name__ == "__main__":
    # 2^255 - 19 % 8 === -19 % 8 === 5
    assert FE.SIZE % 8 == 5
    # Fermat: 2^(p-1) === 1
    assert FE(FE.SQRT_M1) ** 2 == FE(-1)
    assert FE(2).is_square() is False
    assert cast(FE, FE(4).sqrt()) ** 2 == FE(4)
    assert FE(-1).sqrt() is not None
    assert (
        FE(-121665, 121666)
        == 37095705934669439343138083508754565189542113879843219016388785533085940283555
    )
