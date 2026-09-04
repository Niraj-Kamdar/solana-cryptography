"""
5.1.7.  Verify

   1.  To verify a signature on a message M using public key A, with F
       being 0 for Ed25519ctx, 1 for Ed25519ph, and if Ed25519ctx or
       Ed25519ph is being used, C being the context, first split the
       signature into two 32-octet halves.  Decode the first half as a
       point R, and the second half as an integer S, in the range
       0 <= s < L.  Decode the public key A as point A'.  If any of the
       decodings fail (including S being out of range), the signature is
       invalid.

   2.  Compute SHA512(dom2(F, C) || R || A || PH(M)), and interpret the
       64-octet digest as a little-endian integer k.

   3.  Check the group equation [8][S]B = [8]R + [8][k]A'.  It's
       sufficient, but not required, to instead check [S]B = R + [k]A'.
"""


import hashlib

from .ed25519 import GE, B
from .public_key import PublicKey


def verify_signature(sig: bytes, msg: bytes, public_key: PublicKey):
    sig_arr = bytearray(sig)
    if len(sig_arr) != 64 or len(public_key.val) != 32:
        return False
    first = sig_arr[:32]
    second = sig_arr[32:]

    R_Point = GE.from_bytes(first)
    if R_Point is None:
        return False

    S = int.from_bytes(second, "little")
    if S < 0 or S >= GE.ORDER:
        return False

    A_Point = GE.from_bytes(public_key.val)
    if A_Point is None:
        return False

    k_bytes = hashlib.sha512(first + public_key.val + msg).digest()
    k_int = int.from_bytes(k_bytes, "little") % GE.ORDER

    lhs = S * B
    rhs = R_Point + k_int * A_Point

    return lhs == rhs



if __name__ == "__main__":
    priv = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    msg = b""
    sig = (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )

    assert verify_signature(bytes.fromhex(sig), msg, PublicKey(bytes.fromhex(pub))) is True
