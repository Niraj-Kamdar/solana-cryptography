# 5.1.6.  Sign

#    The inputs to the signing procedure is the private key, a 32-octet
#    string, and a message M of arbitrary size.  For Ed25519ctx and
#    Ed25519ph, there is additionally a context C of at most 255 octets
#    and a flag F, 0 for Ed25519ctx and 1 for Ed25519ph.

#    1.  Hash the private key, 32 octets, using SHA-512.  Let h denote the
#        resulting digest.  Construct the secret scalar s from the first
#        half of the digest, and the corresponding public key A, as
#        described in the previous section.  Let prefix denote the second
#        half of the hash digest, h[32],...,h[63].

#    2.  Compute SHA-512(dom2(F, C) || prefix || PH(M)), where M is the
#        message to be signed.  Interpret the 64-octet digest as a little-
#        endian integer r.

#    3.  Compute the point [r]B.  For efficiency, do this by first
#        reducing r modulo L, the group order of B.  Let the string R be
#        the encoding of this point.
#
#        4.  Compute SHA512(dom2(F, C) || R || A || PH(M)), and interpret the
#            64-octet digest as a little-endian integer k.

#        5.  Compute S = (r + k * s) mod L.  For efficiency, again reduce k
#            modulo L first.

#        6.  Form the signature of the concatenation of R (32 octets) and the
#            little-endian encoding of S (32 octets; the three most
#            significant bits of the final octet are always zero).


import hashlib

from ed25519 import FE, GE, B
from keypair import get_prefix_from_priv, get_pubkey_from_priv, get_secret_s_from_priv


def sign(priv: bytes, msg: bytes):
    secret = get_secret_s_from_priv(priv)
    prefix = get_prefix_from_priv(priv)
    pubkey = get_pubkey_from_priv(priv)

    L = GE.ORDER

    r_digest = hashlib.sha512(b"" + prefix + msg).digest()
    r = int.from_bytes(r_digest, "little") % L

    R_point = r * B
    R = R_point.to_bytes()

    k = int.from_bytes(hashlib.sha512(b"" + R + pubkey + msg).digest(), "little") % L

    S = (r + k * secret) % L
    return R + S.to_bytes(32, "little")


def verify(sig: bytes, msg: bytes, pub_key: bytes):
    sig_arr = bytearray(sig)
    if len(sig_arr) != 64 and len(pub_key) != 32:
        return False
    first = sig_arr[:32]
    second = sig_arr[32:]

    R_Point = GE.from_bytes(first)
    if R_Point is None:
        return False

    S = int.from_bytes(second, "little")
    if S < 0 or S >= GE.ORDER:
        return False

    A_Point = GE.from_bytes(pub_key)
    if A_Point is None:
        return False

    k_bytes = hashlib.sha512(first + pub_key + msg).digest()
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

    assert sign(priv, msg) == bytes.fromhex(sig)

    assert verify(bytes.fromhex(sig), msg, bytes.fromhex(pub)) is True
