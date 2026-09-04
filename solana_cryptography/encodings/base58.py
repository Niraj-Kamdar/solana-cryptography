from .codec import generic_decode, generic_encode

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    return generic_encode(BASE58_ALPHABET, data)


def base58_decode(string: str) -> bytes:
    return generic_decode(BASE58_ALPHABET, string)


class Base58Hash:
    val: bytes

    def __init__(self, val: bytes) -> None:
        if len(val) != 32:
            raise ValueError("Invalid length for a hash")
        self.val = val

    @classmethod
    def from_str(cls, val: str) -> "Base58Hash":
        return cls(base58_decode(val))

    def serialize(self) -> bytes:
        return self.val

    def __repr__(self) -> str:
        return f"Base58Hash({self.val.hex()})"

    def __eq__(self, other: object) -> bool:
        return (
            hasattr(other, "val")
            and isinstance(getattr(other, "val"), bytes)
            and self.val == getattr(other, "val")
        )
