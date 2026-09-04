from typing import cast

from ..encodings.base58 import Base58Hash


class PublicKey(Base58Hash):
    def __repr__(self) -> str:
        return f"PublicKey({self.val.hex()})"

    @classmethod
    def from_str(cls, val: str) -> "PublicKey":
        return cast(PublicKey, super().from_str(val))
