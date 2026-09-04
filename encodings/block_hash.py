from typing import cast

from .base58 import Base58Hash


class BlockHash(Base58Hash):
    def __repr__(self) -> str:
        return f"BlockHash({self.val.hex()})"

    @classmethod
    def from_str(cls, val: str) -> "BlockHash":
        return cast(BlockHash, super().from_str(val))
