"""
Reference: https://solana.com/docs/core/transactions/transaction-structure
"""

from dataclasses import dataclass
from typing import List, TypedDict, cast

from codec import base58_decode


def compact_u16(val: int) -> bytes:
    if val < 0:
        raise ValueError("Value Cannot be Negative")
    if val < 0x80:
        return bytes([val])
    elif val < 0x4000:
        return bytes([val & 0x7F | 0x80, val >> 7])
    elif val < 0x10000:
        return bytes([val & 0x7F | 0x80, (val >> 7) & 0x7F | 0x80, val >> 14])
    raise ValueError(val)


class MessageHeaderDict(TypedDict):
    numRequiredSignatures: int
    numReadonlySignedAccounts: int
    numReadonlyUnsignedAccounts: int


class CompiledInstructionDict(TypedDict):
    programIdIndex: int
    accounts: List[int]
    data: str  # base58


class MessageDict(TypedDict):
    header: MessageHeaderDict
    accountKeys: List[str]  # base58
    recentBlockhash: str  # base58
    instructions: List[CompiledInstructionDict]


class PubKey:
    val: bytes

    def __init__(self, val: bytes) -> None:
        if len(val) != 32:
            raise ValueError("Invalid Length for a public key")
        self.val = val

    @classmethod
    def from_str(cls, val: str) -> "PubKey":
        return cls(base58_decode(val))

    def serialize(self) -> bytes:
        return self.val

    def __repr__(self) -> str:
        return f"PubKey({self.val.hex()})"

    def __eq__(self, other: object) -> bool:
        return (
            hasattr(other, "val")
            and isinstance(getattr(other, "val"), bytes)
            and self.val == getattr(other, "val")
        )


class Hash:
    val: bytes

    def __init__(self, val: bytes) -> None:
        if len(val) != 32:
            raise ValueError("Invalid length for a hash")
        self.val = val

    @classmethod
    def from_str(cls, val: str) -> "Hash":
        return cls(base58_decode(val))

    def serialize(self) -> bytes:
        return self.val

    def __repr__(self) -> str:
        return f"Hash({self.val.hex()})"

    def __eq__(self, other: object) -> bool:
        return (
            hasattr(other, "val")
            and isinstance(getattr(other, "val"), bytes)
            and self.val == getattr(other, "val")
        )


@dataclass
class CompiledInstruction:
    program_id_index: int  # program id of the program we invoking
    accounts: List[int]  # Index from accounts -> access list of accounts
    data: bytes  # serialized data

    def serialize(self):
        encoded_program_id_index = self.program_id_index.to_bytes(1, "little")
        encoded_account_length = compact_u16(len(self.accounts))
        encoded_account_indices = b"".join(
            [acc.to_bytes(1, "little") for acc in self.accounts]
        )
        data_length = compact_u16(len(self.data))
        return (
            encoded_program_id_index
            + encoded_account_length
            + encoded_account_indices
            + data_length
            + self.data
        )


@dataclass
class MessageHeader:
    num_required_signatures: int
    num_readonly_signed_accounts: int
    num_readonly_unsigned_accounts: int

    def serialize(self):
        return b"".join(
            map(
                lambda x: x.to_bytes(1, "little"),
                [
                    self.num_required_signatures,
                    self.num_readonly_signed_accounts,
                    self.num_readonly_unsigned_accounts,
                ],
            )
        )


@dataclass
class Message:
    header: MessageHeader
    account_keys: List[PubKey]
    recent_blockhash: Hash
    instructions: List[CompiledInstruction]

    def serialize_account_keys(self):
        account_keys_length = len(self.account_keys)
        return compact_u16(account_keys_length) + b"".join(
            map(lambda acc: acc.serialize(), self.account_keys)
        )

    def serialize_instructions(self):
        instructions_length = len(self.instructions)
        return compact_u16(instructions_length) + b"".join(
            map(lambda ix: ix.serialize(), self.instructions)
        )

    def serialize(self) -> bytes:
        return (
            self.header.serialize()
            + self.serialize_account_keys()
            + self.recent_blockhash.serialize()
            + self.serialize_instructions()
        )

    @classmethod
    def from_dict(cls, data: MessageDict) -> "Message":
        raw_header = data["header"]
        header = MessageHeader(
            num_required_signatures=raw_header["numRequiredSignatures"],
            num_readonly_signed_accounts=raw_header["numReadonlySignedAccounts"],
            num_readonly_unsigned_accounts=raw_header["numReadonlyUnsignedAccounts"],
        )

        account_keys = [PubKey.from_str(key) for key in data["accountKeys"]]

        num_signed = header.num_required_signatures
        num_readonly_unsigned = header.num_readonly_unsigned_accounts
        if num_signed + num_readonly_unsigned > len(account_keys):
            raise ValueError("Header account counts exceed account_keys length")
        if header.num_readonly_signed_accounts >= num_signed:
            raise ValueError("More readonly signers than required signatures")

        instructions = []
        for ix in data["instructions"]:
            program_id_index = ix["programIdIndex"]
            accounts = list(ix["accounts"])
            if program_id_index >= len(account_keys):
                raise ValueError("programIdIndex out of range")
            if any(i >= len(account_keys) for i in accounts):
                raise ValueError("instruction account index out of range")
            instructions.append(
                CompiledInstruction(
                    program_id_index=program_id_index,
                    accounts=accounts,
                    data=base58_decode(ix["data"]),
                )
            )

        return cls(
            header=header,
            account_keys=account_keys,
            recent_blockhash=Hash.from_str(data["recentBlockhash"]),
            instructions=instructions,
        )


if __name__ == "__main__":
    tx: MessageDict = {
        "header": {
            "numRequiredSignatures": 1,
            "numReadonlySignedAccounts": 0,
            "numReadonlyUnsignedAccounts": 1,
        },
        "accountKeys": [
            "EPLUagqZZAuAtJ5LSbK7eeXjqeTdesd4q8WhoqVrfG3g",
            "9Txf5pi5jzm7FydFAsQafk7xn5wY9yN2UNm5LW15qvcK",
            "11111111111111111111111111111111",
        ],
        "recentBlockhash": "2qYPgehzMKXcMt4Ku1tKAk9DACKUbtYEY9EUEN42cseT",
        "instructions": [
            {"programIdIndex": 2, "accounts": [0, 1], "data": "3Bxs4NN8M2Yn4TLb"}
        ],
    }

    msg = Message.from_dict(tx)
    print(msg.serialize().hex())
