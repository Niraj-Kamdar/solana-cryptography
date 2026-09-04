import json
import struct
from enum import IntEnum
from pathlib import Path

from .crypto.private_key import PrivateKey
from .crypto.public_key import PublicKey
from .crypto.signer import Signer
from .crypto.verify import verify_signature
from .encodings.base58 import base58_encode
from .encodings.block_hash import BlockHash
from .encodings.compact_u16 import compact_u16
from .tx_serialize import CompiledInstruction, Message, MessageHeader

SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"


class SystemDiscriminant(IntEnum):
    CreateAccount = 0
    Assign = 1
    Transfer = 2  # we need this
    CreateAccountWithSeed = 3
    AdvanceNonceAccount = 4
    WithdrawNonceAccount = 5
    InitializeNonceAccount = 6
    AuthorizeNonceAccount = 7
    Allocate = 8
    AllocateWithSeed = 9
    AssignWithSeed = 10
    TransferWithSeed = 11
    UpgradeNonceAccount = 12


def serialize_transfer_instruction_data(lamports: int):
    # Little Endian packing
    return struct.pack("<IQ", SystemDiscriminant.Transfer, lamports)


def construct_transfer_message(
    from_account: PublicKey,
    to_account: PublicKey,
    recent_blockhash: BlockHash,
    lamports: int,
):
    # 1 signer and 1 readonly system program account
    msg_header = MessageHeader(1, 0, 1)
    account_keys = [from_account, to_account, PublicKey.from_str(SYSTEM_PROGRAM_ID)]
    transfer_ix_data = serialize_transfer_instruction_data(lamports)

    transfer_ix = CompiledInstruction(2, [0, 1], transfer_ix_data)

    msg = Message(
        header=msg_header,
        account_keys=account_keys,
        recent_blockhash=recent_blockhash,
        instructions=[transfer_ix],
    )
    return msg


def construct_transfer_transaction(
    from_signer: Signer,
    to_account: PublicKey,
    recent_blockhash: BlockHash,
    lamports: int,
):
    from_account = from_signer.public_key
    msg = construct_transfer_message(
        from_account, to_account, recent_blockhash, lamports
    )
    serialized = msg.serialize()

    signature = from_signer.sign(serialized)
    assert verify_signature(signature, serialized, from_account) is True, (
        "Signature should be valid"
    )

    return compact_u16(1) + signature + serialized


if __name__ == "__main__":
    from rpc import getLatestBlockhash, simulateTransaction

    # Use default solana keygen keypair
    from_keypair_path = Path.home() / ".config" / "solana" / "id.json"
    with open(from_keypair_path, "r") as f:
        keypair = bytearray(json.load(f))

    from_signer = Signer(bytes(keypair[:32]))
    to_key = PrivateKey.new()

    from_account = from_signer.public_key
    to_account = to_key.public_key

    recent_blockhash = BlockHash.from_str(getLatestBlockhash())

    ONE_SOL = 1_000_000_000

    amount = int(0.01 * ONE_SOL)
    raw_tx = construct_transfer_transaction(
        from_signer, to_account, recent_blockhash, amount
    )

    result = simulateTransaction(base58_encode(raw_tx))

    print(result)
    assert result is not None
