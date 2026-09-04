import json
from pathlib import Path
import struct
from enum import IntEnum

from codec import base58_encode
from tx_serialize import CompiledInstruction, Hash, Message, MessageHeader, PubKey, compact_u16
from keypair import generate_new
from signer import sign, verify

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
    from_account: PubKey, to_account: PubKey, recent_blockhash: Hash, lamports: int
):
    # 1 signer and 1 readonly system program account
    msg_header = MessageHeader(1, 0, 1)
    account_keys = [from_account, to_account, PubKey.from_str(SYSTEM_PROGRAM_ID)]
    transfer_ix_data = serialize_transfer_instruction_data(lamports)

    transfer_ix = CompiledInstruction(2, [0, 1], transfer_ix_data)

    msg = Message(
        header=msg_header,
        account_keys=account_keys,
        recent_blockhash=recent_blockhash,
        instructions=[transfer_ix],
    )
    return msg


if __name__ == "__main__":
    from rpc import getLatestBlockhash, simulateTransaction

    # Use default solana keygen keypair
    from_keypair_path = Path.home() / ".config" / "solana" / "id.json"
    with open(from_keypair_path, "r") as f:
        keypair = bytearray(json.load(f))

    from_keypair = [bytes(keypair[:32]), bytes(keypair[32:])]

    to_keypair = generate_new()

    from_account = PubKey(from_keypair[1])
    to_account = PubKey(to_keypair[1])

    recent_blockhash = Hash.from_str(getLatestBlockhash())

    ONE_SOL = 1_000_000_000

    msg = construct_transfer_message(from_account, to_account, recent_blockhash, int(0.01 * ONE_SOL))
    serialized = msg.serialize()
    signature = sign(from_keypair[0], serialized)
    assert verify(signature, serialized, from_keypair[1]) is True, "Signature should be valid"

    wired = compact_u16(1) + signature + serialized

    result = simulateTransaction(base58_encode(wired))
    print(result)
