import json
from pathlib import Path
from solana_cryptography.encodings.base58 import base58_encode
from solana_cryptography.rpc import getLatestBlockhash, simulateTransaction
from solana_cryptography.crypto.signer import Signer
from solana_cryptography.crypto.private_key import PrivateKey
from solana_cryptography.encodings.block_hash import BlockHash
from solana_cryptography.transfer import construct_transfer_transaction


def main():
    # Use default solana keygen keypair
    from_keypair_path = Path.home() / ".config" / "solana" / "id.json"
    with open(from_keypair_path, "r") as f:
        keypair = bytearray(json.load(f))

    from_signer = Signer(bytes(keypair[:32]))
    to_account = PrivateKey.new().public_key

    recent_blockhash = BlockHash.from_str(getLatestBlockhash())

    ONE_SOL = 1_000_000_000

    amount = int(0.01 * ONE_SOL)
    raw_tx = construct_transfer_transaction(
        from_signer, to_account, recent_blockhash, amount
    )

    result = simulateTransaction(base58_encode(raw_tx))

    print(result)
    assert result is not None


if __name__ == "__main__":
    main()
